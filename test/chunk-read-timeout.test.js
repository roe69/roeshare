// Regression test for the security-audit finding "chunk-upload
// admission-control semaphore is acquired for the entire (attacker-paced)
// body-read duration with no per-holder time cap" (2026-07).
//
// PATCH /api/shares/:id/files/:fileId acquires its 'chunk'/'chunk-global'
// admission-control slots BEFORE reading the request body, and releases them
// only after the read (and write) completes - so a client that paces its own
// upload body slowly holds a scarce slot for as long as it likes, bounded
// only by Bun's idleTimeout, which resets on ANY byte of activity and so
// never bounds a slow-but-continuous trickle.
//
// The fix wraps the body read in a WALL-CLOCK timeout (uploads.js's
// withTimeout()/CHUNK_READ_TIMEOUT), derived from the declared chunk length
// against a configurable floor rate, so a deliberately slow-paced body gets
// a 408 and its admission-control slot is released instead of being held
// indefinitely. This test drives the floor rate/timeout bounds down via env
// so it stays fast and deterministic.
//
// The slow upload is driven over a raw TCP socket (not through fetch()) so a
// deliberately-paced, non-cooperative sender - matching a real slow-loris-
// style client, which has no reason to behave nicely once the server has
// responded - cannot be confused with the *test harness's own* HTTP client
// connection-pooling/reuse behavior; the verification request afterward uses
// a completely independent connection.
//
// Boots the real server as a child process (mirrors uploads-side tests).

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from 'node:net';

const ROOT = join(import.meta.dir, '..');

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
}

async function bootServer(dataDir, port, extraEnv = {}) {
	const proc = Bun.spawn({
		cmd: [process.execPath, 'run', 'src/server.js'],
		cwd: ROOT,
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(port),
			DATA_DIR: dataDir,
			ADMIN_PASSWORD: 'ChunkTimeoutTest-Pw-2026',
			SECRET: `chunk-timeout-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			// A high floor rate + short min/max bounds makes the timeout fire
			// quickly and deterministically for the deliberately slow body below,
			// without needing a real multi-minute wait.
			CHUNK_READ_MIN_BYTES_PER_SEC: String(1024 * 1024), // 1 MB/s floor
			CHUNK_READ_TIMEOUT_MIN_MS: '700',
			CHUNK_READ_TIMEOUT_MAX_MS: '5000',
			BASE_URL: `http://127.0.0.1:${port}`,
			...extraEnv,
		},
		stdout: 'pipe',
		stderr: 'pipe',
	});

	const deadline = Date.now() + 10_000;
	let lastErr;
	while (Date.now() < deadline) {
		if (proc.exitCode !== null) break;
		try {
			const r = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(500) });
			if (r.ok) return proc;
		} catch (e) {
			lastErr = e;
		}
		await new Promise(r => setTimeout(r, 150));
	}

	const stderr = await new Response(proc.stderr).text();
	proc.kill();
	throw new Error(`server on port ${port} never became healthy (last error: ${lastErr})\n--- stderr ---\n${stderr}`);
}

async function stopServer(proc) {
	try {
		proc.kill();
		await Promise.race([proc.exited, new Promise(r => setTimeout(r, 3000))]);
	} catch {}
}

function cleanupDir(dir) {
	for (let attempt = 0; attempt < 10; attempt++) {
		try {
			rmSync(dir, { recursive: true, force: true });
			return;
		} catch (e) {
			if (attempt === 9) throw e;
			Bun.sleepSync(200);
		}
	}
}

// Sends a PATCH over a raw TCP socket, trickling `totalBytes` out
// `chunkBytes` at a time with `delayMs` between each piece, and resolves
// with the response's status code as soon as the header block arrives (never
// finishes sending the declared Content-Length worth of body). Deliberately
// bypasses fetch()/undici entirely so this non-cooperative sender cannot be
// confused with the test's own HTTP client's connection pooling.
function sendSlowPatch({ host, port, path, editToken, totalBytes, chunkBytes, delayMs }) {
	return new Promise((resolve, reject) => {
		const socket = connect(port, host, () => {
			const req =
				`PATCH ${path} HTTP/1.1\r\n` +
				`Host: ${host}:${port}\r\n` +
				`X-Edit-Token: ${editToken}\r\n` +
				`Content-Type: application/octet-stream\r\n` +
				`Content-Length: ${totalBytes}\r\n` +
				`Connection: close\r\n` +
				`\r\n`;
			socket.write(req);
			let sent = 0;
			function pump() {
				if (socket.destroyed || sent >= totalBytes) return;
				const n = Math.min(chunkBytes, totalBytes - sent);
				socket.write(Buffer.alloc(n));
				sent += n;
				setTimeout(pump, delayMs);
			}
			pump();
		});
		let data = '';
		let resolved = false;
		socket.on('data', chunk => {
			data += chunk.toString('latin1');
			if (!resolved && data.includes('\r\n\r\n')) {
				resolved = true;
				const statusLine = data.split('\r\n')[0];
				const m = /^HTTP\/1\.\d (\d+)/.exec(statusLine);
				resolve({ status: m ? Number(m[1]) : null, raw: data });
			}
		});
		socket.on('error', e => {
			if (!resolved) reject(e);
		});
		socket.on('close', () => {
			if (!resolved) resolve({ status: null, raw: data });
		});
	});
}

describe('chunk-upload admission-control slot: bounded by a wall-clock read timeout', () => {
	test('a deliberately slow-paced chunk body times out (408) and releases its slot for other uploads', async () => {
		const dir = freshDataDir('chunk-timeout');
		try {
			const proc = await bootServer(dir, 3986);
			try {
				const base = 'http://127.0.0.1:3986';

				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false }),
				});
				expect(createRes.status).toBe(201);
				const { id, editToken } = await createRes.json();

				// Two files: one gets the slow-paced body (times out), the other is a
				// normal fast upload used to prove the slot was actually released.
				const totalBytes = 300_000; // well within any per-file/share cap
				async function registerFile(name) {
					const regRes = await fetch(`${base}/api/shares/${id}/files`, {
						method: 'POST',
						headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
						body: JSON.stringify({ name, size: totalBytes, mime: 'application/octet-stream' }),
					});
					expect(regRes.status).toBe(200);
					return (await regRes.json()).fileId;
				}
				const slowFileId = await registerFile('slow.bin');
				const fastFileId = await registerFile('fast.bin');

				// ~20 KB/s - far below the 1 MB/s floor configured above.
				const started = Date.now();
				const slowResult = await sendSlowPatch({
					host: '127.0.0.1',
					port: 3986,
					path: `/api/shares/${id}/files/${slowFileId}?offset=0`,
					editToken,
					totalBytes,
					chunkBytes: 4096,
					delayMs: 200,
				});
				const elapsedMs = Date.now() - started;
				expect(slowResult.status).toBe(408);
				// Must have been cut off by the short configured timeout, not have
				// run anywhere close to the ~15s a full uninterrupted slow send
				// would take at this pacing.
				expect(elapsedMs).toBeLessThan(6000);

				// A brief settle window for the abandoned raw socket's teardown -
				// well under the ~15s a full uninterrupted slow send would need.
				await new Promise(r => setTimeout(r, 500));

				// A normal, fast PATCH to the OTHER file in the SAME share (a fresh
				// connection, via the test's own fetch() client) must now succeed
				// promptly, not hang or 503 - proving the admission-control slot the
				// slow request held really was released, not held hostage as it was
				// before this fix.
				const fastBytes = new Uint8Array(totalBytes);
				const fastStarted = Date.now();
				const fastRes = await fetch(`${base}/api/shares/${id}/files/${fastFileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: fastBytes,
				});
				expect(fastRes.status).toBe(200);
				await fastRes.json();
				expect(Date.now() - fastStarted).toBeLessThan(3000);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
