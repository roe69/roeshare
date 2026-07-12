// Regression test for: a 0-byte chunk PATCH at offset===received was accepted
// for a non-empty file, making no forward progress but still hitting the
// touchInTx() branch that refreshes the storage reservation's TTL (low
// severity - shares age off shares.created_at, not the reservation TTL, so
// this was never independently exploitable, but it's still bad input
// hygiene: a 0-byte body should never be treated as a legitimate chunk for a
// file that has real bytes left to receive).
//
// Fix (src/routes/uploads.js): reject a 0-byte PATCH body whenever
// file.size > 0, both from the declared Content-Length (before the
// byte-rate charge) and from the actual bytes read (after buffering, for
// clients that omit Content-Length). The file.size > 0 guard is load-bearing:
// completing a genuinely empty (size:0) file registration is a legitimate
// single empty PATCH at offset=0/received=0, and must keep working.
//
// Boots the real server as a child process, mirroring
// upload-security-fixes.test.js / zip-byte-rate.test.js.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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
			ADMIN_PASSWORD: 'ZeroByteChunk-Pw-2026',
			SECRET: `zero-byte-chunk-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
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

async function makeShareAndRegister(base, fileSize, name = 'f.bin') {
	const createRes = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ e2e: false }),
	});
	expect(createRes.status).toBe(201);
	const { id, editToken } = await createRes.json();
	const regRes = await fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
		body: JSON.stringify({ name, size: fileSize, mime: 'application/octet-stream' }),
	});
	expect(regRes.status).toBe(200);
	const { fileId } = await regRes.json();
	return { id, editToken, fileId };
}

describe('0-byte chunk PATCH is rejected for a non-empty file, but still allowed to complete a size:0 file', () => {
	test('a 0-byte PATCH at offset===received on a size>0 file is rejected with 400 (declared Content-Length path)', async () => {
		const dir = freshDataDir('zerobyte-declared-len');
		const port = 3960;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const { id, editToken, fileId } = await makeShareAndRegister(base, 100);

			const res = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
				method: 'PATCH',
				headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
				body: new Uint8Array(0),
			});
			expect(res.status).toBe(400);

			// Prove it made no forward progress: a real chunk still has to start
			// at offset=0, not somewhere past it.
			const real = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
				method: 'PATCH',
				headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
				body: new Uint8Array(100),
			});
			expect(real.status).toBe(200);
			const body = await real.json();
			expect(body.received).toBe(100);
			expect(body.complete).toBe(true);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a 0-byte PATCH sent without a Content-Length header (chunked transfer) is still rejected via the post-buffer check', async () => {
		const dir = freshDataDir('zerobyte-no-len');
		const port = 3961;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const { id, editToken, fileId } = await makeShareAndRegister(base, 100);

			// A ReadableStream body makes fetch/undici omit Content-Length and use
			// chunked transfer encoding, exercising the post-buffer chunk.length
			// guard rather than the declared-length guard.
			const stream = new ReadableStream({
				start(controller) {
					controller.close();
				},
			});
			const res = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
				method: 'PATCH',
				headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
				body: stream,
				duplex: 'half',
			});
			expect(res.status).toBe(400);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a single empty PATCH still legitimately completes a size:0 file registration', async () => {
		const dir = freshDataDir('zerobyte-legit-empty-file');
		const port = 3962;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const { id, editToken, fileId } = await makeShareAndRegister(base, 0);

			const res = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
				method: 'PATCH',
				headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
				body: new Uint8Array(0),
			});
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.received).toBe(0);
			expect(body.complete).toBe(true);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});
