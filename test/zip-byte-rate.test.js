// Regression test for M-04 GAP 1: the zip/download-all route had no byte-rate
// cap at all - only request-count rate limiting ('zip' bucket, 30/60s) and
// semaphore concurrency slots - so a client could bypass the configured
// DOWNLOAD_BYTES_PER_SEC budget entirely by using the archive endpoint
// instead of the single-file preview/download routes. Fixed by wiring the
// same takeBytes() 'dl-bytes' bucket (keyed by IP, exactly like preview/
// download - see src/routes/download.js) into download-all, sized from the
// archive's total content bytes before the zip stream opens.
//
// Boots the real server as a child process (mirrors download.test.js) since
// this is an HTTP-surface behavior, not a unit-testable function.

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
			ADMIN_PASSWORD: 'ZipByteRate-Pw-2026',
			SECRET: `zip-byte-rate-secret-${port}`,
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

// rmSync immediately after a process exits can still race a delayed Windows
// file-lock release; retry briefly instead of failing the whole test over a
// harmless cleanup timing issue.
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

// Creates a finalized, non-E2E share with a single file of `fileSize` bytes
// uploaded in one chunk.
async function makeShare(base, body, fileSize) {
	const createRes = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ e2e: false, ...body }),
	});
	expect(createRes.status).toBe(201);
	const { id, editToken } = await createRes.json();

	const bytes = new Uint8Array(fileSize);
	for (let i = 0; i < bytes.length; i++) bytes[i] = 65 + (i % 26);

	const regRes = await fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
		body: JSON.stringify({ name: 'zip-rate.bin', size: bytes.length, mime: 'application/octet-stream' }),
	});
	expect(regRes.status).toBe(200);
	const { fileId } = await regRes.json();

	const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
		method: 'PATCH',
		headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
		body: bytes,
	});
	expect(chunkRes.status).toBe(200);

	const finRes = await fetch(`${base}/api/shares/${id}/finalize`, {
		method: 'POST',
		headers: { 'X-Edit-Token': editToken },
	});
	expect(finRes.status).toBe(200);

	return { id, editToken, fileId, bytes };
}

describe('M-04 GAP 1: download-all (zip) is bound by the byte-rate budget', () => {
	test('a zip download that exceeds the configured byte-rate budget is throttled (429) the same way single-file download is', async () => {
		const dir = freshDataDir('zip-byte-rate');
		const port = 3941;
		// capacity = downloadBytesPerSec * 4 = 400 bytes, refill = 100 bytes/sec.
		const proc = await bootServer(dir, port, { DOWNLOAD_BYTES_PER_SEC: '100' });
		try {
			const base = `http://127.0.0.1:${port}`;
			// 600 bytes is bigger than the 400-byte capacity - the first zip
			// download is still admitted (some budget is available right now) but
			// spends the bucket into debt, exactly like a single large file would.
			const { id } = await makeShare(base, {}, 600);

			const first = await fetch(`${base}/api/shares/${id}/download-all`);
			expect(first.status).toBe(200);
			await first.arrayBuffer(); // drain so the response completes cleanly

			// The bucket is now in debt - an immediate second zip download of the
			// same share must be throttled. Before the fix, download-all never
			// called takeBytes() at all, so this would have kept returning 200
			// forever regardless of DOWNLOAD_BYTES_PER_SEC.
			const second = await fetch(`${base}/api/shares/${id}/download-all`);
			expect(second.status).toBe(429);
			const body = await second.json();
			expect(body.retryAfter).toBeGreaterThan(0);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a single-file download that exhausts the byte-rate budget also throttles a subsequent zip download (same shared "dl-bytes" bucket)', async () => {
		const dir = freshDataDir('zip-byte-rate-cross');
		const port = 3942;
		const proc = await bootServer(dir, port, { DOWNLOAD_BYTES_PER_SEC: '100' });
		try {
			const base = `http://127.0.0.1:${port}`;
			const { id, fileId } = await makeShare(base, {}, 600);

			const dl = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
			expect(dl.status).toBe(200);
			await dl.arrayBuffer();

			// Before the fix, download-all was on an entirely separate (nonexistent)
			// byte budget, so this would still have succeeded.
			const zip = await fetch(`${base}/api/shares/${id}/download-all`);
			expect(zip.status).toBe(429);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a zip download within the byte-rate budget is not throttled', async () => {
		const dir = freshDataDir('zip-byte-rate-ok');
		const port = 3943;
		const proc = await bootServer(dir, port, { DOWNLOAD_BYTES_PER_SEC: '100' }); // capacity 400B
		try {
			const base = `http://127.0.0.1:${port}`;
			const { id } = await makeShare(base, {}, 100); // well under the 400-byte capacity
			const res = await fetch(`${base}/api/shares/${id}/download-all`);
			expect(res.status).toBe(200);
			await res.arrayBuffer();
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});
