// F-09: byte/concurrency governance (src/lib/semaphore.js), exercised through
// the heaviest real stream type - whole-share zip download (`GET
// /api/shares/:id/download-all`, src/routes/download.js), which is guarded by
// both a per-IP semaphore ('zip', limit 2) and a global one ('zip-global',
// limit 6). A saturated semaphore must reject the excess request cleanly
// (503 + Retry-After, no hang, no crash) and release its slot for reuse the
// moment the winning response's stream finishes draining.
//
// The requests deliberately do NOT read their response bodies until the test
// says so: fetch() resolves once headers arrive, but the zip stream (and thus
// the semaphore slot it holds via trackedStream's onEnd) stays open until the
// body is actually drained. Uploading a multi-MB incompressible file makes
// that window reliably observable instead of racing a same-tick completion.
//
// Boots the real server as a child process (mirrors download.test.js /
// trusted-proxy.test.js) since this is admission-control behavior at the HTTP
// surface, not something mockable at the DB/HTTP layer.

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
			ADMIN_PASSWORD: 'SemaphoreTest-Pw-2026',
			SECRET: `semaphore-test-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			TRUSTED_PROXY_CIDRS: '',
			TRUSTED_PROXY_HOPS: '',
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

// A deterministic, incompressible-enough buffer of `size` bytes (not that the
// store-only zip writer compresses anyway - this just avoids an all-zero
// buffer that some layer might special-case).
function randomBytes(size) {
	const buf = new Uint8Array(size);
	for (let i = 0; i < size; i++) buf[i] = (i * 2654435761) & 0xff;
	return buf;
}

// Create a finalized, unprotected, uncapped share with one file of `size`
// bytes, uploaded via the resumable chunk endpoints so it works for files
// larger than a single request's typical body. Returns the share id.
async function makeShareWithFile(base, size) {
	const createRes = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ e2e: false }),
	});
	expect(createRes.status).toBe(201);
	const { id, editToken, chunkSize } = await createRes.json();

	const regRes = await fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
		body: JSON.stringify({ name: 'blob.bin', size, mime: 'application/octet-stream' }),
	});
	expect(regRes.status).toBe(200);
	const { fileId } = await regRes.json();

	let offset = 0;
	while (offset < size) {
		const len = Math.min(chunkSize, size - offset);
		const chunk = randomBytes(len);
		const res = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=${offset}`, {
			method: 'PATCH',
			headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
			body: chunk,
		});
		expect(res.status).toBe(200);
		offset += len;
	}

	const finRes = await fetch(`${base}/api/shares/${id}/finalize`, { method: 'POST', headers: { 'X-Edit-Token': editToken } });
	expect(finRes.status).toBe(200);

	return id;
}

// Fully drain (and discard) a response body, releasing whatever semaphore
// slot its stream was holding via trackedStream's onEnd.
async function drain(res) {
	await res.arrayBuffer();
}

describe('semaphore admission control (F-09)', () => {
	test('per-IP zip semaphore (limit 2): a 3rd concurrent request is rejected cleanly, and the slot is reusable once the first drains', async () => {
		const dir = freshDataDir('sem-perip');
		try {
			const proc = await bootServer(dir, 3660);
			try {
				const base = 'http://127.0.0.1:3660';
				// 16 MiB (two 8 MiB chunks) is plenty to keep the zip stream's
				// backpressure open on an unread response for the duration of this
				// test's synchronous setup of the next request.
				const id = await makeShareWithFile(base, 16 * 1024 * 1024);

				const r1 = await fetch(`${base}/api/shares/${id}/download-all`);
				const r2 = await fetch(`${base}/api/shares/${id}/download-all`);
				expect(r1.status).toBe(200);
				expect(r2.status).toBe(200);

				// A 3rd concurrent request, from the same IP, with both slots still
				// held (neither body has been read yet) must be rejected cleanly -
				// not hang, not 500 - while the two winners' streams are still open.
				const r3 = await fetch(`${base}/api/shares/${id}/download-all`);
				expect(r3.status).toBe(503);
				const body3 = await r3.json();
				expect(body3.error).toBeTruthy();
				expect(typeof body3.retryAfter).toBe('number');
				expect(r3.headers.get('retry-after')).toBeTruthy();

				// Draining the first response's body lets its stream finish, which
				// releases its semaphore slot.
				await drain(r1);

				// The freed slot must be usable by a new request.
				const r4 = await fetch(`${base}/api/shares/${id}/download-all`);
				expect(r4.status).toBe(200);

				// Clean up the still-open streams so the child process can exit.
				await drain(r2);
				await drain(r4);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('global zip semaphore (limit 6): a 7th concurrent request across distinct IPs is rejected while the other 6 succeed', async () => {
		const dir = freshDataDir('sem-global');
		try {
			// Trust X-Forwarded-For from the loopback peer (the test client) with
			// hops=0, so each request's spoofed IP is honored directly - lets a
			// single test process simulate 7 distinct clients, each issuing only
			// one request (well under the per-IP 'zip' limit of 2), isolating the
			// GLOBAL 'zip-global' limit of 6.
			const proc = await bootServer(dir, 3661, { TRUSTED_PROXY_CIDRS: '127.0.0.1/32,::1/128', TRUSTED_PROXY_HOPS: '0' });
			try {
				const base = 'http://127.0.0.1:3661';
				const id = await makeShareWithFile(base, 16 * 1024 * 1024);

				const N = 7;
				const responses = await Promise.all(
					Array.from({ length: N }, (_, i) =>
						fetch(`${base}/api/shares/${id}/download-all`, { headers: { 'X-Forwarded-For': `203.0.113.${10 + i}` } }),
					),
				);

				const ok = responses.filter(r => r.status === 200);
				const rejected = responses.filter(r => r.status === 503);
				expect(ok.length).toBe(6);
				expect(rejected.length).toBe(1);

				for (const r of rejected) {
					const body = await r.json();
					expect(typeof body.retryAfter).toBe('number');
				}

				// Drain every winning stream so the slots are released, then confirm
				// a fresh request succeeds again (the global slot pool is reusable,
				// not permanently exhausted by the earlier rejection).
				await Promise.all(ok.map(drain));

				const again = await fetch(`${base}/api/shares/${id}/download-all`, { headers: { 'X-Forwarded-For': '203.0.113.99' } });
				expect(again.status).toBe(200);
				await drain(again);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
