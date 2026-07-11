// F-12 (remainder): Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy.
//
// The bulk of F-12 (SAFE_INLINE content-type gating + PREVIEW_CSP/PAGE_CSP) was
// already shipped; this covers the last piece - COOP/CORP on SECURITY_HEADERS.
//
// COOP:same-origin is safe everywhere (nothing in this app relies on a
// window.opener relationship). CORP:same-origin is safe on ordinary API/JSON
// responses, but shared file bytes (preview/download/zip) are meant to be
// embeddable/hotlinkable cross-origin (an <img>/<video> on another site
// pointed at a public share link) and are already gated by share id/token/
// password rather than an ambient cookie - so those routes get
// FILE_SECURITY_HEADERS instead, which relaxes CORP back to 'cross-origin'.
//
// Boots the real server as a child process (mirrors download.test.js /
// security-fixes.test.js) since these are HTTP response-header behaviors.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
}

async function bootServer(dataDir, port) {
	const proc = Bun.spawn({
		cmd: [process.execPath, 'run', 'src/server.js'],
		cwd: ROOT,
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(port),
			DATA_DIR: dataDir,
			ADMIN_PASSWORD: 'SecHeadersTest-Pw-2026',
			SECRET: `sec-headers-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			BASE_URL: `http://127.0.0.1:${port}`,
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

// Creates a finalized, non-E2E share with a single small file uploaded in one
// chunk (mirrors download.test.js's helper).
async function makeShare(base, body) {
	const createRes = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ e2e: false, ...body }),
	});
	expect(createRes.status).toBe(201);
	const { id, editToken } = await createRes.json();

	const bytes = new Uint8Array(20);
	for (let i = 0; i < bytes.length; i++) bytes[i] = 65 + i; // 'A'..'T'

	const regRes = await fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
		body: JSON.stringify({ name: 'test.txt', size: bytes.length, mime: 'text/plain' }),
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

describe('F-12: Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy', () => {
	test('an ordinary JSON API response gets COOP:same-origin and CORP:same-origin', async () => {
		const dir = freshDataDir('coop-json');
		try {
			const proc = await bootServer(dir, 3760);
			try {
				const base = 'http://127.0.0.1:3760';
				const res = await fetch(`${base}/health`);
				expect(res.status).toBe(200);
				expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin');
				expect(res.headers.get('cross-origin-resource-policy')).toBe('same-origin');
				// Pre-existing headers must still be present alongside the new ones.
				expect(res.headers.get('x-content-type-options')).toBe('nosniff');
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a share metadata (JSON) response also gets same-origin COOP/CORP', async () => {
		const dir = freshDataDir('coop-share-json');
		try {
			const proc = await bootServer(dir, 3761);
			try {
				const base = 'http://127.0.0.1:3761';
				const { id } = await makeShare(base, {});
				const res = await fetch(`${base}/api/shares/${id}`);
				expect(res.status).toBe(200);
				expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin');
				expect(res.headers.get('cross-origin-resource-policy')).toBe('same-origin');
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('preview/download responses keep COOP:same-origin but relax CORP to cross-origin so hotlinking/embedding a public share still works', async () => {
		const dir = freshDataDir('coop-file');
		try {
			const proc = await bootServer(dir, 3762);
			try {
				const base = 'http://127.0.0.1:3762';
				const { id, fileId, bytes } = await makeShare(base, {});

				const previewRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`);
				expect(previewRes.status).toBe(200);
				expect(previewRes.headers.get('cross-origin-opener-policy')).toBe('same-origin');
				expect(previewRes.headers.get('cross-origin-resource-policy')).toBe('cross-origin');
				expect(new Uint8Array(await previewRes.arrayBuffer())).toEqual(bytes);

				const downloadRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(downloadRes.status).toBe(200);
				expect(downloadRes.headers.get('cross-origin-opener-policy')).toBe('same-origin');
				expect(downloadRes.headers.get('cross-origin-resource-policy')).toBe('cross-origin');
				expect(new Uint8Array(await downloadRes.arrayBuffer())).toEqual(bytes);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('the whole-share zip response also relaxes CORP to cross-origin', async () => {
		const dir = freshDataDir('coop-zip');
		try {
			const proc = await bootServer(dir, 3763);
			try {
				const base = 'http://127.0.0.1:3763';
				const { id } = await makeShare(base, {});
				const res = await fetch(`${base}/api/shares/${id}/download-all`);
				expect(res.status).toBe(200);
				expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin');
				expect(res.headers.get('cross-origin-resource-policy')).toBe('cross-origin');
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('full E2E share round-trip (create, upload, finalize, preview, download) still succeeds with the new headers in place', async () => {
		const dir = freshDataDir('coop-e2e-roundtrip');
		try {
			const proc = await bootServer(dir, 3764);
			try {
				const base = 'http://127.0.0.1:3764';

				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: true }),
				});
				expect(createRes.status).toBe(201);
				const { id, editToken } = await createRes.json();

				const cipher = new Uint8Array(48);
				for (let i = 0; i < cipher.length; i++) cipher[i] = i;

				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'ct-name', size: cipher.length, mime: 'application/octet-stream', cs: 20 }),
				});
				expect(regRes.status).toBe(200);
				const { fileId } = await regRes.json();

				const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: cipher,
				});
				expect(chunkRes.status).toBe(200);
				expect(chunkRes.headers.get('cross-origin-resource-policy')).toBe('same-origin');

				const finRes = await fetch(`${base}/api/shares/${id}/finalize`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken },
				});
				expect(finRes.status).toBe(200);
				expect(finRes.headers.get('cross-origin-opener-policy')).toBe('same-origin');

				const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				expect(metaRes.status).toBe(200);
				expect(metaRes.headers.get('cross-origin-resource-policy')).toBe('same-origin');

				// E2E preview/download stream raw ciphertext straight through
				// download.js - same CORP relaxation as the non-E2E path.
				const previewRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`, {
					headers: { 'X-Edit-Token': editToken },
				});
				expect(previewRes.status).toBe(200);
				expect(previewRes.headers.get('cross-origin-resource-policy')).toBe('cross-origin');
				expect(new Uint8Array(await previewRes.arrayBuffer())).toEqual(cipher);

				const downloadRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
					headers: { 'X-Edit-Token': editToken },
				});
				expect(downloadRes.status).toBe(200);
				expect(downloadRes.headers.get('cross-origin-resource-policy')).toBe('cross-origin');
				expect(new Uint8Array(await downloadRes.arrayBuffer())).toEqual(cipher);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
