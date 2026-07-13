// Regression/coverage test for clipboard/text sharing (see design doc's Core
// principle: "a text snippet is staged as new File([text], name, { type:
// 'text/plain' })" and flows through the existing register -> chunk PATCH ->
// finalize pipeline untouched - zero server changes). This file only proves
// the server side of that claim: a text file round-trips byte-for-byte
// (including multi-byte UTF-8) through preview/download, and a one-time text
// share still genuinely burns after being revealed. No E2E-shaped test here
// by design (client-side only; see the design doc's ruling C3).
//
// Boots the real server as a child process, mirroring
// zero-byte-chunk-guard.test.js / download-grace.test.js.

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
			ADMIN_PASSWORD: 'TextShareTest-Pw-2026',
			SECRET: `text-share-secret-${port}`,
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

// Creates a share and uploads `text` as a single note.txt file (register ->
// one-chunk PATCH -> finalize), exactly the path a staged `new File([text],
// 'note.txt', { type: 'text/plain' })` takes client-side.
async function makeTextShare(base, text, shareBody = {}) {
	const createRes = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ e2e: false, ...shareBody }),
	});
	expect(createRes.status).toBe(201);
	const { id, editToken } = await createRes.json();

	const bytes = new TextEncoder().encode(text);
	const regRes = await fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
		body: JSON.stringify({ name: 'note.txt', size: bytes.length, mime: 'text/plain' }),
	});
	expect(regRes.status).toBe(200);
	const { fileId } = await regRes.json();

	const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
		method: 'PATCH',
		headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
		body: bytes,
	});
	expect(chunkRes.status).toBe(200);
	const chunkBody = await chunkRes.json();
	expect(chunkBody.complete).toBe(true);

	const finRes = await fetch(`${base}/api/shares/${id}/finalize`, { method: 'POST', headers: { 'X-Edit-Token': editToken } });
	expect(finRes.status).toBe(200);

	return { id, editToken, fileId, bytes };
}

const NOTE_TEXT = 'Café façade / 日本語のテスト: héllo wörld, naïve résumé ✓';

describe('text share: a pasted note round-trips through register -> chunk -> finalize -> preview', () => {
	test('plain share: metadata and preview both return the exact UTF-8 text as note.txt/text/plain', async () => {
		const dir = freshDataDir('text-plain');
		try {
			const proc = await bootServer(dir, 3970);
			try {
				const base = 'http://127.0.0.1:3970';
				const { id, fileId } = await makeTextShare(base, NOTE_TEXT);

				const metaRes = await fetch(`${base}/api/shares/${id}`);
				expect(metaRes.status).toBe(200);
				const meta = await metaRes.json();
				expect(meta.files.length).toBe(1);
				expect(meta.files[0].name).toBe('note.txt');
				expect(meta.files[0].mime).toBe('text/plain');
				expect(meta.files[0].complete).toBe(true);

				const previewRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`);
				expect(previewRes.status).toBe(200);
				expect(previewRes.headers.get('content-type')).toBe('text/plain');
				expect(previewRes.headers.get('content-disposition')).toContain('inline');
				expect(previewRes.headers.get('content-disposition')).toContain('note.txt');
				expect(previewRes.headers.get('x-content-type-options')).toBe('nosniff');
				const body = await previewRes.text();
				expect(body).toBe(NOTE_TEXT);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('text share: one-time note is preview-gated for non-owners and genuinely burns on reveal', () => {
	test('non-owner preview is 403; download reveals the text and burns the share (grace-window aware)', async () => {
		const dir = freshDataDir('text-onetime');
		try {
			// Short, deterministic grace window (see download-grace.test.js) so the
			// eventual permanent burn can be asserted quickly and reliably.
			const proc = await bootServer(dir, 3971, { DOWNLOAD_GRACE_MS: '800', DOWNLOAD_GRACE_MAX_MS: '1500' });
			try {
				const base = 'http://127.0.0.1:3971';
				const { id, fileId } = await makeTextShare(base, NOTE_TEXT, { oneTime: true });

				// A non-owner (no X-Edit-Token / access token) must not be able to
				// read a controlled share's content via preview - only via a real,
				// counted/burning download (design doc R1/#6).
				const previewRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`);
				expect(previewRes.status).toBe(403);

				const downloadRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(downloadRes.status).toBe(200);
				expect(await downloadRes.text()).toBe(NOTE_TEXT);

				// The share looks gone to a plain metadata check right away...
				const metaAfter = await fetch(`${base}/api/shares/${id}`);
				expect(metaAfter.status).toBe(404);

				// ...but a redelivery inside the short grace window must still work
				// (same entitlement, not a new one - see download-grace.test.js) and
				// must still return the full, exact text.
				const redeliverRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(redeliverRes.status).toBe(200);
				expect(await redeliverRes.text()).toBe(NOTE_TEXT);

				// Once the grace window (and its ceiling) genuinely elapses, the
				// one-time note is truly and permanently gone.
				await new Promise(r => setTimeout(r, 2000));
				const finalRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(finalRes.status).toBe(404);
				const metaFinal = await fetch(`${base}/api/shares/${id}`);
				expect(metaFinal.status).toBe(404);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
