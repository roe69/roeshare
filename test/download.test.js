// Regression test for the split-Range bypass on controlled (one-time /
// download-capped) shares: two ordinary non-overlapping Range requests
// (bytes=0-N then bytes=N-end) must not be able to reconstruct the whole
// file without ever tripping the one-time burn or the download cap, because
// each half individually looks like a partial read. src/routes/download.js
// closes this by forcing such a Range to be ignored (served as a normal full
// 200) for a non-owner request against a controlled share - see the
// `effRange` guard in the GET .../download handler.
//
// Since the pending-grace-redelivery fix (see download-grace.test.js), a
// second full-equivalent request landing inside the short post-completion
// grace window is answered too - but critically, it is ALWAYS the complete
// file again (the effRange forcing above is untouched by that fix), never
// just the "half" bytes its own Range header asked for - so the split-Range
// attack this file exists to guard against still cannot reconstruct the file
// out of two half-sized, individually-uncounted reads: both halves it might
// get are actually full, counted (or grace-redelivered) deliveries of the
// WHOLE file. This test drives the grace window down to near-zero via env so
// it can also assert the share is truly, permanently gone once that window
// elapses - closing the loop on "was this ever a real bypass" (no - full
// bytes both times) and "does the control still eventually hold for real"
// (yes).
//
// Boots the real server as a child process (mirrors migrations.test.js)
// since this is an HTTP-surface behavior, not a unit-testable function.

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
			ADMIN_PASSWORD: 'DownloadTest-Pw-2026',
			SECRET: `download-test-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			// Fast, deterministic pending-grace window (see download-grace.test.js)
			// so this file's own tests can assert the eventual, permanent block.
			DOWNLOAD_GRACE_MS: '500',
			DOWNLOAD_GRACE_MAX_MS: '1000',
			BASE_URL: `http://127.0.0.1:${port}`,
		},
		stdout: 'pipe',
		stderr: 'pipe',
	});

	const deadline = Date.now() + 10_000;
	let lastErr;
	while (Date.now() < deadline) {
		if (proc.exitCode !== null) break; // process already died
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

// Creates a finalized, non-E2E share with a single small (20-byte) file
// uploaded in one chunk. Returns the share id/editToken/fileId plus the
// exact bytes uploaded, for byte-for-byte comparison against what a
// download response delivers.
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
		body: JSON.stringify({ name: 'test.bin', size: bytes.length, mime: 'application/octet-stream' }),
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

describe('download route: split-Range bypass on controlled shares', () => {
	test('a one-time share cannot be reconstructed via two non-overlapping Range requests, and burns on the first', async () => {
		const dir = freshDataDir('dl-onetime');
		try {
			const proc = await bootServer(dir, 3596);
			try {
				const base = 'http://127.0.0.1:3596';
				const { id, fileId, bytes } = await makeShare(base, { oneTime: true });
				const half = bytes.length / 2;

				// First half of a split Range pair: a one-time share must not honor
				// a partial range for a non-owner - it is forced to a full delivery
				// instead, so this single request already claims the share.
				const r1 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
					headers: { Range: `bytes=0-${half - 1}` },
				});
				expect(r1.status).toBe(200); // NOT 206 - the partial range was ignored
				const b1 = new Uint8Array(await r1.arrayBuffer());
				expect(b1).toEqual(bytes); // delivered whole, not just the requested half

				// The second half of the split pair, inside the (short, test-
				// configured) pending-grace window: still forced to a full delivery
				// (never honored as a genuine 206 partial), and still redelivers the
				// COMPLETE file, not just the "second half" bytes its own Range
				// header asked for - so this is a grace-window redelivery of the
				// same entitlement, never a successful reconstruction of the file
				// out of two individually-uncounted half-reads.
				const r2 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
					headers: { Range: `bytes=${half}-${bytes.length - 1}` },
				});
				expect(r2.status).toBe(200); // NOT 206
				const b2 = new Uint8Array(await r2.arrayBuffer());
				expect(b2).toEqual(bytes); // the WHOLE file again, not just the second half

				// Once the grace window genuinely elapses, the share is truly and
				// permanently gone - a plain full GET, and a further split attempt,
				// are both refused for good.
				await new Promise(r => setTimeout(r, 1500));
				const r3 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r3.status).toBe(404);
				const r4 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
					headers: { Range: `bytes=0-${half - 1}` },
				});
				expect(r4.status).toBe(404);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a maxDownloads=1 share cannot be reconstructed via split Range requests past its cap', async () => {
		const dir = freshDataDir('dl-capped');
		try {
			const proc = await bootServer(dir, 3597);
			try {
				const base = 'http://127.0.0.1:3597';
				const { id, editToken, fileId, bytes } = await makeShare(base, { maxDownloads: 1 });
				const half = bytes.length / 2;

				// First half of the split pair: forced to a full delivery, which
				// claims the share's single download slot.
				const r1 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
					headers: { Range: `bytes=0-${half - 1}` },
				});
				expect(r1.status).toBe(200);
				const b1 = new Uint8Array(await r1.arrayBuffer());
				expect(b1).toEqual(bytes);

				// Second half, inside the (short, test-configured) pending-grace
				// window: still forced to a full delivery and still redelivers the
				// COMPLETE file, not just the "second half" bytes its own Range
				// header asked for - a grace-window redelivery of the same
				// entitlement, never a successful reconstruction out of two
				// individually-uncounted half-reads.
				const r2 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
					headers: { Range: `bytes=${half}-${bytes.length - 1}` },
				});
				expect(r2.status).toBe(200); // NOT 206, NOT 410
				const b2 = new Uint8Array(await r2.arrayBuffer());
				expect(b2).toEqual(bytes);

				// The cap must still reflect exactly one counted download, never
				// more - the grace-window redelivery above must not double-count.
				const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				const meta = await metaRes.json();
				expect(meta.downloadCount).toBe(1);

				// Once the grace window genuinely elapses, the cap holds for real -
				// a further split attempt is refused outright.
				await new Promise(r => setTimeout(r, 1500));
				const r3 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
					headers: { Range: `bytes=0-${half - 1}` },
				});
				expect(r3.status).toBe(410);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

// Regression test: every branch of rangeResponse() is documented (see the L-05
// comment above it) to always be no-store, since a share's bytes are revocable
// user content, never a deliberately public content-addressed object - but the
// 416 (invalid Range) branch was missing Cache-Control entirely, breaking that
// invariant. A response with no Cache-Control at all can fall back to a CDN's
// own default caching heuristic (this is the same class of bug fixed for the
// admin.js/upload.js access gate's 404 - see gatedNotFound() in src/server.js).
describe('download route: every response branch stays no-store', () => {
	test('an invalid Range request gets a 416 that is explicitly no-store', async () => {
		const dir = freshDataDir('dl-416-nostore');
		try {
			const proc = await bootServer(dir, 3598);
			try {
				const base = 'http://127.0.0.1:3598';
				const { id, fileId } = await makeShare(base, {});

				// end < start is an invalid Range per parseRange()'s contract.
				const res = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
					headers: { Range: 'bytes=10-2' },
				});
				expect(res.status).toBe(416);
				expect(res.headers.get('cache-control')).toBe('no-store');
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
