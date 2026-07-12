// Regression test for the security-audit finding "cancelled/interrupted
// downloads still burn one-time and capped shares in production" (2026-07).
//
// download.js's one-time/maxDownloads claim machinery is designed so only a
// delivery whose stream actually drains counts/burns; a genuinely dropped
// connection restores the claim via trackedStream's onEnd. In production
// (behind Cloudflare) that guarantee does not hold: the proxy can itself
// fully absorb a streamed response - so the server sees a fully-drained
// stream (onComplete fires) - even though the real client received almost
// nothing before disconnecting. From this process's point of view, THAT
// false-positive-complete event is indistinguishable from a genuinely
// successful full download: both are "the server's ReadableStream drained
// to completion". So the regression test that actually matters is not "can
// we fake a cancel" (that already worked correctly before this fix, and
// still does) - it is "does a full, complete download still leave the
// recipient able to retry", because in production, a complete-looking
// server-side drain is exactly what a false-positive burn looks like too.
//
// The fix (download.js's pendingDelivery/armDeliveryGrace/
// finalizeOneTimeShare) holds a "full" delivery's completion PENDING for a
// short grace window instead of immediately burning/permanently spending it,
// and treats a fresh full request against the same already-claimed share as
// a redelivery retry rather than a new grant. This test drives the grace
// window down to a couple of seconds via DOWNLOAD_GRACE_MS/
// DOWNLOAD_GRACE_MAX_MS so it stays fast and deterministic.
//
// Follow-up regression test (2026-07, "grace window itself defeats
// maxDownloads"): the first cut of the fix above keyed pending state by
// shareId alone, so ANY full request landing while ANY grace window was
// open - not just a genuine retry of the claim that just completed - took
// the redelivery branch, skipping limitReached()/claimDownload()/
// claimOneTime() entirely. Verified reproduction: after one legitimate
// download of a maxDownloads=1 share, plain sequential GETs (no abort, no
// race) kept returning 200 with the full file for as long as the grace
// window stayed open, which reset on every redelivery - a full defeat of
// maxDownloads/one-time. The describe block below ("bounded per-claim retry
// budget") proves that is now closed: a controlled share always tries the
// REAL atomic claim first, and a claim that has already been redelivered
// config.downloadGraceMaxRetries times (default 1 - one legitimate
// completion's worth of retries) refuses any further redelivery, even
// though the share-level grace window (by elapsed time alone) may still be
// open. These tests pin DOWNLOAD_GRACE_MAX_RETRIES=1 explicitly so the
// bound being asserted doesn't silently drift with the config default.
//
// Boots the real server as a child process (mirrors download.test.js).

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
			ADMIN_PASSWORD: 'DownloadGraceTest-Pw-2026',
			SECRET: `download-grace-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			// Fast, deterministic grace window for the test.
			DOWNLOAD_GRACE_MS: '1500',
			DOWNLOAD_GRACE_MAX_MS: '3000',
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

	const finRes = await fetch(`${base}/api/shares/${id}/finalize`, { method: 'POST', headers: { 'X-Edit-Token': editToken } });
	expect(finRes.status).toBe(200);

	return { id, editToken, fileId, bytes };
}

describe('download route: pending-grace redelivery for one-time/capped shares', () => {
	test('one-time share: a full download that server-side completes can still be redelivered once more inside the grace window, then is truly gone after it elapses', async () => {
		const dir = freshDataDir('grace-onetime');
		try {
			const proc = await bootServer(dir, 3981);
			try {
				const base = 'http://127.0.0.1:3981';
				const { id, fileId, bytes } = await makeShare(base, { oneTime: true });

				// First, genuinely complete download - this is exactly the server-
				// observable event a Cloudflare-buffered-but-client-vanished transfer
				// ALSO produces (see the file header above): the ReadableStream drains
				// to completion either way. Before the fix, this alone permanently
				// burned the share with zero recourse.
				const r1 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r1.status).toBe(200);
				expect(new Uint8Array(await r1.arrayBuffer())).toEqual(bytes);

				// The share now looks gone to a plain metadata check - same as before
				// the fix (no regression to the "burned immediately" appearance).
				const metaAfterFirst = await fetch(`${base}/api/shares/${id}`);
				expect(metaAfterFirst.status).toBe(404);

				// But within the grace window, a fresh full download against the same
				// URL must still succeed - this is the actual fix: the recipient (or
				// anyone still holding the link, since a one-time link's only
				// authorization boundary is possession of it) gets a real chance to
				// retry instead of being permanently locked out by a signal the
				// origin cannot fully trust.
				const r2 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r2.status).toBe(200);
				expect(new Uint8Array(await r2.arrayBuffer())).toEqual(bytes);

				// Wait past the (test-shortened) grace window plus its ceiling - the
				// destructive burn must genuinely still happen eventually.
				await new Promise(r => setTimeout(r, 4000));

				const r3 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r3.status).toBe(404);
				const metaFinal = await fetch(`${base}/api/shares/${id}`);
				expect(metaFinal.status).toBe(404);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('maxDownloads=1 share: a full download can still be redelivered once more inside the grace window, then the cap truly holds after it elapses', async () => {
		const dir = freshDataDir('grace-capped');
		try {
			const proc = await bootServer(dir, 3982);
			try {
				const base = 'http://127.0.0.1:3982';
				const { id, fileId, bytes } = await makeShare(base, { maxDownloads: 1 });

				const r1 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r1.status).toBe(200);
				expect(new Uint8Array(await r1.arrayBuffer())).toEqual(bytes);

				// Before the fix, this second attempt would have returned 410
				// immediately - the recipient permanently locked out even though the
				// server has no real proof the first delivery reached them.
				const r2 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r2.status).toBe(200);
				expect(new Uint8Array(await r2.arrayBuffer())).toEqual(bytes);

				// The cap must still reflect exactly one counted download, never more
				// (redelivery inside the grace window must not double-count).
				const meta = await fetch(`${base}/api/shares/${id}`);
				expect(meta.status).toBe(200);
				const metaBody = await meta.json();
				expect(metaBody.downloadCount).toBe(1);

				// After the grace window (and its ceiling) elapses, the cap holds for
				// real - no more free redeliveries.
				await new Promise(r => setTimeout(r, 4000));
				const r3 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r3.status).toBe(410);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('download-all (zip): one-time share can be redelivered once more inside the grace window', async () => {
		const dir = freshDataDir('grace-zip');
		try {
			const proc = await bootServer(dir, 3983);
			try {
				const base = 'http://127.0.0.1:3983';
				const { id } = await makeShare(base, { oneTime: true });

				const r1 = await fetch(`${base}/api/shares/${id}/download-all`);
				expect(r1.status).toBe(200);
				await r1.arrayBuffer();

				const metaAfterFirst = await fetch(`${base}/api/shares/${id}`);
				expect(metaAfterFirst.status).toBe(404);

				// Grace-window retry via the zip path too - same claim/burn machinery.
				const r2 = await fetch(`${base}/api/shares/${id}/download-all`);
				expect(r2.status).toBe(200);
				await r2.arrayBuffer();

				await new Promise(r => setTimeout(r, 4000));
				const r3 = await fetch(`${base}/api/shares/${id}/download-all`);
				expect(r3.status).toBe(404);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('download route: pending-grace redelivery has a bounded per-claim retry budget (does not defeat maxDownloads)', () => {
	test('maxDownloads=1 share: plain sequential requests cannot ride an open grace window to unlimited redelivery', async () => {
		const dir = freshDataDir('grace-capped-bounded');
		try {
			const proc = await bootServer(dir, 3984, { DOWNLOAD_GRACE_MAX_RETRIES: '1' });
			try {
				const base = 'http://127.0.0.1:3984';
				const { id, fileId, bytes } = await makeShare(base, { maxDownloads: 1 });

				const r1 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r1.status).toBe(200);
				expect(new Uint8Array(await r1.arrayBuffer())).toEqual(bytes);

				// Immediately fire FIVE more plain, ordinary sequential GETs - no
				// abort, no race, nothing but the exact reproduction from the
				// vulnerability report. Before the per-claim retry-budget fix (the
				// original pendingDelivery was a single shareId-keyed slot, not
				// bounded by a retry count), EVERY one of these returned 200 with
				// the full file for as long as the grace window stayed open - and
				// each redelivery reset that window, so it could be ridden
				// indefinitely.
				const statuses = [];
				for (let i = 0; i < 5; i++) {
					const r = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
					statuses.push(r.status);
					if (r.status === 200) expect(new Uint8Array(await r.arrayBuffer())).toEqual(bytes);
					else await r.arrayBuffer().catch(() => {});
				}

				// Exactly ONE of the five extra requests may succeed - the single
				// bounded grace retry DOWNLOAD_GRACE_MAX_RETRIES=1 grants to the
				// one real claim above (property 1: a genuine CDN-truncation retry
				// must still get a real chance). Every other request - including
				// ones fired back-to-back with no wait at all - must be refused.
				expect(statuses.filter(s => s === 200).length).toBe(1);
				expect(statuses.filter(s => s === 410).length).toBe(4);

				// The share's counted consumption must reflect exactly ONE
				// download, never more, no matter how many 200 responses were
				// served above (a grace redelivery is the SAME entitlement, not a
				// second one).
				const meta = await fetch(`${base}/api/shares/${id}`);
				const metaBody = await meta.json();
				expect(metaBody.downloadCount).toBe(1);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('maxDownloads=2 share: total counted consumption never exceeds 2, and each of the 2 real claims gets its own independently-bounded retry', async () => {
		const dir = freshDataDir('grace-capped2-bounded');
		try {
			const proc = await bootServer(dir, 3985, { DOWNLOAD_GRACE_MAX_RETRIES: '1' });
			try {
				const base = 'http://127.0.0.1:3985';
				const { id, fileId, bytes } = await makeShare(base, { maxDownloads: 2 });

				// Two plain sequential requests both succeed as two REAL,
				// independently-claimed downloads (maxDownloads=2 genuinely allows
				// two) - not "one real download plus a grace retry". The fix
				// always tries the real atomic claim first, so a share with a free
				// slot is never funneled into the retry path just because some
				// OTHER claim happens to be mid-grace.
				const r1 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r1.status).toBe(200);
				expect(new Uint8Array(await r1.arrayBuffer())).toEqual(bytes);
				const r2 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r2.status).toBe(200);
				expect(new Uint8Array(await r2.arrayBuffer())).toEqual(bytes);

				const metaAfterTwo = await fetch(`${base}/api/shares/${id}`);
				expect((await metaAfterTwo.json()).downloadCount).toBe(2);

				// The cap is now genuinely exhausted. Each of the two real claims
				// still gets its OWN single bounded grace retry (so a
				// CDN-truncated delivery to EITHER legitimate recipient can still
				// be recovered) - at most 2 more successful redeliveries, never
				// more, and NEVER an increase to the counted download total. This
				// is the key invariant: no plain sequential flood, however long,
				// can push a maxDownloads=2 share's actual consumption past 2.
				const statuses = [];
				for (let i = 0; i < 6; i++) {
					const r = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
					statuses.push(r.status);
					if (r.status === 200) await r.arrayBuffer();
					else await r.arrayBuffer().catch(() => {});
				}
				expect(statuses.filter(s => s === 200).length).toBe(2);
				expect(statuses.filter(s => s === 410).length).toBe(4);

				const metaFinal = await fetch(`${base}/api/shares/${id}`);
				expect((await metaFinal.json()).downloadCount).toBe(2);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('one-time share: repeated plain sequential requests are bounded - never an unlimited-redelivery link', async () => {
		const dir = freshDataDir('grace-onetime-bounded');
		try {
			const proc = await bootServer(dir, 3986, { DOWNLOAD_GRACE_MAX_RETRIES: '1' });
			try {
				const base = 'http://127.0.0.1:3986';
				const { id, fileId, bytes } = await makeShare(base, { oneTime: true });

				const r1 = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(r1.status).toBe(200);
				expect(new Uint8Array(await r1.arrayBuffer())).toEqual(bytes);

				// Same reproduction as the maxDownloads case above, against a
				// one-time share: plain sequential GETs, no abort, no race.
				const statuses = [];
				for (let i = 0; i < 5; i++) {
					const r = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
					statuses.push(r.status);
					if (r.status === 200) expect(new Uint8Array(await r.arrayBuffer())).toEqual(bytes);
					else await r.arrayBuffer().catch(() => {});
				}
				expect(statuses.filter(s => s === 200).length).toBe(1);
				expect(statuses.every(s => s === 200 || s === 410)).toBe(true);

				// And, as always (existing semantics, unchanged by this fix): once
				// the grace window genuinely elapses the share is truly and
				// permanently gone - a one-time link never becomes a standing
				// multi-use link, no matter how it was probed during the window.
				await new Promise(r => setTimeout(r, 4000));
				const rFinal = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(rFinal.status).toBe(404);
				const metaFinal = await fetch(`${base}/api/shares/${id}`);
				expect(metaFinal.status).toBe(404);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('download-all (zip): maxDownloads=1 share cannot ride the grace window to unlimited zip redelivery either', async () => {
		const dir = freshDataDir('grace-zip-bounded');
		try {
			const proc = await bootServer(dir, 3987, { DOWNLOAD_GRACE_MAX_RETRIES: '1' });
			try {
				const base = 'http://127.0.0.1:3987';
				const { id } = await makeShare(base, { maxDownloads: 1 });

				const r1 = await fetch(`${base}/api/shares/${id}/download-all`);
				expect(r1.status).toBe(200);
				await r1.arrayBuffer();

				const statuses = [];
				for (let i = 0; i < 4; i++) {
					const r = await fetch(`${base}/api/shares/${id}/download-all`);
					statuses.push(r.status);
					await r.arrayBuffer().catch(() => {});
				}
				expect(statuses.filter(s => s === 200).length).toBe(1);
				expect(statuses.filter(s => s === 410).length).toBe(3);

				const meta = await fetch(`${base}/api/shares/${id}`);
				expect((await meta.json()).downloadCount).toBe(1);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
