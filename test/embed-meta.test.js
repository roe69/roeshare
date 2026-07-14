// C: server-rendered OpenGraph/Twitter embed meta for the view page, on BOTH
// GET /s/:id and the root-level slug fallback (server.js) - the latter is
// CRITICAL because the one-shot upload's returned url is `{origin}/{id}`, so
// every RoeSnip-created link hits the fallback, not /s/:id.
//
// Exercises the real server end to end:
//   - a public, finalized, non-e2e, single-image share gets rich meta with an
//     escaped title/description and an og:image pointing at /preview
//   - a title containing an attribute-breakout XSS payload comes out fully
//     escaped (no raw '<' or unescaped '"' near the injected value)
//   - missing id, e2e, password-protected, one-time, and non-image shares all
//     render byte-identical GENERIC meta (no per-share data leaks through)
//   - two different shares never leak each other's title into one another's
//     response (no cross-share cache poisoning)
//   - fetching the page does not touch the share's view_count (a crawler
//     prefetching a pasted link must not inflate the owner's stats)

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'EmbedMetaTest-Pw-2026';

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
			ADMIN_PASSWORD,
			SECRET: `embed-meta-secret-${port}`,
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

async function adminCookie(base) {
	const res = await fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	expect(res.status).toBe(200);
	const setCookie = res.headers.get('set-cookie');
	return setCookie.split(';')[0];
}

async function makeKey(base, cookie, name) {
	const res = await fetch(`${base}/api/admin/api-keys`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
		body: JSON.stringify({ name }),
	});
	expect(res.status).toBe(201);
	return res.json();
}

async function adminViewCount(base, cookie, id) {
	const res = await fetch(`${base}/api/admin/shares/${id}`, { headers: { Cookie: cookie } });
	expect(res.status).toBe(200);
	const body = await res.json();
	return body.viewCount;
}

describe('embed meta (C)', () => {
	test('rich meta for a public finalized single-image share; XSS-safe title; served on BOTH /s/:id and the root slug fallback', async () => {
		const dir = freshDataDir('embed-rich');
		try {
			const proc = await bootServer(dir, 3760);
			try {
				const base = 'http://127.0.0.1:3760';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'embed-rich-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const xssTitle = '"><script>alert(1)</script>';
				const res = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&title=${encodeURIComponent(xssTitle)}`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'pic.png' },
					body: new Uint8Array([137, 80, 78, 71]),
				});
				expect(res.status).toBe(201);
				const made = await res.json();

				for (const path of [`/s/${made.id}`, `/${made.id}`]) {
					const pageRes = await fetch(`${base}${path}`);
					expect(pageRes.status).toBe(200);
					const html = await pageRes.text();

					// No raw script tag or attribute-breakout anywhere in the page.
					expect(html).not.toContain('<script>alert(1)</script>');
					expect(html).not.toContain('"><script>');
					// The escaped form is present.
					expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
					expect(html).toContain('&quot;&gt;&lt;script&gt;');

					// Rich og:image points at the /preview endpoint for this file.
					const imageUrl = `${base}/api/shares/${made.id}/files/${made.fileId}/preview`;
					expect(html).toContain(`content="${imageUrl}"`);
					expect(html).toContain('property="og:image:type" content="image/png"');
					expect(html).toContain('name="twitter:card" content="summary_large_image"');
				}

				// The og:image URL itself actually serves the image, unauthenticated.
				const previewRes = await fetch(`${base}/api/shares/${made.id}/files/${made.fileId}/preview`);
				expect(previewRes.status).toBe(200);
				expect(previewRes.headers.get('content-type')).toContain('image/png');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('missing/e2e/password/one-time/non-image shares all render byte-identical generic meta; no cross-share leakage; view_count untouched', async () => {
		const dir = freshDataDir('embed-generic');
		try {
			const proc = await bootServer(dir, 3761);
			try {
				const base = 'http://127.0.0.1:3761';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'embed-generic-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				// Non-image mime.
				const nonImageRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=text%2Fplain`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'notes.txt' },
					body: new Uint8Array([1]),
				});
				const nonImage = await nonImageRes.json();

				// Password-protected image.
				const passwordRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&title=SecretPic`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'p.png', 'X-Upload-Password': 'embed-secret-1' },
					body: new Uint8Array([1, 2]),
				});
				const password = await passwordRes.json();

				// One-time image.
				const oneTimeRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&oneTime=1&title=OneTimePic`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'o.png' },
					body: new Uint8Array([1, 2, 3]),
				});
				const oneTime = await oneTimeRes.json();

				// Download-capped image: the og:image target (/preview) 403s for a
				// non-owner whenever max_downloads is set (download.js), so this must
				// get generic meta too rather than a half-working embed.
				const cappedRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&maxDownloads=3&title=CappedPic`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'c.png' },
					body: new Uint8Array([1, 2, 3, 4]),
				});
				const capped = await cappedRes.json();

				// E2E share (via the web-portal resumable flow; e2e is not reachable
				// through the API-key one-shot path).
				const draftRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ expiresIn: 0, e2e: true, title: 'E2ESecretTitle' }),
				});
				expect(draftRes.status).toBe(201);
				const draft = await draftRes.json();
				const regRes = await fetch(`${base}/api/shares/${draft.id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': draft.editToken, Origin: base },
					body: JSON.stringify({ name: 'enc-blob', size: 4, mime: 'application/octet-stream' }),
				});
				expect(regRes.status).toBe(200);
				const reg = await regRes.json();
				const chunkRes = await fetch(`${base}/api/shares/${draft.id}/files/${reg.fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/octet-stream', 'X-Edit-Token': draft.editToken, Origin: base },
					body: new Uint8Array([9, 9, 9, 9]),
				});
				expect(chunkRes.status).toBe(200);
				const finRes = await fetch(`${base}/api/shares/${draft.id}/finalize`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': draft.editToken, Origin: base },
				});
				expect(finRes.status).toBe(200);

				const missingId = 'no-such-share-id-xyz';

				const pages = {};
				for (const [label, id] of Object.entries({ missing: missingId, nonImage: nonImage.id, password: password.id, oneTime: oneTime.id, e2e: draft.id, capped: capped.id })) {
					const r = await fetch(`${base}/${id}`);
					expect(r.status).toBe(200);
					pages[label] = await r.text();
				}

				// All six are byte-for-byte identical - none leaks a title/description/image.
				const values = Object.values(pages);
				for (let i = 1; i < values.length; i++) {
					expect(values[i]).toBe(values[0]);
				}
				expect(pages.password).not.toContain('SecretPic');
				expect(pages.oneTime).not.toContain('OneTimePic');
				expect(pages.e2e).not.toContain('E2ESecretTitle');
				expect(pages.capped).not.toContain('CappedPic');
				expect(pages.missing).not.toContain('og:image');

				// Cross-share leakage check against the rich (image) share from the
				// other test: create two DIFFERENT rich shares here and confirm
				// neither's title appears in the other's page.
				const picARes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&title=ShareAAAtitle`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'a.png' },
					body: new Uint8Array([1]),
				});
				const picA = await picARes.json();
				const picBRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&title=ShareBBBtitle`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'b.png' },
					body: new Uint8Array([1]),
				});
				const picB = await picBRes.json();

				const pageA = await (await fetch(`${base}/${picA.id}`)).text();
				const pageB = await (await fetch(`${base}/${picB.id}`)).text();
				expect(pageA).toContain('ShareAAAtitle');
				expect(pageA).not.toContain('ShareBBBtitle');
				expect(pageB).toContain('ShareBBBtitle');
				expect(pageB).not.toContain('ShareAAAtitle');

				// Re-fetching A again is still A's own title (no poisoning from B's request in between).
				const pageAAgain = await (await fetch(`${base}/${picA.id}`)).text();
				expect(pageAAgain).toContain('ShareAAAtitle');
				expect(pageAAgain).not.toContain('ShareBBBtitle');

				// view_count is untouched by page fetches (crawler prefetch safety).
				const before = await adminViewCount(base, cookie, picA.id);
				await fetch(`${base}/s/${picA.id}`);
				await fetch(`${base}/${picA.id}`);
				const after = await adminViewCount(base, cookie, picA.id);
				expect(after).toBe(before);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
