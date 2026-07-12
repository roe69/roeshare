// Regression test for the static-asset Cache-Control fix: JS/CSS used to be
// served `no-store` (every request round-trips to origin, and a CDN like
// Cloudflare bypasses its edge cache entirely for a no-store response). They
// now default to `no-cache` (ETag-revalidated: cacheable, but never served
// without a successful conditional GET first - the same policy images/fonts
// already used, which is what prevents the "stale sibling import" bug no-store
// used to guard against). The two gated bundles (js/upload.js, js/admin.js)
// deliberately stay on `no-store` even for an authorized requester, as
// defense-in-depth against a misbehaving CDN revalidation path - see the
// NO_STORE_PATHS comment in src/server.js.
//
// Boots the real server as a child process (mirrors body-limits-csp.test.js /
// security-fixes.test.js) since this is an HTTP-surface behavior.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'StaticCacheTest-Pw-2026';
const UPLOAD_PASSWORD = 'StaticCacheUploadTest-2026';

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
			ADMIN_PASSWORD,
			SECRET: `static-cache-secret-${port}`,
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

function getSetCookies(res) {
	if (typeof res.headers.getSetCookie === 'function') return res.headers.getSetCookie();
	const single = res.headers.get('set-cookie');
	return single ? [single] : [];
}

function cookieNamed(cookies, name) {
	return cookies.find(c => c.startsWith(`${name}=`));
}

describe('static asset Cache-Control (no-store -> no-cache)', () => {
	test('unauthenticated: /css/app.css and /js/shared.js are no-cache with a working ETag and a correct 304 on matching If-None-Match', async () => {
		const dir = freshDataDir('static-cache-public');
		try {
			const proc = await bootServer(dir, 3870);
			try {
				const base = 'http://127.0.0.1:3870';
				for (const path of ['/css/app.css', '/js/shared.js']) {
					const first = await fetch(`${base}${path}`);
					expect(first.status).toBe(200);
					expect(first.headers.get('cache-control')).toBe('no-cache');
					const etag = first.headers.get('etag');
					expect(typeof etag).toBe('string');
					expect(etag.length).toBeGreaterThan(0);
					await first.arrayBuffer();

					const revalidated = await fetch(`${base}${path}`, { headers: { 'If-None-Match': etag } });
					expect(revalidated.status).toBe(304);
					expect(revalidated.headers.get('cache-control')).toBe('no-cache');
					await revalidated.arrayBuffer();
				}
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('unauthorized visitors still get a 404 (not the source) for /js/upload.js and /js/admin.js', async () => {
		const dir = freshDataDir('static-cache-gated-404');
		try {
			// UPLOAD_PASSWORD must be set for upload.js to be gated at all -
			// hasUploadAccess() deliberately grants everyone access when no upload
			// password is configured (open uploads), so /js/upload.js is only ever
			// a 404 for an unauthorized caller once a password is actually set.
			const proc = await bootServer(dir, 3871, { UPLOAD_PASSWORD });
			try {
				const base = 'http://127.0.0.1:3871';
				const uploadRes = await fetch(`${base}/js/upload.js`);
				expect(uploadRes.status).toBe(404);
				await uploadRes.arrayBuffer();

				const adminRes = await fetch(`${base}/js/admin.js`);
				expect(adminRes.status).toBe(404);
				await adminRes.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('authorized admin.js and upload.js stay no-store even though the caller is entitled to see them, and do not 304', async () => {
		const dir = freshDataDir('static-cache-gated-nostore');
		try {
			const proc = await bootServer(dir, 3872, { UPLOAD_PASSWORD });
			try {
				const base = 'http://127.0.0.1:3872';

				// Admin session.
				const loginRes = await fetch(`${base}/api/admin/login`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ password: ADMIN_PASSWORD }),
				});
				expect(loginRes.status).toBe(200);
				const loginBody = await loginRes.json();
				expect(loginBody.mfaRequired).toBeFalsy();
				const adminCookie = cookieNamed(getSetCookies(loginRes), 'roeshare_admin');
				expect(adminCookie).toBeTruthy();

				const adminJsRes = await fetch(`${base}/js/admin.js`, { headers: { Cookie: adminCookie } });
				expect(adminJsRes.status).toBe(200);
				expect(adminJsRes.headers.get('cache-control')).toBe('no-store');
				const adminEtag = adminJsRes.headers.get('etag');
				await adminJsRes.arrayBuffer();

				// A no-store response must never 304, even given its own ETag back -
				// only no-cache assets take part in revalidation (staticResponse()).
				const adminJsReval = await fetch(`${base}/js/admin.js`, {
					headers: { Cookie: adminCookie, 'If-None-Match': adminEtag },
				});
				expect(adminJsReval.status).toBe(200);
				expect(adminJsReval.headers.get('cache-control')).toBe('no-store');
				await adminJsReval.arrayBuffer();

				// Upload session.
				const verifyRes = await fetch(`${base}/api/upload/verify`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ password: UPLOAD_PASSWORD }),
				});
				expect(verifyRes.status).toBe(200);
				const uploadCookie = cookieNamed(getSetCookies(verifyRes), 'roeshare_upload');
				expect(uploadCookie).toBeTruthy();

				const uploadJsRes = await fetch(`${base}/js/upload.js`, { headers: { Cookie: uploadCookie } });
				expect(uploadJsRes.status).toBe(200);
				expect(uploadJsRes.headers.get('cache-control')).toBe('no-store');
				await uploadJsRes.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
