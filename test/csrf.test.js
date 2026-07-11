// F-10: cookie-authenticated privileged mutations lack explicit CSRF defense.
//
// Every ambient cookie in this app (roeshare_admin, roeshare_apikey,
// roeshare_upload) is already SameSite=Lax + HttpOnly, which blocks cookie
// attachment on cross-site non-GET requests in all evergreen browsers. The fix
// (requireSameOrigin() in lib/http.js) is defense-in-depth on top of that: it
// rejects a non-GET mutation carrying proof of a cross-site origin (Origin or
// Sec-Fetch-Site), while a request with NEITHER header (a non-browser client -
// curl, a backup script, server-to-server) is let through, since it carries no
// ambient cookie an attacker's page could have ridden along.
//
// Covers all three surfaces from the audit:
//   - src/routes/admin.js: every non-GET route, gated on the isAdmin() cookie.
//   - src/routes/api.js: the cookie-authenticated path of DELETE /api/v1/shares/:id
//     (authenticateSource()'s viaCookie flag) - the bearer-token path is exempt.
//   - src/routes/shares.js: DELETE /api/shares/:id via the isAdmin() cookie (the
//     X-Edit-Token header path is exempt, it's not an ambient credential), and
//     POST /api/shares via the upload-password cookie (an explicit body password
//     is exempt, same reasoning).
//
// Boots the real server as a child process (mirrors security-regressions.test.js).

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'CsrfTest-Pw-2026';

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
			SECRET: `csrf-secret-${port}`,
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

// Plain fetch() (as used by every existing test in this repo) never sends
// Origin or Sec-Fetch-Site itself, so it always exercises the "non-browser
// client" pass-through path unless we add the headers explicitly below - that
// is what makes it a faithful stand-in for a real cross-origin browser
// request (which always carries at least one of them) vs. a legitimate
// same-origin one (which we simulate with a matching Origin/Sec-Fetch-Site).

async function adminCookie(base) {
	const res = await fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	expect(res.status).toBe(200);
	return res.headers.get('set-cookie').split(';')[0];
}

async function createShare(base, headers = {}) {
	const res = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body: JSON.stringify({ e2e: false }),
	});
	expect(res.status).toBe(201);
	return res.json();
}

describe('F-10 CSRF: admin.js (ambient roeshare_admin cookie)', () => {
	test('cross-origin Origin on a PATCH is rejected; same-origin Origin succeeds', async () => {
		const dir = freshDataDir('csrf-admin-patch');
		const proc = await bootServer(dir, 3750);
		try {
			const base = 'http://127.0.0.1:3750';
			const cookie = await adminCookie(base);
			const { id } = await createShare(base);

			const crossSite = await fetch(`${base}/api/admin/shares/${id}`, {
				method: 'PATCH',
				headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: 'http://evil.example.com' },
				body: JSON.stringify({ title: 'pwned' }),
			});
			expect(crossSite.status).toBe(403);
			const crossBody = await crossSite.json();
			expect(crossBody.error).toMatch(/cross-origin/i);

			const sameOrigin = await fetch(`${base}/api/admin/shares/${id}`, {
				method: 'PATCH',
				headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
				body: JSON.stringify({ title: 'legit' }),
			});
			expect(sameOrigin.status).toBe(200);

			// The title must reflect only the accepted (same-origin) request.
			const check = await fetch(`${base}/api/admin/shares/${id}`, { headers: { Cookie: cookie } });
			const checkBody = await check.json();
			expect(checkBody.title).toBe('legit');
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('Sec-Fetch-Site is checked before Origin: cross-site is rejected even with a matching Origin, same-origin is accepted even with a mismatched Origin', async () => {
		const dir = freshDataDir('csrf-admin-sfs');
		const proc = await bootServer(dir, 3751);
		try {
			const base = 'http://127.0.0.1:3751';
			const cookie = await adminCookie(base);
			const { id: id1 } = await createShare(base);
			const { id: id2 } = await createShare(base);

			// Sec-Fetch-Site: cross-site wins over a same-origin-looking Origin.
			const bad = await fetch(`${base}/api/admin/shares/${id1}`, {
				method: 'DELETE',
				headers: { Cookie: cookie, Origin: base, 'Sec-Fetch-Site': 'cross-site' },
			});
			expect(bad.status).toBe(403);

			// Sec-Fetch-Site: same-origin wins over a mismatched/absent Origin.
			const good = await fetch(`${base}/api/admin/shares/${id2}`, {
				method: 'DELETE',
				headers: { Cookie: cookie, Origin: 'http://evil.example.com', 'Sec-Fetch-Site': 'same-origin' },
			});
			expect(good.status).toBe(200);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a non-browser admin client (no Origin, no Sec-Fetch-Site) is unaffected', async () => {
		const dir = freshDataDir('csrf-admin-nonbrowser');
		const proc = await bootServer(dir, 3752);
		try {
			const base = 'http://127.0.0.1:3752';
			const cookie = await adminCookie(base);
			const { id } = await createShare(base);

			const res = await fetch(`${base}/api/admin/shares/${id}`, {
				method: 'DELETE',
				headers: { Cookie: cookie },
			});
			expect(res.status).toBe(200);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('POST /api/admin/login itself is rejected cross-origin (login-CSRF hygiene)', async () => {
		const dir = freshDataDir('csrf-admin-login');
		const proc = await bootServer(dir, 3753);
		try {
			const base = 'http://127.0.0.1:3753';
			const res = await fetch(`${base}/api/admin/login`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example.com' },
				body: JSON.stringify({ password: ADMIN_PASSWORD }),
			});
			expect(res.status).toBe(403);
			expect(res.headers.get('set-cookie')).toBeFalsy();
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});

describe('F-10 CSRF: api.js DELETE /api/v1/shares/:id (cookie path only)', () => {
	async function makeKeyAndSession(base, adminCk) {
		const keyRes = await fetch(`${base}/api/admin/api-keys`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: adminCk },
			body: JSON.stringify({ name: 'csrf-test-key' }),
		});
		expect(keyRes.status).toBe(201);
		const key = await keyRes.json();

		const loginRes = await fetch(`${base}/api/v1/login`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ token: key.token, name: key.name }),
		});
		expect(loginRes.status).toBe(200);
		const sessionCookie = loginRes.headers.get('set-cookie').split(';')[0];
		return { key, sessionCookie };
	}

	async function createShareViaBearer(base, token) {
		const res = await fetch(`${base}/api/v1/shares`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
			body: JSON.stringify({}),
		});
		expect(res.status).toBe(201);
		return res.json();
	}

	test('cross-origin portal-cookie DELETE is rejected; same-origin succeeds', async () => {
		const dir = freshDataDir('csrf-api-delete');
		const proc = await bootServer(dir, 3754);
		try {
			const base = 'http://127.0.0.1:3754';
			const adminCk = await adminCookie(base);
			const { key, sessionCookie } = await makeKeyAndSession(base, adminCk);

			const share1 = await createShareViaBearer(base, key.token);
			const crossSite = await fetch(`${base}/api/v1/shares/${share1.id}`, {
				method: 'DELETE',
				headers: { Cookie: sessionCookie, Origin: 'http://evil.example.com' },
			});
			expect(crossSite.status).toBe(403);

			const share2 = await createShareViaBearer(base, key.token);
			const sameOrigin = await fetch(`${base}/api/v1/shares/${share2.id}`, {
				method: 'DELETE',
				headers: { Cookie: sessionCookie, Origin: base },
			});
			expect(sameOrigin.status).toBe(200);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a bearer-token DELETE with no Origin and no CSRF proof still succeeds (non-browser clients unaffected)', async () => {
		const dir = freshDataDir('csrf-api-bearer');
		const proc = await bootServer(dir, 3755);
		try {
			const base = 'http://127.0.0.1:3755';
			const adminCk = await adminCookie(base);
			const { key } = await makeKeyAndSession(base, adminCk);

			const share = await createShareViaBearer(base, key.token);
			const res = await fetch(`${base}/api/v1/shares/${share.id}`, {
				method: 'DELETE',
				headers: { Authorization: `Bearer ${key.token}` },
			});
			expect(res.status).toBe(200);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});

describe('F-10 CSRF: shares.js (admin-cookie delete + upload-password-cookie create)', () => {
	test('DELETE /api/shares/:id via the admin cookie is CSRF-checked; the X-Edit-Token owner path is unaffected', async () => {
		const dir = freshDataDir('csrf-shares-delete');
		const proc = await bootServer(dir, 3756);
		try {
			const base = 'http://127.0.0.1:3756';
			const adminCk = await adminCookie(base);

			const { id: id1 } = await createShare(base);
			const crossSite = await fetch(`${base}/api/shares/${id1}`, {
				method: 'DELETE',
				headers: { Cookie: adminCk, Origin: 'http://evil.example.com' },
			});
			expect(crossSite.status).toBe(403);

			const sameOrigin = await fetch(`${base}/api/shares/${id1}`, {
				method: 'DELETE',
				headers: { Cookie: adminCk, Origin: base },
			});
			expect(sameOrigin.status).toBe(200);

			// The edit-token path (X-Edit-Token header, not an ambient cookie) must
			// keep working with no Origin at all, cross-site or otherwise.
			const draft = await fetch(`${base}/api/shares`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ e2e: false }),
			});
			const { id: id2, editToken } = await draft.json();
			const viaEditToken = await fetch(`${base}/api/shares/${id2}`, {
				method: 'DELETE',
				headers: { 'X-Edit-Token': editToken, Origin: 'http://evil.example.com' },
			});
			expect(viaEditToken.status).toBe(200);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('POST /api/shares via the upload-password cookie is CSRF-checked; an explicit body password is unaffected', async () => {
		const dir = freshDataDir('csrf-shares-upload-cookie');
		const UPLOAD_PASSWORD = 'CsrfUploadTest-2026';
		const proc = await bootServer(dir, 3757, { UPLOAD_PASSWORD });
		try {
			const base = 'http://127.0.0.1:3757';

			const verify = await fetch(`${base}/api/upload/verify`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ password: UPLOAD_PASSWORD }),
			});
			expect(verify.status).toBe(200);
			const uploadCookie = verify.headers.get('set-cookie').split(';')[0];

			// Ambient upload cookie, cross-origin -> rejected, and NOT the generic
			// "Upload password required" message (proves it got past the auth check
			// and was specifically stopped by the CSRF gate).
			const crossSite = await fetch(`${base}/api/shares`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: uploadCookie, Origin: 'http://evil.example.com' },
				body: JSON.stringify({ e2e: false }),
			});
			expect(crossSite.status).toBe(403);
			const crossBody = await crossSite.json();
			expect(crossBody.error).toMatch(/cross-origin/i);

			// Ambient upload cookie, same-origin -> succeeds.
			const sameOrigin = await fetch(`${base}/api/shares`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: uploadCookie, Origin: base },
				body: JSON.stringify({ e2e: false }),
			});
			expect(sameOrigin.status).toBe(201);

			// An explicit body password (no cookie at all) is not an ambient
			// credential, so it is never asked for CSRF proof, even cross-origin.
			const viaPassword = await fetch(`${base}/api/shares`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example.com' },
				body: JSON.stringify({ e2e: false, uploadPassword: UPLOAD_PASSWORD }),
			});
			expect(viaPassword.status).toBe(201);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});
