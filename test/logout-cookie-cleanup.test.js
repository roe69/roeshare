// Regression test: logout must clear a session cookie regardless of which
// cookie NAME it was issued under.
//
// lib/http.js's sessionCookieName()/readSessionCookie() pair name a session
// cookie "__Host-<base>" once a request is seen over https (secure=true),
// but readSessionCookie() still falls back to accepting the legacy plain
// "<base>" name too, for migration compatibility (e.g. a session issued
// before a deployment started terminating TLS / setting X-Forwarded-Proto,
// still sitting in the browser's cookie jar). A logout handler that only
// clears sessionCookieName(base, secure) - the CURRENT dynamically-computed
// name - never instructs the browser to drop that legacy-named cookie, so it
// keeps being sent (and keeps authenticating) on every request after logout.
//
// Simulated end to end: a "pre-deploy" login is performed WITHOUT
// X-Forwarded-Proto (secure=false -> plain cookie name), then the
// environment is treated as having moved to https (X-Forwarded-Proto: https
// from a trusted peer -> secure=true, "__Host-" names) for every request
// after that, exactly as it would for a real deployment. Logout is called in
// that https context while the browser still only holds the legacy
// plain-named cookie - it must still clear it.
//
// Boots the real server as a child process (mirrors trusted-proxy.test.js).

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'LogoutCleanupTest-Pw-2026';
const LOOPBACK_CIDRS = '127.0.0.1/32,::1/128';

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
			SECRET: `logout-cleanup-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			TRUSTED_PROXY_CIDRS: LOOPBACK_CIDRS,
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

// A minimal browser-like cookie jar: applies every Set-Cookie from a response
// (a Max-Age=0 entry deletes, anything else sets/overwrites), and renders the
// current contents back into a Cookie header string - exactly what a real
// browser would send on the next request. Per RFC 6265bis, a real browser
// refuses to store/act on a Set-Cookie for a "__Host-"-prefixed name unless
// it also carries the Secure attribute - mirror that here, otherwise this
// simulator would give false confidence that a spec-non-compliant clear
// directive actually cleared the cookie.
function applySetCookies(jar, res) {
	for (const raw of getSetCookies(res)) {
		const [pair, ...attrs] = raw.split(';').map(s => s.trim());
		const eq = pair.indexOf('=');
		const name = pair.slice(0, eq);
		const value = pair.slice(eq + 1);
		const secure = attrs.some(a => /^secure$/i.test(a));
		if (name.startsWith('__Host-') && !secure) continue;
		const maxAge = attrs.find(a => /^max-age=/i.test(a));
		if (maxAge && Number(maxAge.split('=')[1]) <= 0) jar.delete(name);
		else jar.set(name, value);
	}
}

function cookieHeader(jar) {
	return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

describe('logout clears a session cookie regardless of which name it was issued under', () => {
	test('admin logout clears a legacy plain-named cookie left over from before the deployment used "__Host-" naming', async () => {
		const dir = freshDataDir('admin-logout-legacy');
		const port = 3920;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const jar = new Map();

			// "Pre-deploy" login: no X-Forwarded-Proto, so secure=false and the
			// session cookie is issued under the plain "roeshare_admin" name - the
			// legacy name a still-outstanding browser session would carry.
			const loginRes = await fetch(`${base}/api/admin/login`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: base },
				body: JSON.stringify({ password: ADMIN_PASSWORD }),
			});
			expect(loginRes.status).toBe(200);
			const loginCookies = getSetCookies(loginRes);
			expect(loginCookies.find(c => c.startsWith('roeshare_admin='))).toBeTruthy();
			expect(loginCookies.find(c => c.startsWith('__Host-roeshare_admin='))).toBeUndefined();
			applySetCookies(jar, loginRes);
			expect(jar.has('roeshare_admin')).toBe(true);

			// Sanity: the legacy cookie authenticates.
			const before = await fetch(`${base}/api/admin/me`, { headers: { Cookie: cookieHeader(jar) } });
			expect((await before.json()).admin).toBe(true);

			// The deployment has since moved to https (trusted proxy signaling
			// X-Forwarded-Proto): every request from here on is seen as secure, so
			// the CURRENT dynamically-computed cookie name is "__Host-roeshare_admin"
			// - but the browser still only holds the legacy plain-named cookie from
			// the earlier login. Logging out in this context must still clear it.
			const logoutRes = await fetch(`${base}/api/admin/logout`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: base, 'X-Forwarded-Proto': 'https', Cookie: cookieHeader(jar) },
			});
			expect(logoutRes.status).toBe(200);
			const logoutCookies = getSetCookies(logoutRes);
			// Both the current dynamic name AND the legacy plain name must be
			// cleared (Max-Age=0), not just the one the current request's scheme
			// would mint.
			const legacyClear = logoutCookies.find(c => c.startsWith('roeshare_admin=') && !c.startsWith('roeshare_admin_mfa='));
			const currentClear = logoutCookies.find(c => c.startsWith('__Host-roeshare_admin='));
			expect(legacyClear).toBeTruthy();
			expect(/max-age=0/i.test(legacyClear)).toBe(true);
			expect(currentClear).toBeTruthy();
			expect(/max-age=0/i.test(currentClear)).toBe(true);

			applySetCookies(jar, logoutRes);
			expect(jar.has('roeshare_admin')).toBe(false);
			expect(jar.has('__Host-roeshare_admin')).toBe(false);

			// End to end: replaying whatever the jar has left (i.e. what a real
			// browser would now send) no longer authenticates.
			const after = await fetch(`${base}/api/admin/me`, { headers: { Cookie: cookieHeader(jar) } });
			expect((await after.json()).admin).toBe(false);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('api key (v1) logout clears a legacy plain-named session cookie the same way', async () => {
		const dir = freshDataDir('apikey-logout-legacy');
		const port = 3921;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;

			// Mint an API key via the admin panel so /api/v1/login has a name+token
			// to authenticate with.
			const adminLogin = await fetch(`${base}/api/admin/login`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: base },
				body: JSON.stringify({ password: ADMIN_PASSWORD }),
			});
			const adminCookie = getSetCookies(adminLogin).find(c => c.startsWith('roeshare_admin=')).split(';')[0];
			const keyRes = await fetch(`${base}/api/admin/api-keys`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: base, Cookie: adminCookie },
				body: JSON.stringify({ name: 'logout-cleanup-key' }),
			});
			expect(keyRes.status).toBe(201);
			const { name, token } = await keyRes.json();

			const jar = new Map();

			// "Pre-deploy" portal login: no X-Forwarded-Proto -> plain
			// "roeshare_apikey" cookie name.
			const portalLogin = await fetch(`${base}/api/v1/login`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: base },
				body: JSON.stringify({ name, token }),
			});
			expect(portalLogin.status).toBe(200);
			const portalCookies = getSetCookies(portalLogin);
			expect(portalCookies.find(c => c.startsWith('roeshare_apikey='))).toBeTruthy();
			expect(portalCookies.find(c => c.startsWith('__Host-roeshare_apikey='))).toBeUndefined();
			applySetCookies(jar, portalLogin);

			const before = await fetch(`${base}/api/v1/session`, { headers: { Cookie: cookieHeader(jar) } });
			expect((await before.json()).session).not.toBeNull();

			// Now in an https context (trusted proxy + X-Forwarded-Proto), logout
			// must still clear the legacy-named cookie the browser is holding.
			const logoutRes = await fetch(`${base}/api/v1/logout`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: base, 'X-Forwarded-Proto': 'https', Cookie: cookieHeader(jar) },
			});
			expect(logoutRes.status).toBe(200);
			const logoutCookies = getSetCookies(logoutRes);
			const legacyClear = logoutCookies.find(c => c.startsWith('roeshare_apikey='));
			const currentClear = logoutCookies.find(c => c.startsWith('__Host-roeshare_apikey='));
			expect(legacyClear).toBeTruthy();
			expect(/max-age=0/i.test(legacyClear)).toBe(true);
			expect(currentClear).toBeTruthy();
			expect(/max-age=0/i.test(currentClear)).toBe(true);

			applySetCookies(jar, logoutRes);
			const after = await fetch(`${base}/api/v1/session`, { headers: { Cookie: cookieHeader(jar) } });
			expect((await after.json()).session).toBeNull();
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	// The two tests above cover a session issued BEFORE https (legacy plain
	// cookie name) surviving a post-deploy logout. They never actually put a
	// "__Host-" cookie in the jar, so they can't catch a regression in the
	// Secure attribute on the "__Host-" clear directive itself - the jar's own
	// spec-compliant applySetCookies() would just silently ignore a malformed
	// clear either way. These two additional tests cover the everyday/primary
	// case: a session both issued AND torn down while already on https, where
	// the browser genuinely holds a "__Host-" cookie and a missing Secure
	// attribute on logout's clear directive means the browser rejects the
	// clear outright and the session cookie survives "logout".
	test('admin logout clears a "__Host-" session cookie issued and torn down under https (primary case)', async () => {
		const dir = freshDataDir('admin-logout-https');
		const port = 3922;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const jar = new Map();
			const httpsHeaders = { 'Content-Type': 'application/json', Origin: base, 'X-Forwarded-Proto': 'https' };

			const loginRes = await fetch(`${base}/api/admin/login`, {
				method: 'POST',
				headers: httpsHeaders,
				body: JSON.stringify({ password: ADMIN_PASSWORD }),
			});
			expect(loginRes.status).toBe(200);
			const loginSetCookie = getSetCookies(loginRes).find(c => c.startsWith('__Host-roeshare_admin='));
			expect(loginSetCookie).toBeTruthy();
			expect(/;\s*secure\s*(;|$)/i.test(loginSetCookie)).toBe(true);
			applySetCookies(jar, loginRes);
			// The jar only stores a "__Host-" entry if Secure was present (see
			// applySetCookies) - this assertion would fail if login regressed too.
			expect(jar.has('__Host-roeshare_admin')).toBe(true);

			const before = await fetch(`${base}/api/admin/me`, { headers: { Cookie: cookieHeader(jar) } });
			expect((await before.json()).admin).toBe(true);

			const logoutRes = await fetch(`${base}/api/admin/logout`, {
				method: 'POST',
				headers: { ...httpsHeaders, Cookie: cookieHeader(jar) },
			});
			expect(logoutRes.status).toBe(200);
			const currentClear = getSetCookies(logoutRes).find(c => c.startsWith('__Host-roeshare_admin='));
			expect(currentClear).toBeTruthy();
			expect(/max-age=0/i.test(currentClear)).toBe(true);
			// The actual bug this test exists to catch: the clear directive for a
			// "__Host-" name MUST carry Secure, or a real browser discards it and
			// the live session cookie is never cleared.
			expect(/;\s*secure\s*(;|$)/i.test(currentClear)).toBe(true);

			applySetCookies(jar, logoutRes);
			expect(jar.has('__Host-roeshare_admin')).toBe(false);

			const after = await fetch(`${base}/api/admin/me`, { headers: { Cookie: cookieHeader(jar) } });
			expect((await after.json()).admin).toBe(false);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('api key (v1) logout clears a "__Host-" session cookie issued and torn down under https (primary case)', async () => {
		const dir = freshDataDir('apikey-logout-https');
		const port = 3923;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const httpsHeaders = { 'Content-Type': 'application/json', Origin: base, 'X-Forwarded-Proto': 'https' };

			const adminLogin = await fetch(`${base}/api/admin/login`, {
				method: 'POST',
				headers: httpsHeaders,
				body: JSON.stringify({ password: ADMIN_PASSWORD }),
			});
			const adminCookie = getSetCookies(adminLogin).find(c => c.startsWith('__Host-roeshare_admin=')).split(';')[0];
			const keyRes = await fetch(`${base}/api/admin/api-keys`, {
				method: 'POST',
				headers: { ...httpsHeaders, Cookie: adminCookie },
				body: JSON.stringify({ name: 'logout-cleanup-key-https' }),
			});
			expect(keyRes.status).toBe(201);
			const { name, token } = await keyRes.json();

			const jar = new Map();
			const portalLogin = await fetch(`${base}/api/v1/login`, {
				method: 'POST',
				headers: httpsHeaders,
				body: JSON.stringify({ name, token }),
			});
			expect(portalLogin.status).toBe(200);
			const portalSetCookie = getSetCookies(portalLogin).find(c => c.startsWith('__Host-roeshare_apikey='));
			expect(portalSetCookie).toBeTruthy();
			expect(/;\s*secure\s*(;|$)/i.test(portalSetCookie)).toBe(true);
			applySetCookies(jar, portalLogin);
			expect(jar.has('__Host-roeshare_apikey')).toBe(true);

			const before = await fetch(`${base}/api/v1/session`, { headers: { Cookie: cookieHeader(jar) } });
			expect((await before.json()).session).not.toBeNull();

			const logoutRes = await fetch(`${base}/api/v1/logout`, {
				method: 'POST',
				headers: { ...httpsHeaders, Cookie: cookieHeader(jar) },
			});
			expect(logoutRes.status).toBe(200);
			const currentClear = getSetCookies(logoutRes).find(c => c.startsWith('__Host-roeshare_apikey='));
			expect(currentClear).toBeTruthy();
			expect(/max-age=0/i.test(currentClear)).toBe(true);
			expect(/;\s*secure\s*(;|$)/i.test(currentClear)).toBe(true);

			applySetCookies(jar, logoutRes);
			expect(jar.has('__Host-roeshare_apikey')).toBe(false);

			const after = await fetch(`${base}/api/v1/session`, { headers: { Cookie: cookieHeader(jar) } });
			expect((await after.json()).session).toBeNull();
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});
