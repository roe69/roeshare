// M-3: the upload quick-access magic link used to be redeemed as a side
// effect of a bare GET (and, since router.js auto-routes HEAD to GET, a bare
// HEAD too) reaching GET / with a ?token= query param. The link is designed
// to be pasted into chat/email, where link-preview scanners (Slack, Teams,
// Outlook Safe Links, Proofpoint, iMessage, ...) prefetch pasted URLs
// server-side with no cookie and no JS execution - a prefetch would silently
// and permanently burn the single-use token before the intended human ever
// clicked it.
//
// Fix: GET/HEAD / never redeems the token anymore - it only serves a minimal
// interstitial page (link.html) when a token is present. That page's module
// script (public/js/link-redeem.js), which only runs in a real browser, is
// what fires the actual POST /api/upload/link/redeem that consumes the
// token and issues the upload cookie.
//
// This exercises the real server end to end:
//   - a bare GET (and a bare HEAD) to the token URL does NOT consume the
//     token: it serves the interstitial page, not the lock or upload page,
//     and the token can still be redeemed afterward
//   - POST /api/upload/link/redeem actually consumes the token: it succeeds
//     once (granting the upload cookie), and a second call with the same
//     token fails (single-use preserved)

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const UPLOAD_PASSWORD = 'MagicLinkPrefetchTest-Pw-2026';

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
			ADMIN_PASSWORD: 'MagicLinkPrefetchTest-Admin-2026',
			SECRET: `magic-link-prefetch-secret-${port}`,
			UPLOAD_PASSWORD,
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

// Unlock the upload gate the normal way (typed password) and return the
// resulting upload-cookie header value.
async function uploadCookie(base) {
	const res = await fetch(`${base}/api/upload/verify`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password: UPLOAD_PASSWORD }),
	});
	expect(res.status).toBe(200);
	const setCookie = res.headers.get('set-cookie');
	return setCookie.split(';')[0];
}

// Mint a fresh single-use quick-access link token (same-origin, cookie-
// authorized, exactly like the upload portal's "copy quick-access link"
// button).
async function mintLinkToken(base, cookie) {
	const res = await fetch(`${base}/api/upload/link`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
	});
	expect(res.status).toBe(200);
	const body = await res.json();
	expect(body.enabled).toBe(true);
	const url = new URL(body.url);
	const token = url.searchParams.get('token');
	expect(token).toBeTruthy();
	return token;
}

describe('M-3: magic-link redemption is immune to non-JS link-preview prefetch', () => {
	test('a bare GET does not consume the token; POST /api/upload/link/redeem does (single-use)', async () => {
		const dir = freshDataDir('magic-link-get');
		try {
			const proc = await bootServer(dir, 3840);
			try {
				const base = 'http://127.0.0.1:3840';
				const cookie = await uploadCookie(base);
				const token = await mintLinkToken(base, cookie);

				// Simulate a link-preview scanner: a bare GET with no cookie and no JS.
				const prefetchRes = await fetch(`${base}/?token=${encodeURIComponent(token)}`);
				expect(prefetchRes.status).toBe(200);
				const prefetchBody = await prefetchRes.text();
				// Serves the interstitial page - never the unlocked upload portal, and
				// never silently falls back to the plain lock page either.
				expect(prefetchBody).toContain('link-redeem.js');
				expect(prefetchBody).not.toContain('id="dropzone"');
				expect(prefetchBody).not.toContain('id="lock-form"');
				expect(prefetchRes.headers.get('set-cookie')).toBeNull();

				// A bare HEAD (what router.js auto-routes GET handlers to answer) must
				// not consume it either.
				const headRes = await fetch(`${base}/?token=${encodeURIComponent(token)}`, { method: 'HEAD' });
				expect(headRes.status).toBe(200);
				expect(headRes.headers.get('set-cookie')).toBeNull();

				// The token is still live: the real redeem endpoint (what the
				// interstitial page's browser JS calls) can still consume it.
				const redeemRes = await fetch(`${base}/api/upload/link/redeem`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ token }),
				});
				expect(redeemRes.status).toBe(200);
				const redeemBody = await redeemRes.json();
				expect(redeemBody.ok).toBe(true);
				const grantedCookie = redeemRes.headers.get('set-cookie');
				expect(grantedCookie).toBeTruthy();

				// The granted cookie actually unlocks the upload portal.
				const unlockedRes = await fetch(`${base}/`, { headers: { Cookie: grantedCookie.split(';')[0] } });
				expect(unlockedRes.status).toBe(200);
				const unlockedBody = await unlockedRes.text();
				expect(unlockedBody).toContain('id="dropzone"');

				// Single-use: redeeming the same token again fails.
				const secondRedeemRes = await fetch(`${base}/api/upload/link/redeem`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ token }),
				});
				expect(secondRedeemRes.status).toBe(403);
				expect(secondRedeemRes.headers.get('set-cookie')).toBeNull();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('an invalid/unknown token is rejected generically by the redeem endpoint', async () => {
		const dir = freshDataDir('magic-link-invalid');
		try {
			const proc = await bootServer(dir, 3841);
			try {
				const base = 'http://127.0.0.1:3841';
				const res = await fetch(`${base}/api/upload/link/redeem`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ token: 'not-a-real-token' }),
				});
				expect(res.status).toBe(403);
				const body = await res.json();
				expect(body.error).toBeTruthy();
				expect(res.headers.get('set-cookie')).toBeNull();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
