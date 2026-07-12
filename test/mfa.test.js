// F-13: admin authentication was a single shared password with no MFA. Covers
// the new RFC 6238 TOTP second factor end to end - enrollment, password+code
// login, a stolen password alone NOT granting a session, disabling MFA
// returning to password-only login, and a backup code being single-use.
//
// The TOTP algorithm (base32 decode, HMAC-SHA1, RFC 4226 dynamic truncation)
// is reimplemented independently here rather than importing src/lib/totp.js,
// so a subtle bug in the server's implementation would show up as a test
// failure instead of being rubber-stamped by both sides sharing the same bug.
//
// Boots the real server as a child process (mirrors csrf.test.js / migrations.test.js).

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHmac } from 'node:crypto';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'MfaTest-Pw-2026';

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
			SECRET: `mfa-test-secret-${port}`,
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

// ---- Independent RFC 6238 TOTP implementation (test-side only) -------------

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32DecodeIndependent(str) {
	const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
	let bits = '';
	for (const c of clean) {
		const idx = B32_ALPHABET.indexOf(c);
		if (idx === -1) continue;
		bits += idx.toString(2).padStart(5, '0');
	}
	const bytes = [];
	for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
	return Buffer.from(bytes);
}

// Independently implements RFC 4226 HOTP + the RFC 6238 time-step derivation.
function totpCodeIndependent(secretB32, stepOffset = 0) {
	const key = base32DecodeIndependent(secretB32);
	const counter = Math.floor(Date.now() / 1000 / 30) + stepOffset;
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(BigInt(counter));
	const digest = createHmac('sha1', key).update(buf).digest();
	const offset = digest[19] & 0xf;
	const binCode =
		((digest[offset] & 0x7f) << 24) |
		((digest[offset + 1] & 0xff) << 16) |
		((digest[offset + 2] & 0xff) << 8) |
		(digest[offset + 3] & 0xff);
	return String(binCode % 1_000_000).padStart(6, '0');
}

// ---- Shared helpers ----------------------------------------------------------

function getSetCookies(res) {
	// Modern fetch spec API for reading multiple identically-named response
	// headers (needed here: the MFA login-completion response sets both the
	// real admin cookie AND clears the intermediate MFA cookie in one response).
	if (typeof res.headers.getSetCookie === 'function') return res.headers.getSetCookie();
	const single = res.headers.get('set-cookie');
	return single ? [single] : [];
}

function cookieNamed(cookies, name) {
	return cookies.find(c => c.startsWith(`${name}=`));
}

async function passwordLogin(base) {
	// Origin: base simulates a legitimate same-origin browser request - login is
	// CSRF-checked (L-01: absent Origin/Sec-Fetch-Site now fails closed).
	const res = await fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	return res;
}

async function fullAdminCookie(base) {
	const res = await passwordLogin(base);
	expect(res.status).toBe(200);
	const body = await res.json();
	expect(body.mfaRequired).toBeFalsy();
	const cookies = getSetCookies(res);
	return cookieNamed(cookies, 'roeshare_admin');
}

async function enrollMfa(base, adminCookie) {
	const setupRes = await fetch(`${base}/api/admin/mfa/setup`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: adminCookie, Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	expect(setupRes.status).toBe(200);
	const { secret } = await setupRes.json();
	expect(typeof secret).toBe('string');
	expect(secret.length).toBeGreaterThan(0);

	const code = totpCodeIndependent(secret);
	const confirmRes = await fetch(`${base}/api/admin/mfa/confirm`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: adminCookie, Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD, code }),
	});
	expect(confirmRes.status).toBe(200);
	const confirmBody = await confirmRes.json();
	expect(confirmBody.ok).toBe(true);
	expect(Array.isArray(confirmBody.backupCodes)).toBe(true);
	expect(confirmBody.backupCodes.length).toBe(10);
	for (const c of confirmBody.backupCodes) expect(c).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);

	return { secret, backupCodes: confirmBody.backupCodes };
}

describe('F-13 admin TOTP MFA', () => {
	test('enroll, then log in requiring both password and a valid code', async () => {
		const dir = freshDataDir('mfa-enroll-login');
		const port = 3800;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;

			// Before enrollment: /api/admin/mfa reports disabled.
			const adminCookie = await fullAdminCookie(base);
			const statusBefore = await fetch(`${base}/api/admin/mfa`, { headers: { Cookie: adminCookie } });
			expect((await statusBefore.json())).toEqual({ enabled: false, pendingSetup: false, backupCodesRemaining: 0 });

			const { secret } = await enrollMfa(base, adminCookie);

			// The just-enrolled session is invalidated the instant MFA is enabled
			// (the admin cookie's fingerprint folds in mfaEnabledAt()).
			const staleCheck = await fetch(`${base}/api/admin/me`, { headers: { Cookie: adminCookie } });
			expect((await staleCheck.json()).admin).toBe(false);

			// A fresh password-only login now requires a second step.
			const loginRes = await passwordLogin(base);
			expect(loginRes.status).toBe(200);
			const loginBody = await loginRes.json();
			expect(loginBody.mfaRequired).toBe(true);
			const loginCookies = getSetCookies(loginRes);
			expect(cookieNamed(loginCookies, 'roeshare_admin')).toBeUndefined();
			const mfaCookie = cookieNamed(loginCookies, 'roeshare_admin_mfa');
			expect(mfaCookie).toBeTruthy();
			const mfaCookieHeader = mfaCookie.split(';')[0];

			// Complete the second step with an independently-computed valid code.
			// Offset +1: confirmEnrollment() just consumed the CURRENT step as its
			// lastUsedStep, so the replay guard would reject that same step being
			// reused here a moment later (by design) - the next step over is a
			// fresh, still-valid code.
			const code = totpCodeIndependent(secret, 1);
			const mfaRes = await fetch(`${base}/api/admin/login/mfa`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: mfaCookieHeader, Origin: base },
				body: JSON.stringify({ code }),
			});
			expect(mfaRes.status).toBe(200);
			const mfaCookies = getSetCookies(mfaRes);
			const newAdminCookie = cookieNamed(mfaCookies, 'roeshare_admin');
			expect(newAdminCookie).toBeTruthy();

			const me = await fetch(`${base}/api/admin/me`, { headers: { Cookie: newAdminCookie.split(';')[0] } });
			expect((await me.json()).admin).toBe(true);

			const statusAfter = await fetch(`${base}/api/admin/mfa`, { headers: { Cookie: newAdminCookie.split(';')[0] } });
			const statusAfterBody = await statusAfter.json();
			expect(statusAfterBody.enabled).toBe(true);
			expect(statusAfterBody.backupCodesRemaining).toBe(10);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a wrong or missing code is rejected at the MFA step', async () => {
		const dir = freshDataDir('mfa-wrong-code');
		const port = 3801;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const adminCookie = await fullAdminCookie(base);
			await enrollMfa(base, adminCookie);

			const loginRes = await passwordLogin(base);
			const mfaCookie = cookieNamed(getSetCookies(loginRes), 'roeshare_admin_mfa').split(';')[0];

			const wrong = await fetch(`${base}/api/admin/login/mfa`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: mfaCookie, Origin: base },
				body: JSON.stringify({ code: '000000' }),
			});
			expect(wrong.status).toBe(403);
			expect(getSetCookies(wrong).find(c => c.startsWith('roeshare_admin='))).toBeUndefined();

			const missing = await fetch(`${base}/api/admin/login/mfa`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: mfaCookie, Origin: base },
				body: JSON.stringify({}),
			});
			expect(missing.status).toBe(403);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a stolen password alone does not grant a session when MFA is enabled', async () => {
		const dir = freshDataDir('mfa-stolen-password');
		const port = 3802;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const adminCookie = await fullAdminCookie(base);
			await enrollMfa(base, adminCookie);

			// The attacker has the correct password and nothing else.
			const loginRes = await passwordLogin(base);
			expect(loginRes.status).toBe(200);
			const body = await loginRes.json();
			expect(body.mfaRequired).toBe(true);
			expect(body.ok).toBe(true);
			const cookies = getSetCookies(loginRes);
			// No real admin cookie is ever issued from the password step alone.
			expect(cookieNamed(cookies, 'roeshare_admin')).toBeUndefined();

			// Nothing usable to authenticate an admin request with yet - only the
			// short-lived intermediate cookie, which isAdmin() never accepts.
			const mfaCookie = cookieNamed(cookies, 'roeshare_admin_mfa').split(';')[0];
			const attempt = await fetch(`${base}/api/admin/shares`, { headers: { Cookie: mfaCookie } });
			expect(attempt.status).toBe(403);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('disabling MFA returns to password-only login', async () => {
		const dir = freshDataDir('mfa-disable');
		const port = 3803;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const adminCookie = await fullAdminCookie(base);
			const { secret, backupCodes } = await enrollMfa(base, adminCookie);

			// Complete a real MFA login to get a working admin session again.
			const loginRes = await passwordLogin(base);
			const mfaCookie = cookieNamed(getSetCookies(loginRes), 'roeshare_admin_mfa').split(';')[0];
			const mfaLoginRes = await fetch(`${base}/api/admin/login/mfa`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: mfaCookie, Origin: base },
				// Offset +1 for the same replay-guard reason as the enroll/login test.
				body: JSON.stringify({ code: totpCodeIndependent(secret, 1) }),
			});
			expect(mfaLoginRes.status).toBe(200);
			const workingAdminCookie = cookieNamed(getSetCookies(mfaLoginRes), 'roeshare_admin').split(';')[0];

			// Disabling requires the password AND a valid code - a bare cookie is
			// not enough on its own (checked implicitly: the call below supplies both).
			// A fresh backup code is used here (rather than a second TOTP code) to
			// avoid any risk of colliding with the TOTP step already consumed by the
			// login above, which the server's replay guard would reject.
			const disableRes = await fetch(`${base}/api/admin/mfa/disable`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: workingAdminCookie, Origin: base },
				body: JSON.stringify({ password: ADMIN_PASSWORD, code: backupCodes[0] }),
			});
			expect(disableRes.status).toBe(200);

			// Password-only login now succeeds outright again, byte-for-byte the
			// original behavior.
			const finalLogin = await passwordLogin(base);
			expect(finalLogin.status).toBe(200);
			const finalBody = await finalLogin.json();
			expect(finalBody.mfaRequired).toBeFalsy();
			expect(cookieNamed(getSetCookies(finalLogin), 'roeshare_admin')).toBeTruthy();
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('setup/confirm require the admin password - a hijacked cookie alone cannot enroll or swap TOTP', async () => {
		const dir = freshDataDir('mfa-stepup');
		const port = 3805;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const adminCookie = await fullAdminCookie(base);

			// /setup with no password at all is rejected before a pending secret is
			// even generated.
			const setupNoPw = await fetch(`${base}/api/admin/mfa/setup`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: adminCookie, Origin: base },
				body: '{}',
			});
			expect(setupNoPw.status).toBe(403);

			// /setup with a WRONG password is rejected too.
			const setupWrongPw = await fetch(`${base}/api/admin/mfa/setup`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: adminCookie, Origin: base },
				body: JSON.stringify({ password: 'definitely-not-the-password' }),
			});
			expect(setupWrongPw.status).toBe(403);

			// The correct password lets setup proceed, producing a pending secret.
			const setupOk = await fetch(`${base}/api/admin/mfa/setup`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: adminCookie, Origin: base },
				body: JSON.stringify({ password: ADMIN_PASSWORD }),
			});
			expect(setupOk.status).toBe(200);
			const { secret } = await setupOk.json();
			const code = totpCodeIndependent(secret);

			// /confirm with a correct code but no/wrong password must NOT enable MFA.
			const confirmNoPw = await fetch(`${base}/api/admin/mfa/confirm`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: adminCookie, Origin: base },
				body: JSON.stringify({ code }),
			});
			expect(confirmNoPw.status).toBe(403);
			const statusStillOff = await fetch(`${base}/api/admin/mfa`, { headers: { Cookie: adminCookie } });
			expect((await statusStillOff.json()).enabled).toBe(false);

			// The correct password (and the pending code) now succeeds.
			const confirmOk = await fetch(`${base}/api/admin/mfa/confirm`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: adminCookie, Origin: base },
				body: JSON.stringify({ password: ADMIN_PASSWORD, code }),
			});
			expect(confirmOk.status).toBe(200);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('re-enrolling while MFA is already enabled additionally requires a code from the CURRENT factor', async () => {
		const dir = freshDataDir('mfa-swap-gate');
		const port = 3806;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const adminCookie = await fullAdminCookie(base);
			const { backupCodes } = await enrollMfa(base, adminCookie);

			// enrollMfa() invalidated that session (mfaEnabledAt() changed); sign
			// back in the normal password+code way to get a live admin cookie.
			const loginRes = await passwordLogin(base);
			const mfaCookie = cookieNamed(getSetCookies(loginRes), 'roeshare_admin_mfa').split(';')[0];
			const mfaLoginRes = await fetch(`${base}/api/admin/login/mfa`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: mfaCookie, Origin: base },
				body: JSON.stringify({ code: backupCodes[0] }),
			});
			expect(mfaLoginRes.status).toBe(200);
			const liveCookie = cookieNamed(getSetCookies(mfaLoginRes), 'roeshare_admin').split(';')[0];

			// Attacker holds the hijacked cookie AND has just learned the password
			// (e.g. via the disable endpoint's own password requirement being
			// satisfied some other way) - but has no access to the real device's
			// authenticator. Starting a new enrollment is still allowed (password
			// checks out)...
			const setupRes = await fetch(`${base}/api/admin/mfa/setup`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: liveCookie, Origin: base },
				body: JSON.stringify({ password: ADMIN_PASSWORD }),
			});
			expect(setupRes.status).toBe(200);
			const { secret: newSecret } = await setupRes.json();
			const newCode = totpCodeIndependent(newSecret);

			// ...but confirming the swap WITHOUT a code from the still-enrolled
			// factor must be rejected - this is the swap-prevention gate.
			const confirmNoExisting = await fetch(`${base}/api/admin/mfa/confirm`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: liveCookie, Origin: base },
				body: JSON.stringify({ password: ADMIN_PASSWORD, code: newCode }),
			});
			expect(confirmNoExisting.status).toBe(403);
			const statusStillOld = await fetch(`${base}/api/admin/mfa`, { headers: { Cookie: liveCookie } });
			expect((await statusStillOld.json()).enabled).toBe(true);

			// Supplying a correct existingCode (a fresh, still-unused backup code)
			// lets the swap complete.
			const confirmWithExisting = await fetch(`${base}/api/admin/mfa/confirm`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: liveCookie, Origin: base },
				body: JSON.stringify({ password: ADMIN_PASSWORD, code: newCode, existingCode: backupCodes[1] }),
			});
			expect(confirmWithExisting.status).toBe(200);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a backup code works exactly once, then is rejected on reuse', async () => {
		const dir = freshDataDir('mfa-backup-code');
		const port = 3804;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const adminCookie = await fullAdminCookie(base);
			const { backupCodes } = await enrollMfa(base, adminCookie);
			const backupCode = backupCodes[0];

			const loginRes = await passwordLogin(base);
			const mfaCookie = cookieNamed(getSetCookies(loginRes), 'roeshare_admin_mfa').split(';')[0];

			const first = await fetch(`${base}/api/admin/login/mfa`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: mfaCookie, Origin: base },
				body: JSON.stringify({ code: backupCode }),
			});
			expect(first.status).toBe(200);
			expect(cookieNamed(getSetCookies(first), 'roeshare_admin')).toBeTruthy();

			// Reusing the SAME backup code on a fresh login attempt must fail.
			const loginRes2 = await passwordLogin(base);
			const mfaCookie2 = cookieNamed(getSetCookies(loginRes2), 'roeshare_admin_mfa').split(';')[0];
			const second = await fetch(`${base}/api/admin/login/mfa`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: mfaCookie2, Origin: base },
				body: JSON.stringify({ code: backupCode }),
			});
			expect(second.status).toBe(403);
			expect(cookieNamed(getSetCookies(second), 'roeshare_admin')).toBeUndefined();

			// A backup code entered without its formatting dash must also work
			// (case-insensitive, dash-optional) - use a fresh unused code for this.
			const secondCode = backupCodes[1];
			const loginRes3 = await passwordLogin(base);
			const mfaCookie3 = cookieNamed(getSetCookies(loginRes3), 'roeshare_admin_mfa').split(';')[0];
			const third = await fetch(`${base}/api/admin/login/mfa`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: mfaCookie3, Origin: base },
				body: JSON.stringify({ code: secondCode.replace('-', '').toLowerCase() }),
			});
			expect(third.status).toBe(200);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});
