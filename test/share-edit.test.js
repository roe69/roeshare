// D2: PATCH /api/shares/:id - the minimal owner self-service surface (change
// or clear expiry, set/replace/clear the password). Exercises the real
// server end to end:
//   - owner can set expiry to never (0) and to a positive offset
//   - owner setting a password invalidates a pre-existing visitor access
//     token (tokens are bound to password_hash) and gates the share
//   - owner can clear the password again ("make public")
//   - a non-owner (no edit token) gets 403
//   - an invalid expiresIn is 400
//   - the rate limit (20/min/share) fires on the 21st request

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'ShareEditTest-Pw-2026';

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
			SECRET: `share-edit-secret-${port}`,
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

async function makeShare(base) {
	const res = await fetch(`${base}/api/v1/upload?expiresIn=0`, {
		method: 'POST',
		headers: { ...(await keyAuth(base)), 'X-Filename': 'edit-test.txt' },
		body: new Uint8Array([1, 2, 3]),
	});
	expect(res.status).toBe(201);
	return res.json();
}

let cachedAuth = null;
async function keyAuth(base) {
	if (cachedAuth) return cachedAuth;
	const loginRes = await fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	const cookie = loginRes.headers.get('set-cookie').split(';')[0];
	const keyRes = await fetch(`${base}/api/admin/api-keys`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
		body: JSON.stringify({ name: 'share-edit-key' }),
	});
	const key = await keyRes.json();
	cachedAuth = { Authorization: `Bearer ${key.token}` };
	return cachedAuth;
}

describe('PATCH /api/shares/:id (D2)', () => {
	test('owner can change expiry to never and to a positive offset', async () => {
		cachedAuth = null;
		const dir = freshDataDir('share-edit-expiry');
		try {
			const proc = await bootServer(dir, 3750);
			try {
				const base = 'http://127.0.0.1:3750';
				const made = await makeShare(base);

				const before = Math.floor(Date.now() / 1000);
				const res = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ expiresIn: 3600 }),
				});
				expect(res.status).toBe(200);
				const body = await res.json();
				expect(body.ok).toBe(true);
				expect(body.expiresAt).toBeGreaterThanOrEqual(before + 3600 - 5);
				expect(body.expiresAt).toBeLessThanOrEqual(before + 3600 + 30);

				// Back to never.
				const res2 = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ expiresIn: 0 }),
				});
				expect(res2.status).toBe(200);
				const body2 = await res2.json();
				expect(body2.expiresAt).toBeNull();

				// Unspecified expiresIn on an unrelated password change leaves it unchanged.
				const res3 = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({}),
				});
				expect(res3.status).toBe(200);
				const body3 = await res3.json();
				expect(body3.expiresAt).toBeNull();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('setting a password invalidates a pre-existing access token and gates the share; clearing makes it public again', async () => {
		cachedAuth = null;
		const dir = freshDataDir('share-edit-password');
		try {
			const proc = await bootServer(dir, 3751);
			try {
				const base = 'http://127.0.0.1:3751';
				const made = await makeShare(base);

				// A visitor with no password fetches metadata freely before any password exists.
				const openRes = await fetch(`${base}/api/shares/${made.id}`);
				expect(openRes.status).toBe(200);

				// Owner sets a password.
				const patchRes = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ password: 'now-private-123' }),
				});
				expect(patchRes.status).toBe(200);
				const patchBody = await patchRes.json();
				expect(patchBody.protected).toBe(true);

				// A now-unauthenticated visitor is gated.
				const gatedRes = await fetch(`${base}/api/shares/${made.id}`);
				expect(gatedRes.status).toBe(401);
				const gatedBody = await gatedRes.json();
				expect(gatedBody.protected).toBe(true);

				// Unlock with the new password to get an access token.
				const unlockRes = await fetch(`${base}/api/shares/${made.id}/unlock`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password: 'now-private-123' }),
				});
				expect(unlockRes.status).toBe(200);
				const { accessToken } = await unlockRes.json();
				expect(accessToken).toBeTruthy();

				// That token works right now.
				const withToken = await fetch(`${base}/api/shares/${made.id}?access=${encodeURIComponent(accessToken)}`);
				expect(withToken.status).toBe(200);

				// Owner changes the password again - the old access token, bound to
				// the old password_hash, must stop working.
				const patchRes2 = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ password: 'yet-another-pw-456' }),
				});
				expect(patchRes2.status).toBe(200);

				const staleToken = await fetch(`${base}/api/shares/${made.id}?access=${encodeURIComponent(accessToken)}`);
				expect(staleToken.status).toBe(401);

				// Owner clears the password ("make public").
				const clearRes = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ password: null }),
				});
				expect(clearRes.status).toBe(200);
				const clearBody = await clearRes.json();
				expect(clearBody.protected).toBe(false);

				const publicAgain = await fetch(`${base}/api/shares/${made.id}`);
				expect(publicAgain.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('non-owner gets 403; invalid expiresIn is 400', async () => {
		cachedAuth = null;
		const dir = freshDataDir('share-edit-forbidden');
		try {
			const proc = await bootServer(dir, 3752);
			try {
				const base = 'http://127.0.0.1:3752';
				const made = await makeShare(base);

				const forbidden = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ expiresIn: 60 }),
				});
				expect(forbidden.status).toBe(403);

				const badExpiry = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ expiresIn: 'not-a-number' }),
				});
				expect(badExpiry.status).toBe(400);

				const negativeExpiry = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ expiresIn: -5 }),
				});
				expect(negativeExpiry.status).toBe(400);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a max_expiry-capped key cannot PATCH a share past its cap, even to never', async () => {
		cachedAuth = null;
		const dir = freshDataDir('share-edit-cap');
		try {
			const proc = await bootServer(dir, 3754);
			try {
				const base = 'http://127.0.0.1:3754';

				const loginRes = await fetch(`${base}/api/admin/login`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ password: ADMIN_PASSWORD }),
				});
				const cookie = loginRes.headers.get('set-cookie').split(';')[0];
				const keyRes = await fetch(`${base}/api/admin/api-keys`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
					body: JSON.stringify({ name: 'capped-key', limits: { maxExpiry: 3600 } }),
				});
				expect(keyRes.status).toBe(201);
				const key = await keyRes.json();
				const auth = { Authorization: `Bearer ${key.token}` };

				const madeRes = await fetch(`${base}/api/v1/upload?expiresIn=0`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'capped.txt' },
					body: new Uint8Array([1]),
				});
				expect(madeRes.status).toBe(201);
				const made = await madeRes.json();
				// The 1-hour cap already clamped the "never" request at creation.
				expect(made.expiresAt).not.toBeNull();
				const capLimit = made.expiresAt;

				// PATCHing to "never" must still respect the cap, not bypass it.
				const patchNever = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ expiresIn: 0 }),
				});
				expect(patchNever.status).toBe(200);
				const neverBody = await patchNever.json();
				expect(neverBody.expiresAt).not.toBeNull();
				expect(neverBody.expiresAt).toBeLessThanOrEqual(capLimit + 5);

				// PATCHing to something longer than the cap is clamped down to it.
				const patchLong = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
					body: JSON.stringify({ expiresIn: 999_999 }),
				});
				expect(patchLong.status).toBe(200);
				const longBody = await patchLong.json();
				expect(longBody.expiresAt).toBeLessThanOrEqual(capLimit + 5);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('PATCH expiresIn on a not-yet-finalized share is refused (would be re-shifted by finalize)', async () => {
		cachedAuth = null;
		const dir = freshDataDir('share-edit-unfinalized');
		try {
			const proc = await bootServer(dir, 3755);
			try {
				const base = 'http://127.0.0.1:3755';

				const draftRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ expiresIn: 0 }),
				});
				expect(draftRes.status).toBe(201);
				const draft = await draftRes.json();

				// Not finalized yet - changing expiry must be refused, not silently
				// accepted and then overshot by finalize's shiftExpiry.
				const patchRes = await fetch(`${base}/api/shares/${draft.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': draft.editToken, Origin: base },
					body: JSON.stringify({ expiresIn: 3600 }),
				});
				expect(patchRes.status).toBe(409);

				// A password-only PATCH (no expiresIn) is unaffected.
				const passRes = await fetch(`${base}/api/shares/${draft.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': draft.editToken, Origin: base },
					body: JSON.stringify({ password: 'still-fine-123' }),
				});
				expect(passRes.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('rate limit fires after 20 edits in a minute', async () => {
		cachedAuth = null;
		const dir = freshDataDir('share-edit-ratelimit');
		try {
			const proc = await bootServer(dir, 3753);
			try {
				const base = 'http://127.0.0.1:3753';
				const made = await makeShare(base);

				let last;
				for (let i = 0; i < 21; i++) {
					last = await fetch(`${base}/api/shares/${made.id}`, {
						method: 'PATCH',
						headers: { 'Content-Type': 'application/json', 'X-Edit-Token': made.editToken, Origin: base },
						body: JSON.stringify({ expiresIn: 3600 + i }),
					});
				}
				expect(last.status).toBe(429);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
