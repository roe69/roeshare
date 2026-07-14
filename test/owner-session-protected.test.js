// D3: the server-side plumbing view.js's #edit= flow depends on - exchanging
// an X-Edit-Token for the owner-session cookie, then reading owner state
// (including the new `protected` field - see the D2/D3 note in shares.js)
// purely from that ambient cookie, exactly as the RoeSnip-provided link's
// Open action and view.js's exchangeEditToken() do.
//
// Exercises the real server end to end:
//   - POST /api/shares/:id/owner-session with X-Edit-Token sets a cookie that
//     alone (no further header) resolves owner: true on GET /api/shares/:id
//   - the same GET's `protected` field flips from false to true after the
//     owner sets a password via PATCH, using only the owner-session cookie
//     (no X-Edit-Token on the PATCH), matching what the owner-panel buttons do

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'OwnerSessionProtectedTest-Pw-2026';

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
			SECRET: `owner-session-protected-secret-${port}`,
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
	return res.headers.get('set-cookie').split(';')[0];
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

describe('owner-session cookie + protected field (D3 plumbing)', () => {
	test('X-Edit-Token exchanges for a cookie that alone resolves owner:true and tracks protected', async () => {
		const dir = freshDataDir('owner-session-protected');
		try {
			const proc = await bootServer(dir, 3770);
			try {
				const base = 'http://127.0.0.1:3770';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'owner-session-key');

				const made = await (await fetch(`${base}/api/v1/upload?expiresIn=0`, {
					method: 'POST',
					headers: { Authorization: `Bearer ${key.token}`, 'X-Filename': 'owner.txt' },
					body: new Uint8Array([1, 2, 3]),
				})).json();
				expect(made.editToken).toBeTruthy();

				// Exactly what view.js's exchangeEditToken() does: a same-origin POST
				// with X-Edit-Token, no cookie yet.
				const sessionRes = await fetch(`${base}/api/shares/${made.id}/owner-session`, {
					method: 'POST',
					headers: { 'X-Edit-Token': made.editToken, Origin: base },
				});
				expect(sessionRes.status).toBe(200);
				const setCookie = sessionRes.headers.get('set-cookie');
				expect(setCookie).toBeTruthy();
				const ownerCookie = setCookie.split(';')[0];

				// GET with ONLY the cookie (no X-Edit-Token) resolves owner: true and
				// protected: false, matching a freshly-made unprotected share.
				const meta1 = await (await fetch(`${base}/api/shares/${made.id}`, { headers: { Cookie: ownerCookie } })).json();
				expect(meta1.owner).toBe(true);
				expect(meta1.protected).toBe(false);

				// Owner sets a password using ONLY the cookie (same-origin PATCH, as
				// the "Make private..." button does) - requireSameOrigin needs Origin.
				const patchRes = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', Cookie: ownerCookie, Origin: base },
					body: JSON.stringify({ password: 'cookie-owner-secret' }),
				});
				expect(patchRes.status).toBe(200);
				const patchBody = await patchRes.json();
				expect(patchBody.protected).toBe(true);

				// GET again reflects the change immediately.
				const meta2 = await (await fetch(`${base}/api/shares/${made.id}`, { headers: { Cookie: ownerCookie } })).json();
				expect(meta2.owner).toBe(true);
				expect(meta2.protected).toBe(true);

				// And clearing it again ("Remove password") flips it back.
				const clearRes = await fetch(`${base}/api/shares/${made.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', Cookie: ownerCookie, Origin: base },
					body: JSON.stringify({ password: null }),
				});
				expect(clearRes.status).toBe(200);
				const meta3 = await (await fetch(`${base}/api/shares/${made.id}`, { headers: { Cookie: ownerCookie } })).json();
				expect(meta3.protected).toBe(false);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a bogus edit token never establishes an owner session (silent-visitor fallback path)', async () => {
		const dir = freshDataDir('owner-session-bogus');
		try {
			const proc = await bootServer(dir, 3771);
			try {
				const base = 'http://127.0.0.1:3771';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'owner-session-bogus-key');

				const made = await (await fetch(`${base}/api/v1/upload?expiresIn=0`, {
					method: 'POST',
					headers: { Authorization: `Bearer ${key.token}`, 'X-Filename': 'bogus.txt' },
					body: new Uint8Array([9]),
				})).json();

				const sessionRes = await fetch(`${base}/api/shares/${made.id}/owner-session`, {
					method: 'POST',
					headers: { 'X-Edit-Token': 'not-the-real-token', Origin: base },
				});
				expect(sessionRes.status).toBe(403);
				expect(sessionRes.headers.get('set-cookie')).toBeFalsy();

				// Metadata still loads fine as an ordinary visitor (view.js's silent
				// fallback path - no error surfaced to the page).
				const meta = await (await fetch(`${base}/api/shares/${made.id}`)).json();
				expect(meta.owner).toBe(false);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
