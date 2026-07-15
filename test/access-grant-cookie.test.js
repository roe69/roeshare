// 2026-07 audit F-3: unlocking (or owning) a password-protected share now also
// sets a same-origin, HttpOnly, per-share grant cookie carrying the exact same
// signed access token the JSON body already returns (see lib/auth.js's
// readAccessGrantCookie / issueAccessToken). This is purely ADDITIVE - it must
// never replace or weaken the existing `Authorization: Bearer` / `?access=`
// query-string paths, which DEPLOY.md's separate-file-domain recipe depends on
// (a cookie set on the app's own origin cannot follow a URL to a different
// registrable domain). Exercises:
//   - unlock sets the cookie, and the cookie alone (no query token, no header)
//     authenticates a subsequent metadata/preview/download request
//   - the owner branch of GET /api/shares/:id sets the same cookie too
//   - the existing `?access=` query token keeps working unchanged (F-3 adds,
//     never removes, the query fallback)
//   - the cookie is bound to password_hash like the query token: changing the
//     share's password invalidates a previously-issued grant cookie

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'AccessCookieTest-Pw-2026';

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
			SECRET: `access-cookie-secret-${port}`,
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

// Create a password-protected, finalized, one-file share via the plain web
// portal (no upload password configured, so no gate to clear first).
async function makeProtectedShare(base, password) {
	const createRes = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password }),
	});
	expect(createRes.status).toBe(201);
	const { id, editToken } = await createRes.json();

	const regRes = await fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/json' },
		body: JSON.stringify({ name: 'f.bin', size: 3, mime: 'application/octet-stream' }),
	});
	expect(regRes.status).toBe(200);
	const { fileId } = await regRes.json();
	const patchRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
		method: 'PATCH',
		headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
		body: new Uint8Array([1, 2, 3]),
	});
	expect(patchRes.status).toBe(200);
	const finalizeRes = await fetch(`${base}/api/shares/${id}/finalize`, { method: 'POST', headers: { 'X-Edit-Token': editToken } });
	expect(finalizeRes.status).toBe(200);

	return { id, editToken, fileId };
}

describe('per-share access grant cookie (2026-07 audit F-3)', () => {
	test('unlock sets an ambient cookie that alone authenticates metadata/preview/download, without weakening the existing ?access= path', async () => {
		const dir = freshDataDir('access-cookie-unlock');
		try {
			const proc = await bootServer(dir, 3990);
			try {
				const base = 'http://127.0.0.1:3990';
				const { id, fileId } = await makeProtectedShare(base, 'unlock-me-123');

				// A cold visitor is gated.
				const gatedRes = await fetch(`${base}/api/shares/${id}`);
				expect(gatedRes.status).toBe(401);

				// Unlock; capture both the JSON accessToken (unchanged, existing
				// behavior) and the new grant cookie.
				const unlockRes = await fetch(`${base}/api/shares/${id}/unlock`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password: 'unlock-me-123' }),
				});
				expect(unlockRes.status).toBe(200);
				const { accessToken } = await unlockRes.json();
				expect(accessToken).toBeTruthy();
				const setCookieHeader = unlockRes.headers.get('set-cookie');
				expect(setCookieHeader).toBeTruthy();
				expect(setCookieHeader).toContain(`roeshare_access_${id}=`);
				expect(setCookieHeader).toContain('HttpOnly');
				const grantCookie = setCookieHeader.split(';')[0];

				// The existing `?access=` query token keeps working unchanged - F-3
				// only ADDS the cookie path, never removes the query fallback (which
				// DEPLOY.md's separate-file-domain recipe depends on).
				const withQueryToken = await fetch(`${base}/api/shares/${id}?access=${encodeURIComponent(accessToken)}`);
				expect(withQueryToken.status).toBe(200);

				// The cookie ALONE (no query token, no Authorization header)
				// authenticates the same metadata route.
				const withCookieOnly = await fetch(`${base}/api/shares/${id}`, { headers: { Cookie: grantCookie } });
				expect(withCookieOnly.status).toBe(200);

				// ...and the preview/download routes too (the ones view.js's
				// withAccess() targets with <img>/<video> src / download links).
				const previewRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`, { headers: { Cookie: grantCookie } });
				expect(previewRes.status).toBe(200);

				const downloadRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, { headers: { Cookie: grantCookie } });
				expect(downloadRes.status).toBe(200);

				// No cookie, no query token, no header: still gated as before.
				const stillGatedRes = await fetch(`${base}/api/shares/${id}`);
				expect(stillGatedRes.status).toBe(401);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('the owner metadata branch also sets the grant cookie, and it is invalidated by a password change like the query token', async () => {
		const dir = freshDataDir('access-cookie-owner');
		try {
			const proc = await bootServer(dir, 3991);
			try {
				const base = 'http://127.0.0.1:3991';
				const { id, editToken } = await makeProtectedShare(base, 'owner-pw-123');

				// Owner reads their own share metadata via the edit token - this is
				// the OTHER place issueAccessToken() is minted (GET /api/shares/:id's
				// owner branch), so it must set the grant cookie too.
				const ownerMetaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				expect(ownerMetaRes.status).toBe(200);
				const ownerBody = await ownerMetaRes.json();
				expect(ownerBody.accessToken).toBeTruthy();
				const setCookieHeader = ownerMetaRes.headers.get('set-cookie');
				expect(setCookieHeader).toBeTruthy();
				expect(setCookieHeader).toContain(`roeshare_access_${id}=`);
				const grantCookie = setCookieHeader.split(';')[0];

				// A stranger with only that cookie (no edit token) reads as an
				// ordinary unlocked visitor.
				const visitorRes = await fetch(`${base}/api/shares/${id}`, { headers: { Cookie: grantCookie } });
				expect(visitorRes.status).toBe(200);
				const visitorBody = await visitorRes.json();
				expect(visitorBody.owner).toBe(false);

				// Owner changes the password - the grant cookie, bound to the OLD
				// password_hash exactly like the query token, must stop working.
				const patchRes = await fetch(`${base}/api/shares/${id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken, Origin: base },
					body: JSON.stringify({ password: 'a-different-pw-456' }),
				});
				expect(patchRes.status).toBe(200);

				const staleRes = await fetch(`${base}/api/shares/${id}`, { headers: { Cookie: grantCookie } });
				expect(staleRes.status).toBe(401);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
