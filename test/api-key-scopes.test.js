// F-06: API keys gained operation-level scopes (shares:create/write/read/delete)
// so a compromised single-purpose key (e.g. a backup-writer script) cannot also
// read/list/delete everything it created. Exercises two representative scope
// profiles end to end against the real server:
//
//   - a writer-only key (create+write, no read/delete): can create shares and
//     upload/finalize files, but every read/list/delete route - both the
//     bearer-token /api/v1 routes AND the edit-token routes a share it created
//     flows through (status/register/patch/finalize's write is allowed, but
//     delete via edit token and any read-elevation must be denied/degraded)
//   - a list-only key (read only): can list/inspect shares, but every
//     create/write/delete route must reject it with 403, even before the
//     target resource is resolved (DELETE on a made-up id still 403s on scope,
//     not 404).
//
// Also covers the read-elevation DEGRADE behavior (not a 403): a share made by
// a key without the read scope must still work normally for an ordinary public
// visitor (owner just collapses to false, so a password-gated share of a
// write-only key's own making correctly demands the password even from that
// key's own edit token).

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'ApiKeyScopeTest-Pw-2026';

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
			SECRET: `apikey-scope-secret-${port}`,
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
	// Origin: base simulates a legitimate same-origin browser request - login is
	// CSRF-checked (L-01: absent Origin/Sec-Fetch-Site now fails closed).
	const res = await fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	expect(res.status).toBe(200);
	const setCookie = res.headers.get('set-cookie');
	return setCookie.split(';')[0];
}

// Create a key restricted to exactly the given scopes via the admin API.
async function makeScopedKey(base, cookie, name, scopes) {
	const res = await fetch(`${base}/api/admin/api-keys`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
		body: JSON.stringify({ name, limits: { scopes } }),
	});
	expect(res.status).toBe(201);
	const body = await res.json();
	// The admin API must echo back the exact scopes just requested, not silently
	// default them to full access.
	const got = await fetch(`${base}/api/admin/api-keys/${body.id}`, { headers: { Cookie: cookie } });
	const gotBody = await got.json();
	expect(gotBody.limits.scopes).toEqual(scopes);
	return body;
}

describe('API key operation scopes (F-06)', () => {
	test('a writer-only key (create+write, no read/delete) is allowed create/write and denied read/list/delete', async () => {
		const dir = freshDataDir('scope-writer');
		try {
			const proc = await bootServer(dir, 3640);
			try {
				const base = 'http://127.0.0.1:3640';
				const cookie = await adminCookie(base);

				const writer = await makeScopedKey(base, cookie, 'writer-only', { create: true, write: true, read: false, delete: false });
				const auth = { Authorization: `Bearer ${writer.token}` };

				// Inside scope: create a share (resumable flow).
				const createRes = await fetch(`${base}/api/v1/shares`, {
					method: 'POST',
					headers: { ...auth, 'Content-Type': 'application/json' },
					body: JSON.stringify({}),
				});
				expect(createRes.status).toBe(201);
				const { id, editToken } = await createRes.json();

				// Inside scope: register + upload + finalize a file, all via the edit
				// token the share create returned - these flow through
				// scopeErrorForShare(share, 'write'), resolved from the ORIGINATING
				// (writer) key, not a fresh bearer token.
				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'f.bin', size: 5, mime: 'application/octet-stream' }),
				});
				expect(regRes.status).toBe(200);
				const { fileId } = await regRes.json();

				const statusRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/status`, { headers: { 'X-Edit-Token': editToken } });
				expect(statusRes.status).toBe(200);

				const patchRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: new Uint8Array([1, 2, 3, 4, 5]),
				});
				expect(patchRes.status).toBe(200);

				const finalizeRes = await fetch(`${base}/api/shares/${id}/finalize`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken },
				});
				expect(finalizeRes.status).toBe(200);

				// Inside scope: one-shot upload (create+write).
				const oneShotRes = await fetch(`${base}/api/v1/upload?filename=one.bin`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'one.bin' },
					body: new Uint8Array([9, 9, 9]),
				});
				expect(oneShotRes.status).toBe(201);

				// Outside scope: list/read/delete via the bearer-token /api/v1 routes.
				const listRes = await fetch(`${base}/api/v1/shares`, { headers: auth });
				expect(listRes.status).toBe(403);

				const getRes = await fetch(`${base}/api/v1/shares/${id}`, { headers: auth });
				expect(getRes.status).toBe(403);

				const delRes = await fetch(`${base}/api/v1/shares/${id}`, { method: 'DELETE', headers: auth });
				expect(delRes.status).toBe(403);

				// Outside scope: deleting the SAME share via its own edit token (the
				// resumable-flow owner-delete path) must also be denied - the write
				// scope this key has does not imply delete.
				const editDelRes = await fetch(`${base}/api/shares/${id}`, { method: 'DELETE', headers: { 'X-Edit-Token': editToken } });
				expect(editDelRes.status).toBe(403);

				// Read-elevation DEGRADES rather than 403s: the visitor-metadata route,
				// hit with this key's own edit token, must simply stop treating it as
				// the owner (no accessToken/received offsets leaked) instead of erroring.
				const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				expect(metaRes.status).toBe(200);
				const metaBody = await metaRes.json();
				expect(metaBody.owner).toBe(false);
				expect(metaBody.accessToken).toBeUndefined();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('read-scope degradation blocks owner-only download access to a password-protected share made by a write-only key', async () => {
		const dir = freshDataDir('scope-writer-download');
		try {
			const proc = await bootServer(dir, 3641);
			try {
				const base = 'http://127.0.0.1:3641';
				const cookie = await adminCookie(base);

				// allow_password stays at its default (true); only the read scope is
				// stripped, so this isolates read-degradation from the unrelated
				// allow_password scope.
				const writer = await makeScopedKey(base, cookie, 'writer-only-pw', { create: true, write: true, read: false, delete: false });
				const auth = { Authorization: `Bearer ${writer.token}` };

				const createRes = await fetch(`${base}/api/v1/shares`, {
					method: 'POST',
					headers: { ...auth, 'Content-Type': 'application/json' },
					body: JSON.stringify({ password: 'letmein123' }),
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
				await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: new Uint8Array([1, 2, 3]),
				});
				await fetch(`${base}/api/shares/${id}/finalize`, { method: 'POST', headers: { 'X-Edit-Token': editToken } });

				// Without the read scope, the edit token no longer counts as owner for
				// download.js's accessCheck - so it falls through to the ordinary
				// password gate and is refused, exactly like a stranger with no password.
				const dlRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, { headers: { 'X-Edit-Token': editToken } });
				expect(dlRes.status).toBe(403);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a list/read-only key is allowed list/read and denied create/write/delete, scope-checked before the resource is even resolved', async () => {
		const dir = freshDataDir('scope-reader');
		try {
			const proc = await bootServer(dir, 3642);
			try {
				const base = 'http://127.0.0.1:3642';
				const cookie = await adminCookie(base);

				const reader = await makeScopedKey(base, cookie, 'read-only', { create: false, write: false, read: true, delete: false });
				const auth = { Authorization: `Bearer ${reader.token}` };

				// Inside scope: list (starts empty) and /me.
				const listRes = await fetch(`${base}/api/v1/shares`, { headers: auth });
				expect(listRes.status).toBe(200);
				const listBody = await listRes.json();
				expect(listBody.shares).toEqual([]);

				const meRes = await fetch(`${base}/api/v1/me`, { headers: auth });
				expect(meRes.status).toBe(200);

				// Outside scope: create/upload.
				const createRes = await fetch(`${base}/api/v1/shares`, {
					method: 'POST',
					headers: { ...auth, 'Content-Type': 'application/json' },
					body: JSON.stringify({}),
				});
				expect(createRes.status).toBe(403);

				const oneShotRes = await fetch(`${base}/api/v1/upload?filename=x.bin`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'x.bin' },
					body: new Uint8Array([1]),
				});
				expect(oneShotRes.status).toBe(403);

				// Outside scope: delete, checked before the (nonexistent) share is
				// even looked up - a made-up id still gets 403 (scope), never 404.
				const delRes = await fetch(`${base}/api/v1/shares/this-id-does-not-exist`, { method: 'DELETE', headers: auth });
				expect(delRes.status).toBe(403);

				// GET on a nonexistent share is inside scope (read) but the resource
				// still 404s - proving the scope check and the existence check are
				// independent, not conflated.
				const getRes = await fetch(`${base}/api/v1/shares/this-id-does-not-exist`, { headers: auth });
				expect(getRes.status).toBe(404);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a key with all four scopes granted (the admin UI default) behaves exactly like before scopes existed', async () => {
		const dir = freshDataDir('scope-full');
		try {
			const proc = await bootServer(dir, 3643);
			try {
				const base = 'http://127.0.0.1:3643';
				const cookie = await adminCookie(base);

				// Omitting `scopes` entirely (the shape every pre-this-batch admin
				// request used) must still default to full access.
				const res = await fetch(`${base}/api/admin/api-keys`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
					body: JSON.stringify({ name: 'default-full' }),
				});
				expect(res.status).toBe(201);
				const key = await res.json();
				const auth = { Authorization: `Bearer ${key.token}` };

				const createRes = await fetch(`${base}/api/v1/shares`, {
					method: 'POST',
					headers: { ...auth, 'Content-Type': 'application/json' },
					body: JSON.stringify({}),
				});
				expect(createRes.status).toBe(201);
				const { id, editToken } = await createRes.json();

				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'f.bin', size: 1, mime: 'application/octet-stream' }),
				});
				expect(regRes.status).toBe(200);

				const listRes = await fetch(`${base}/api/v1/shares`, { headers: auth });
				expect(listRes.status).toBe(200);

				const getRes = await fetch(`${base}/api/v1/shares/${id}`, { headers: auth });
				expect(getRes.status).toBe(200);

				const delRes = await fetch(`${base}/api/v1/shares/${id}`, { method: 'DELETE', headers: auth });
				expect(delRes.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	describe('API key rotation (2026-07 audit F-1)', () => {
		test('rotating a key cuts off every pre-rotation credential (bearer, portal session, edit token, owner cookie) while the new secret keeps full carry-over access', async () => {
			const dir = freshDataDir('rotate-carryover');
			try {
				const proc = await bootServer(dir, 3644);
				try {
					const base = 'http://127.0.0.1:3644';
					const adminC = await adminCookie(base);

					const key = await makeScopedKey(base, adminC, 'rotate-me', { create: true, write: true, read: true, delete: true });
					const oldToken = key.token;
					const oldAuth = { Authorization: `Bearer ${oldToken}` };

					// Share A, created and fully finalized with a small file BEFORE rotation.
					const createRes = await fetch(`${base}/api/v1/shares`, {
						method: 'POST',
						headers: { ...oldAuth, 'Content-Type': 'application/json' },
						body: JSON.stringify({}),
					});
					expect(createRes.status).toBe(201);
					const { id: shareA, editToken: aEdit } = await createRes.json();

					const regRes = await fetch(`${base}/api/shares/${shareA}/files`, {
						method: 'POST',
						headers: { 'X-Edit-Token': aEdit, 'Content-Type': 'application/json' },
						body: JSON.stringify({ name: 'a.bin', size: 4, mime: 'application/octet-stream' }),
					});
					expect(regRes.status).toBe(200);
					const { fileId: aFileId } = await regRes.json();
					const patchRes = await fetch(`${base}/api/shares/${shareA}/files/${aFileId}?offset=0`, {
						method: 'PATCH',
						headers: { 'X-Edit-Token': aEdit, 'Content-Type': 'application/octet-stream' },
						body: new Uint8Array([1, 2, 3, 4]),
					});
					expect(patchRes.status).toBe(200);
					const finalizeRes = await fetch(`${base}/api/shares/${shareA}/finalize`, { method: 'POST', headers: { 'X-Edit-Token': aEdit } });
					expect(finalizeRes.status).toBe(200);

					// Exchange the edit token for a per-share owner cookie (M-05).
					const ownerSessionRes = await fetch(`${base}/api/shares/${shareA}/owner-session`, {
						method: 'POST',
						headers: { 'X-Edit-Token': aEdit, Origin: base },
					});
					expect(ownerSessionRes.status).toBe(200);
					const ownerCookie = ownerSessionRes.headers.get('set-cookie').split(';')[0];

					// Log in to the key's browser portal.
					const loginRes = await fetch(`${base}/api/v1/login`, {
						method: 'POST',
						headers: { 'Content-Type': 'application/json', Origin: base },
						body: JSON.stringify({ name: key.name, token: oldToken }),
					});
					expect(loginRes.status).toBe(200);
					const portalCookie = loginRes.headers.get('set-cookie').split(';')[0];

					// Sanity: the portal session is genuinely live pre-rotation.
					const preSessionRes = await fetch(`${base}/api/v1/session`, { headers: { Cookie: portalCookie } });
					expect((await preSessionRes.json()).session?.id).toBe(key.id);

					// Rotate.
					const rotateRes = await fetch(`${base}/api/admin/api-keys/${key.id}/rotate`, {
						method: 'POST',
						headers: { Cookie: adminC, Origin: base },
					});
					expect(rotateRes.status).toBe(200);
					const { token: newToken } = await rotateRes.json();
					const newAuth = { Authorization: `Bearer ${newToken}` };

					// ---- PREVIOUS LOSES ACCESS ----------------------------------------

					// Old bearer token: dead immediately (already true pre-fix; verified here).
					const oldBearerRes = await fetch(`${base}/api/v1/shares`, { headers: oldAuth });
					expect(oldBearerRes.status).toBe(401);

					// Old portal session cookie: dead immediately (already true pre-fix; verified here).
					const postSessionRes = await fetch(`${base}/api/v1/session`, { headers: { Cookie: portalCookie } });
					expect((await postSessionRes.json()).session).toBeNull();

					// Old edit token: the header ownership path now dies too (F-1 fix).
					const oldEditPatchRes = await fetch(`${base}/api/shares/${shareA}`, {
						method: 'PATCH',
						headers: { 'X-Edit-Token': aEdit, 'Content-Type': 'application/json' },
						body: JSON.stringify({ expiresIn: 0 }),
					});
					expect(oldEditPatchRes.status).toBe(403);

					// Old owner cookie: the cookie ownership path now dies too (F-1 fix).
					const oldCookieFinalizeRes = await fetch(`${base}/api/shares/${shareA}/finalize`, {
						method: 'POST',
						headers: { Cookie: ownerCookie, Origin: base },
					});
					expect(oldCookieFinalizeRes.status).toBe(403);

					// ---- CARRY-OVER (new secret, same key id) --------------------------

					const listRes = await fetch(`${base}/api/v1/shares`, { headers: newAuth });
					expect(listRes.status).toBe(200);
					expect((await listRes.json()).shares.map(s => s.id)).toContain(shareA);

					const getRes = await fetch(`${base}/api/v1/shares/${shareA}`, { headers: newAuth });
					expect(getRes.status).toBe(200);

					const dlRes = await fetch(`${base}/api/shares/${shareA}/files/${aFileId}/download`, { headers: newAuth });
					expect(dlRes.status).toBe(200);

					// A share created AFTER rotation gets a version-current edit token,
					// which must keep working normally end to end (write/finalize/edit).
					const createBRes = await fetch(`${base}/api/v1/shares`, {
						method: 'POST',
						headers: { ...newAuth, 'Content-Type': 'application/json' },
						body: JSON.stringify({}),
					});
					expect(createBRes.status).toBe(201);
					const { id: shareB, editToken: bEdit } = await createBRes.json();

					const regBRes = await fetch(`${base}/api/shares/${shareB}/files`, {
						method: 'POST',
						headers: { 'X-Edit-Token': bEdit, 'Content-Type': 'application/json' },
						body: JSON.stringify({ name: 'b.bin', size: 2, mime: 'application/octet-stream' }),
					});
					expect(regBRes.status).toBe(200);
					const { fileId: bFileId } = await regBRes.json();
					const patchBRes = await fetch(`${base}/api/shares/${shareB}/files/${bFileId}?offset=0`, {
						method: 'PATCH',
						headers: { 'X-Edit-Token': bEdit, 'Content-Type': 'application/octet-stream' },
						body: new Uint8Array([9, 9]),
					});
					expect(patchBRes.status).toBe(200);
					const finalizeBRes = await fetch(`${base}/api/shares/${shareB}/finalize`, { method: 'POST', headers: { 'X-Edit-Token': bEdit } });
					expect(finalizeBRes.status).toBe(200);
					const editBRes = await fetch(`${base}/api/shares/${shareB}`, {
						method: 'PATCH',
						headers: { 'X-Edit-Token': bEdit, 'Content-Type': 'application/json' },
						body: JSON.stringify({ expiresIn: 0 }),
					});
					expect(editBRes.status).toBe(200);

					// Delete of the pre-rotation share via the new secret's bearer token.
					const delRes = await fetch(`${base}/api/v1/shares/${shareA}`, { method: 'DELETE', headers: newAuth });
					expect(delRes.status).toBe(200);
				} finally {
					await stopServer(proc);
				}
			} finally {
				cleanupDir(dir);
			}
		});
	});
});
