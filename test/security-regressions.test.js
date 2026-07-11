// Regression tests for two narrow gaps found in the third red-team pass:
//
// 1. GET /api/shares/:id/files/:fileId/status (uploads.js) authenticated via
//    the edit token only and never checked whether the share's backing API
//    key had been revoked/expired - unlike every sibling owner-gated route
//    (register, chunk PATCH, finalize, delete, and every download.js read),
//    which all fold in checkKeyValid()/keyValidForShare(). A revoked key's
//    edit token kept returning upload-progress status forever.
//
// 2. PATCH /api/admin/shares/:id (admin.js, slug rename) checked the new slug
//    for a collision with a case-SENSITIVE `WHERE id = ?`, unlike the public
//    create path's case-insensitive check - so it could create two live
//    shares whose ids differ only by case, which collide on a case-insensitive
//    filesystem once renameShareDir() runs.
//
// Boots the real server as a child process (mirrors migrations.test.js /
// download.test.js) since both are HTTP-surface behaviors.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'SecRegressionTest-Pw-2026';

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
			SECRET: `sec-regression-secret-${port}`,
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
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	expect(res.status).toBe(200);
	const setCookie = res.headers.get('set-cookie');
	return setCookie.split(';')[0];
}

describe('API key revocation reaches the upload-status endpoint', () => {
	test('a revoked key\'s edit token loses access to GET .../status, matching every other owner-gated route', async () => {
		const dir = freshDataDir('status-revoke');
		try {
			const proc = await bootServer(dir, 3598);
			try {
				const base = 'http://127.0.0.1:3598';
				const cookie = await adminCookie(base);

				const keyRes = await fetch(`${base}/api/admin/api-keys`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Cookie: cookie },
					body: JSON.stringify({ name: 'status-revoke-test-key' }),
				});
				expect(keyRes.status).toBe(201);
				const key = await keyRes.json();

				const shareRes = await fetch(`${base}/api/v1/shares`, {
					method: 'POST',
					headers: { Authorization: `Bearer ${key.token}`, 'Content-Type': 'application/json' },
					body: JSON.stringify({}),
				});
				expect(shareRes.status).toBe(201);
				const { id, editToken } = await shareRes.json();

				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'f.bin', size: 10, mime: 'application/octet-stream' }),
				});
				expect(regRes.status).toBe(200);
				const { fileId } = await regRes.json();

				// Before revocation, the status endpoint works normally.
				const before = await fetch(`${base}/api/shares/${id}/files/${fileId}/status`, {
					headers: { 'X-Edit-Token': editToken },
				});
				expect(before.status).toBe(200);
				const beforeBody = await before.json();
				expect(beforeBody).toEqual({ received: 0, size: 10, complete: false });

				const revokeRes = await fetch(`${base}/api/admin/api-keys/${key.id}/revoke`, {
					method: 'POST',
					headers: { Cookie: cookie },
				});
				expect(revokeRes.status).toBe(200);

				// After revocation, the SAME edit token must now be rejected here too -
				// this is exactly the gap the fix closed (it already worked correctly
				// for register/finalize/delete/download before this fix).
				const after = await fetch(`${base}/api/shares/${id}/files/${fileId}/status`, {
					headers: { 'X-Edit-Token': editToken },
				});
				expect(after.status).toBe(403);

				// And register (a sibling route that already had the check) must
				// still behave the same way, as a sanity cross-check.
				const regAfter = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'g.bin', size: 1, mime: 'application/octet-stream' }),
				});
				expect(regAfter.status).toBe(403);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('admin slug rename enforces case-insensitive uniqueness', () => {
	test('renaming to a slug that case-insensitively collides with a different live share is refused', async () => {
		const dir = freshDataDir('rename-collide');
		try {
			const proc = await bootServer(dir, 3599);
			try {
				const base = 'http://127.0.0.1:3599';
				const cookie = await adminCookie(base);

				const shareA = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false, slug: 'tenant-a-live' }),
				}).then(r => r.json());

				await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false, slug: 'mydocs' }),
				});

				// Renaming share A to a slug that differs from "mydocs" only by case
				// must be refused - not silently create a colliding directory.
				const renameRes = await fetch(`${base}/api/admin/shares/${shareA.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', Cookie: cookie },
					body: JSON.stringify({ slug: 'MyDocs' }),
				});
				expect(renameRes.status).toBe(409);

				// The original share must be completely unaffected (no partial rename).
				const stillThere = await fetch(`${base}/api/shares/tenant-a-live`);
				expect(stillThere.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a case-only rename of a share to its own slug (different case) still succeeds', async () => {
		const dir = freshDataDir('rename-self');
		try {
			const proc = await bootServer(dir, 3600);
			try {
				const base = 'http://127.0.0.1:3600';
				const cookie = await adminCookie(base);

				const share = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false, slug: 'selfrename' }),
				}).then(r => r.json());

				// The "own row" exclusion (id != ?) must not falsely block a
				// case-only rename of a share to a slug that only collides with
				// itself.
				const renameRes = await fetch(`${base}/api/admin/shares/${share.id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', Cookie: cookie },
					body: JSON.stringify({ slug: 'SelfRename' }),
				});
				expect(renameRes.status).toBe(200);

				const renamed = await fetch(`${base}/api/shares/SelfRename`);
				expect(renamed.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
