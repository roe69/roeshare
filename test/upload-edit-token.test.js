// D1: POST /api/v1/upload's 201 body gains two additive fields alongside the
// existing { id, url, fileId, name, size } - editToken (the plaintext owner
// secret; createShare only ever persists its hash) and expiresAt (the
// resolved epoch-seconds expiry, or null for never). Neither changes the
// shape of any existing field, so an old client that only reads `url` sees
// no difference. Exercises the real server end to end:
//   - expiresIn=0 -> expiresAt is null, and the returned editToken actually
//     authenticates as owner via X-Edit-Token against GET /api/shares/:id
//   - expiresIn omitted -> expiresAt is close to now + config.defaultExpiry (7d)
//   - a positive expiresIn -> expiresAt is close to now + that many seconds

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'UploadEditTokenTest-Pw-2026';

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
			SECRET: `upload-edit-token-secret-${port}`,
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
	const setCookie = res.headers.get('set-cookie');
	return setCookie.split(';')[0];
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

describe('one-shot upload response gains editToken/expiresAt (D1)', () => {
	test('expiresIn=0 -> expiresAt null; the returned editToken authenticates as owner', async () => {
		const dir = freshDataDir('upload-edit-token-never');
		try {
			const proc = await bootServer(dir, 3740);
			try {
				const base = 'http://127.0.0.1:3740';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'edit-token-key-never');
				const auth = { Authorization: `Bearer ${key.token}` };

				const res = await fetch(`${base}/api/v1/upload?expiresIn=0`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'never.txt' },
					body: new Uint8Array([1, 2, 3]),
				});
				expect(res.status).toBe(201);
				const made = await res.json();
				expect(made.id).toBeTruthy();
				expect(made.editToken).toBeTruthy();
				expect(typeof made.editToken).toBe('string');
				expect(made.expiresAt).toBeNull();

				// The edit token actually works as an owner credential.
				const metaRes = await fetch(`${base}/api/shares/${made.id}`, {
					headers: { 'X-Edit-Token': made.editToken },
				});
				expect(metaRes.status).toBe(200);
				const meta = await metaRes.json();
				expect(meta.owner).toBe(true);
				expect(meta.expiresAt).toBeNull();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('expiresIn omitted -> expiresAt close to now + defaultExpiry (7d)', async () => {
		const dir = freshDataDir('upload-edit-token-default');
		try {
			const proc = await bootServer(dir, 3741);
			try {
				const base = 'http://127.0.0.1:3741';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'edit-token-key-default');
				const auth = { Authorization: `Bearer ${key.token}` };

				const before = Math.floor(Date.now() / 1000);
				const res = await fetch(`${base}/api/v1/upload`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'default.txt' },
					body: new Uint8Array([4, 5, 6]),
				});
				expect(res.status).toBe(201);
				const made = await res.json();
				expect(made.expiresAt).toBeTruthy();
				const sevenDays = 7 * 24 * 3600;
				expect(made.expiresAt).toBeGreaterThanOrEqual(before + sevenDays - 5);
				expect(made.expiresAt).toBeLessThanOrEqual(before + sevenDays + 30);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a positive expiresIn -> expiresAt close to now + that many seconds', async () => {
		const dir = freshDataDir('upload-edit-token-positive');
		try {
			const proc = await bootServer(dir, 3742);
			try {
				const base = 'http://127.0.0.1:3742';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'edit-token-key-positive');
				const auth = { Authorization: `Bearer ${key.token}` };

				const before = Math.floor(Date.now() / 1000);
				const res = await fetch(`${base}/api/v1/upload?expiresIn=3600`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'hour.txt' },
					body: new Uint8Array([7, 8, 9]),
				});
				expect(res.status).toBe(201);
				const made = await res.json();
				expect(made.expiresAt).toBeGreaterThanOrEqual(before + 3600 - 5);
				expect(made.expiresAt).toBeLessThanOrEqual(before + 3600 + 30);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
