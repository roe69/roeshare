// F-07: the one-shot upload endpoint (POST /api/v1/upload) accepted a share
// password as a URL query param (?password=), which ends up in proxy access
// logs, browser history, and Referer headers - all things a password should
// never appear in. Fixed by accepting the password via a dedicated
// `X-Upload-Password` request header instead. F-07 originally kept `?password=`
// as a deprecated back-compat fallback for one release; M-01 removes that
// fallback outright - a request that still sends `?password=` is now rejected
// with 400 rather than silently proceeding without a password, so a stale
// client fails loud instead of quietly publishing an unprotected share.
//
// Exercises the real server end to end:
//   - a one-shot upload with X-Upload-Password succeeds and the resulting
//     share is actually password-protected (unauthenticated metadata fetch is
//     gated with { protected: true }, and the correct password unlocks it)
//   - a lone ?password= query param is rejected with 400 (M-01)
//   - ?password= is rejected with 400 even when a valid X-Upload-Password
//     header is also sent (M-01: never silently ignored)

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'UploadPwHeaderTest-Pw-2026';

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
			SECRET: `upload-pw-header-secret-${port}`,
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

// Full-scope API key, same shape the admin UI creates by default.
async function makeKey(base, cookie, name) {
	const res = await fetch(`${base}/api/admin/api-keys`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
		body: JSON.stringify({ name }),
	});
	expect(res.status).toBe(201);
	return res.json();
}

describe('one-shot upload password (F-07)', () => {
	test('X-Upload-Password header protects the created share; unauthenticated metadata fetch is gated, correct password unlocks it', async () => {
		const dir = freshDataDir('upload-pw-header');
		try {
			const proc = await bootServer(dir, 3730);
			try {
				const base = 'http://127.0.0.1:3730';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'header-pw-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const res = await fetch(`${base}/api/v1/upload?title=Header%20Protected`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'secret.txt', 'X-Upload-Password': 'header-secret-123' },
					body: new Uint8Array([1, 2, 3, 4]),
				});
				expect(res.status).toBe(201);
				const made = await res.json();
				expect(made.id).toBeTruthy();

				// No password supplied: gated.
				const gatedRes = await fetch(`${base}/api/shares/${made.id}`);
				expect(gatedRes.status).toBe(401);
				const gatedBody = await gatedRes.json();
				expect(gatedBody.protected).toBe(true);

				// Wrong password: rejected.
				const wrongRes = await fetch(`${base}/api/shares/${made.id}/unlock`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password: 'not-it' }),
				});
				expect(wrongRes.status).toBe(403);

				// Correct password: unlocks.
				const unlockRes = await fetch(`${base}/api/shares/${made.id}/unlock`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password: 'header-secret-123' }),
				});
				expect(unlockRes.status).toBe(200);
				const unlockBody = await unlockRes.json();
				expect(unlockBody.accessToken).toBeTruthy();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('?password= alone is rejected with 400 (M-01: no more silent back-compat fallback)', async () => {
		const dir = freshDataDir('upload-pw-query');
		try {
			const proc = await bootServer(dir, 3731);
			try {
				const base = 'http://127.0.0.1:3731';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'query-pw-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const res = await fetch(`${base}/api/v1/upload?title=Query%20Protected&password=${encodeURIComponent('query-secret-456')}`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'secret.txt' },
					body: new Uint8Array([5, 6, 7, 8]),
				});
				expect(res.status).toBe(400);
				const body = await res.json();
				expect(body.error).toMatch(/X-Upload-Password/);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('?password= is rejected with 400 even alongside a valid X-Upload-Password header', async () => {
		const dir = freshDataDir('upload-pw-precedence');
		try {
			const proc = await bootServer(dir, 3732);
			try {
				const base = 'http://127.0.0.1:3732';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'precedence-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const res = await fetch(`${base}/api/v1/upload?title=Precedence&password=query-value`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'secret.txt', 'X-Upload-Password': 'header-value' },
					body: new Uint8Array([9, 9]),
				});
				expect(res.status).toBe(400);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
