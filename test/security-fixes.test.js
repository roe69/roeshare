// Regression tests for six findings from the second red-team audit pass:
//
// F-01: preview bypassed maxDownloads (only one_time was blocked for
//       non-owners) - a capped share was fully retrievable inline with the
//       counter never incremented.
// F-02: the whole-share zip route enforced maxDownloads with a plain
//       check-then-act read instead of the atomic claimDownload/
//       releaseDownload the single-file path already used - a race that let
//       N concurrent zip requests all succeed against a maxDownloads=1 share.
// F-11: preview responses were cached for a year even for password/one-time/
//       capped shares.
// F-15: a malformed percent-encoded cookie value threw uncaught out of
//       parseCookies, producing a generic 500 for the whole request.
// F-16: the unauthorized-metadata response for a protected share leaked the
//       share's title before the visitor proved they knew the password.
// F-17: verifyToken silently ignored extra "." segments beyond the first two,
//       instead of rejecting a token that does not have exactly two.
//
// Boots the real server as a child process (mirrors download.test.js /
// migrations.test.js) since these are HTTP-surface behaviors.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');

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
			ADMIN_PASSWORD: 'SecFixesTest-Pw-2026',
			SECRET: `sec-fixes-secret-${port}`,
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

// Creates a finalized, non-E2E share with a single small file uploaded in
// one chunk, mirroring download.test.js's helper.
async function makeShare(base, body) {
	const createRes = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ e2e: false, ...body }),
	});
	expect(createRes.status).toBe(201);
	const { id, editToken } = await createRes.json();

	const bytes = new Uint8Array(20);
	for (let i = 0; i < bytes.length; i++) bytes[i] = 65 + i; // 'A'..'T'

	const regRes = await fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
		body: JSON.stringify({ name: 'test.bin', size: bytes.length, mime: 'application/octet-stream' }),
	});
	expect(regRes.status).toBe(200);
	const { fileId } = await regRes.json();

	const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
		method: 'PATCH',
		headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
		body: bytes,
	});
	expect(chunkRes.status).toBe(200);

	const finRes = await fetch(`${base}/api/shares/${id}/finalize`, {
		method: 'POST',
		headers: { 'X-Edit-Token': editToken },
	});
	expect(finRes.status).toBe(200);

	return { id, editToken, fileId, bytes };
}

describe('F-01: preview no longer bypasses maxDownloads', () => {
	test('a non-owner cannot preview a maxDownloads-capped share, and the cap is never consumed', async () => {
		const dir = freshDataDir('f01-preview');
		try {
			const proc = await bootServer(dir, 3610);
			try {
				const base = 'http://127.0.0.1:3610';
				const { id, editToken, fileId } = await makeShare(base, { maxDownloads: 1 });

				const previewRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`);
				expect(previewRes.status).toBe(403);

				// The cap must not have been touched by the blocked preview attempt.
				const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				const meta = await metaRes.json();
				expect(meta.downloadCount).toBe(0);

				// The owner can still preview their own capped share.
				const ownerPreview = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`, {
					headers: { 'X-Edit-Token': editToken },
				});
				expect(ownerPreview.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('F-02: zip download atomically enforces maxDownloads', () => {
	test('N parallel zip requests against a maxDownloads=1 share: exactly one succeeds', async () => {
		const dir = freshDataDir('f02-zip');
		try {
			const proc = await bootServer(dir, 3611);
			try {
				const base = 'http://127.0.0.1:3611';
				const { id, editToken } = await makeShare(base, { maxDownloads: 1 });

				const N = 8;
				const results = await Promise.all(
					Array.from({ length: N }, () => fetch(`${base}/api/shares/${id}/download-all`))
				);
				// Drain every body so each response is fully accounted for.
				await Promise.all(results.map(r => r.arrayBuffer()));

				const oks = results.filter(r => r.status === 200).length;
				const gones = results.filter(r => r.status === 410).length;
				expect(oks).toBe(1);
				expect(gones).toBe(N - 1);

				const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				const meta = await metaRes.json();
				expect(meta.downloadCount).toBe(1);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('F-11: preview caching reflects protection state', () => {
	test('an uncontrolled public share still gets a long immutable cache', async () => {
		const dir = freshDataDir('f11-public');
		try {
			const proc = await bootServer(dir, 3612);
			try {
				const base = 'http://127.0.0.1:3612';
				const { id, fileId } = await makeShare(base, {});

				const res = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`);
				expect(res.status).toBe(200);
				expect(res.headers.get('cache-control')).toBe('private, max-age=31536000, immutable');
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a password-protected share is never cached, even once unlocked', async () => {
		const dir = freshDataDir('f11-password');
		try {
			const proc = await bootServer(dir, 3613);
			try {
				const base = 'http://127.0.0.1:3613';
				const { id, fileId } = await makeShare(base, { password: 'correct-horse-battery' });

				const unlockRes = await fetch(`${base}/api/shares/${id}/unlock`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password: 'correct-horse-battery' }),
				});
				expect(unlockRes.status).toBe(200);
				const { accessToken } = await unlockRes.json();

				const res = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`, {
					headers: { Authorization: `Bearer ${accessToken}` },
				});
				expect(res.status).toBe(200);
				expect(res.headers.get('cache-control')).toBe('no-store');
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('F-15: a malformed cookie no longer crashes the request', () => {
	test('a request with an unparseable percent-encoded cookie still gets a normal response', async () => {
		const dir = freshDataDir('f15-cookie');
		try {
			const proc = await bootServer(dir, 3614);
			try {
				const base = 'http://127.0.0.1:3614';
				const res = await fetch(`${base}/api/config`, {
					headers: { Cookie: 'foo=%ZZ' },
				});
				expect(res.status).toBe(200);
				const body = await res.json();
				expect(body.chunkSize).toBeDefined();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('F-16: protected-share metadata no longer leaks the title pre-unlock', () => {
	test('the 401 response for a locked share omits title', async () => {
		const dir = freshDataDir('f16-title');
		try {
			const proc = await bootServer(dir, 3615);
			try {
				const base = 'http://127.0.0.1:3615';
				const secretTitle = 'prod-db-backup-customer-acme';
				const { id } = await makeShare(base, { password: 'hunter2hunter2', title: secretTitle });

				const res = await fetch(`${base}/api/shares/${id}`);
				expect(res.status).toBe(401);
				const body = await res.json();
				expect(body).toEqual({ protected: true });
				expect(JSON.stringify(body)).not.toContain(secretTitle);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('F-17: HMAC token verification rejects extra segments', () => {
	test('appending an extra "." segment to a valid access token invalidates it', async () => {
		const dir = freshDataDir('f17-token');
		try {
			const proc = await bootServer(dir, 3616);
			try {
				const base = 'http://127.0.0.1:3616';
				const { id, fileId } = await makeShare(base, { password: 'token-splice-test' });

				const unlockRes = await fetch(`${base}/api/shares/${id}/unlock`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password: 'token-splice-test' }),
				});
				expect(unlockRes.status).toBe(200);
				const { accessToken } = await unlockRes.json();

				// The unmodified token works.
				const good = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`, {
					headers: { Authorization: `Bearer ${accessToken}` },
				});
				expect(good.status).toBe(200);
				await good.arrayBuffer();

				// A token with a trailing bogus third segment must be rejected outright,
				// not silently parsed as if the extra segment were not there.
				const spliced = `${accessToken}.xyz`;
				const bad = await fetch(`${base}/api/shares/${id}/files/${fileId}/preview`, {
					headers: { Authorization: `Bearer ${spliced}` },
				});
				expect(bad.status).toBe(403);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
