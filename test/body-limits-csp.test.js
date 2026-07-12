// Regression tests for two findings from the third red-team audit pass (L-03,
// L-04):
//
// L-03: the server's JSON body ceiling (maxRequestBodySize in server.js) is
//       sized for upload chunks (>=64 MiB) and was applied globally - login/
//       MFA/password and share/admin metadata endpoints parsed whatever body
//       a client sent, up to that whole-server limit, before any semantic
//       validation ran. lib/http.js's readJson() now rejects a body over a
//       route-appropriate cap (LOGIN_BODY_MAX / METADATA_BODY_MAX) with 413,
//       both from a declared Content-Length and from the actual bytes read.
//
// L-04: the page CSP allowed `object-src 'self' blob:` even though the app
//       never renders an <object>/<embed> anywhere - needless attack surface
//       for a MIME-confused or parser-exploited upload framed on our own
//       origin. object-src is now 'none'; frame-src keeps 'self' blob:
//       (genuinely load-bearing for PDF preview - see public/js/view.js).
//
// Boots the real server as a child process (mirrors security-fixes.test.js /
// security-headers.test.js) since these are HTTP-surface behaviors.

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
			ADMIN_PASSWORD: 'BodyLimitsCspTest-Pw-2026',
			SECRET: `body-limits-csp-secret-${port}`,
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

describe('L-03: route-specific JSON body limits', () => {
	test('a login-class body (share unlock) over LOGIN_BODY_MAX is rejected 413 via Content-Length, before touching the password', async () => {
		const dir = freshDataDir('l03-unlock-cl');
		try {
			const proc = await bootServer(dir, 3830);
			try {
				const base = 'http://127.0.0.1:3830';
				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false }),
				});
				expect(createRes.status).toBe(201);
				const { id } = await createRes.json();

				const oversized = JSON.stringify({ password: 'x'.repeat(20 * 1024) });
				const res = await fetch(`${base}/api/shares/${id}/unlock`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: oversized,
				});
				expect(res.status).toBe(413);
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a login-class body (admin login) over LOGIN_BODY_MAX is rejected 413 even without a Content-Length (actual-bytes cap)', async () => {
		const dir = freshDataDir('l03-admin-login-chunked');
		try {
			const proc = await bootServer(dir, 3831);
			try {
				const base = 'http://127.0.0.1:3831';
				const oversized = JSON.stringify({ password: 'x'.repeat(20 * 1024) });
				// A ReadableStream body makes fetch/Bun send the request without a
				// Content-Length header, so this exercises the actual-bytes-read cap
				// rather than the declared-Content-Length precheck.
				const stream = new ReadableStream({
					start(controller) {
						controller.enqueue(new TextEncoder().encode(oversized));
						controller.close();
					},
				});
				const res = await fetch(`${base}/api/admin/login`, {
					method: 'POST',
					// Origin: base simulates a legitimate same-origin browser request -
					// login is CSRF-checked (L-01: absent Origin/Sec-Fetch-Site fails
					// closed), so this must be present to reach the body-size check.
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: stream,
					duplex: 'half',
				});
				expect(res.status).toBe(413);
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a metadata-class body (share create) over METADATA_BODY_MAX is rejected 413', async () => {
		const dir = freshDataDir('l03-share-create');
		try {
			const proc = await bootServer(dir, 3832);
			try {
				const base = 'http://127.0.0.1:3832';
				const oversized = JSON.stringify({ title: 'x'.repeat(100 * 1024) });
				const res = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: oversized,
				});
				expect(res.status).toBe(413);
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('an ordinary small body on every capped route still succeeds normally', async () => {
		const dir = freshDataDir('l03-normal');
		try {
			const proc = await bootServer(dir, 3833);
			try {
				const base = 'http://127.0.0.1:3833';

				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false, title: 'normal share' }),
				});
				expect(createRes.status).toBe(201);
				const { id } = await createRes.json();

				const unlockRes = await fetch(`${base}/api/shares/${id}/unlock`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password: 'irrelevant, share has none' }),
				});
				// Not password-protected: unlock still runs (and legitimately 403s
				// against verifyPassword's null hash) rather than being rejected for
				// its size - proves the cap did not swallow a normal-sized request.
				expect(unlockRes.status).toBe(403);

				const loginRes = await fetch(`${base}/api/admin/login`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ password: 'wrong-password' }),
				});
				expect(loginRes.status).toBe(403);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('L-04: page CSP tightening', () => {
	test('the view page CSP sets object-src none and keeps frame-src self blob: for PDF preview', async () => {
		const dir = freshDataDir('l04-csp');
		try {
			const proc = await bootServer(dir, 3834);
			try {
				const base = 'http://127.0.0.1:3834';
				const res = await fetch(`${base}/s/nonexistent-share-id`);
				expect(res.status).toBe(200);
				const csp = res.headers.get('content-security-policy');
				expect(csp).toContain("object-src 'none'");
				expect(csp).not.toContain("object-src 'self'");
				expect(csp).toContain("frame-src 'self' blob:");
				await res.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
