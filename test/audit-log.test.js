// Section 10 of the security audit: structured security-event audit logging
// (src/lib/audit.js writes to the new audit_events table; GET /api/admin/audit
// is the operator-facing read surface). Triggers a handful of real
// instrumented events - a failed admin login, an API key revoke, and a CSRF
// rejection - through the real HTTP surface, then confirms each produces
// exactly one correctly-shaped row and that no secret material (the admin
// password, the API key's token/secret, a cookie value) ever appears in any
// audit field.
//
// Boots the real server as a child process (mirrors csrf.test.js / mfa.test.js).

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'AuditLogTest-Pw-2026';

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
			SECRET: `audit-log-secret-${port}`,
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

describe('audit log', () => {
	test('a failed admin login, an API key revoke, and a CSRF rejection each produce exactly one correctly-shaped, secret-free row', async () => {
		const dir = freshDataDir('audit-log');
		const port = 3940;
		try {
			const proc = await bootServer(dir, port);
			try {
				const base = `http://127.0.0.1:${port}`;

				// 1. A failed admin login (wrong password) -> admin.login.failure.
				// Origin: base so this reaches the password check (L-01 CSRF gate runs
				// first) instead of being rejected as a CSRF failure itself.
				const badLogin = await fetch(`${base}/api/admin/login`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ password: 'definitely-wrong' }),
				});
				expect(badLogin.status).toBe(403);

				// A real admin session, to drive the rest of the scenario.
				const cookie = await adminCookie(base);

				// 2. Create then revoke an API key -> apikey.created, apikey.revoked.
				const createRes = await fetch(`${base}/api/admin/api-keys`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
					body: JSON.stringify({ name: 'audit-log-test-key' }),
				});
				expect(createRes.status).toBe(201);
				const key = await createRes.json();
				expect(key.token).toBeTruthy();

				const revokeRes = await fetch(`${base}/api/admin/api-keys/${key.id}/revoke`, {
					method: 'POST',
					headers: { Cookie: cookie, Origin: base },
				});
				expect(revokeRes.status).toBe(200);

				// 3. A cross-site mutation attempt -> csrf.rejected. A same-site
				// cookie-authenticated POST carrying a cross-site Sec-Fetch-Site is
				// exactly the forged-request shape requireSameOrigin() exists to catch.
				const csrfRes = await fetch(`${base}/api/admin/logout`, {
					method: 'POST',
					headers: { Cookie: cookie, 'Sec-Fetch-Site': 'cross-site' },
				});
				expect(csrfRes.status).toBe(403);

				// Read the log back through the real admin-only endpoint.
				const auditRes = await fetch(`${base}/api/admin/audit?limit=500`, { headers: { Cookie: cookie } });
				expect(auditRes.status).toBe(200);
				const { events, total } = await auditRes.json();
				expect(total).toBe(events.length);

				const byEvent = name => events.filter(e => e.event === name);

				const loginFailures = byEvent('admin.login.failure');
				expect(loginFailures.length).toBe(1);
				expect(loginFailures[0].ip).toBe('127.0.0.1');
				expect(loginFailures[0].actor).toBeNull();

				const created = byEvent('apikey.created');
				expect(created.length).toBe(1);
				expect(created[0].target).toBe(key.id);
				expect(created[0].actor).toBe('admin');

				const revoked = byEvent('apikey.revoked');
				expect(revoked.length).toBe(1);
				expect(revoked[0].target).toBe(key.id);
				expect(revoked[0].actor).toBe('admin');

				const csrfRejections = byEvent('csrf.rejected');
				expect(csrfRejections.length).toBe(1);
				expect(csrfRejections[0].ip).toBeNull();
				expect(csrfRejections[0].detail).toEqual({ method: 'POST', path: '/api/admin/logout' });

				// A real admin login (the password step, MFA disabled here) also logs
				// admin.login.success - confirms the success side of the taxonomy fires
				// too, not just failures.
				expect(byEvent('admin.login.success').length).toBe(1);

				// No secret material anywhere in the log: the admin password, the raw
				// API key token/secret, or the session cookie value must never appear
				// in any field of any row.
				const dump = JSON.stringify(events);
				expect(dump).not.toContain(ADMIN_PASSWORD);
				expect(dump).not.toContain(key.token);
				const secretPart = key.token.split('_')[2];
				expect(dump).not.toContain(secretPart);
				expect(dump).not.toContain(cookie.split('=')[1]);

				// The event= exact-match filter narrows both the returned rows and total.
				const filtered = await fetch(`${base}/api/admin/audit?event=apikey.created`, { headers: { Cookie: cookie } });
				const filteredBody = await filtered.json();
				expect(filteredBody.total).toBe(1);
				expect(filteredBody.events.every(e => e.event === 'apikey.created')).toBe(true);

				// The read endpoint itself is admin-only.
				const anon = await fetch(`${base}/api/admin/audit`);
				expect(anon.status).toBe(403);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
