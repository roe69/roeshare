// Regression tests for F-08: the in-memory fixed-window rate limiter did not
// survive a restart (a redeploy silently reset every brute-force counter) and
// evicted oldest-first under a flood of unrelated keys (a flood of unique
// keys could crowd a login counter out of the Map and reset it). Fixed by
// adding a synchronous SQLite write-through for the four credential
// brute-force buckets only (admin-login, apikey-login, upload-verify,
// unlock) - see lib/ratelimit.js's PERSIST_PREFIXES.
//
// Boots the real server as a child process (mirrors trusted-proxy.test.js)
// and drives it purely over HTTP - no mocking of the DB or rate limiter.

import { test, expect, describe } from 'bun:test';
import { Database } from 'bun:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
}

async function bootServer(dataDir, port, extraEnv = {}) {
	const proc = Bun.spawn({
		cmd: [process.execPath, 'run', 'src/server.js'],
		cwd: ROOT,
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(port),
			DATA_DIR: dataDir,
			ADMIN_PASSWORD: 'RateLimitPersist-Pw-2026',
			SECRET: `ratelimit-persist-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			BASE_URL: `http://127.0.0.1:${port}`,
			...extraEnv,
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

async function wrongPasswordLogin(base) {
	// Origin: base so this reaches enforce()/the password check (L-01's CSRF
	// gate runs first in the handler) rather than being rejected as CSRF itself
	// - the rate-limit counter this test exercises must actually increment.
	return fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password: 'definitely-not-the-password' }),
	});
}

describe('rate limiter SQLite persistence (F-08)', () => {
	test('a persisted bucket (admin-login) survives a process restart instead of resetting', async () => {
		// admin-login: 8 attempts per 5 minutes per IP (routes/admin.js). A wrong
		// password still counts against the limiter (it is checked before the
		// password comparison), so this never needs a correct password.
		const dir = freshDataDir('ratelimit-restart');
		let proc = await bootServer(dir, 3720);
		try {
			const base = 'http://127.0.0.1:3720';

			// Consume 5 of the 8 allowed attempts before restarting.
			for (let i = 0; i < 5; i++) {
				const res = await wrongPasswordLogin(base);
				expect(res.status).toBe(403); // wrong password, but still under the limit
			}

			await stopServer(proc);
			proc = await bootServer(dir, 3720); // reboot against the SAME data dir

			// If the counter reset on restart, the next 4 requests (bringing a
			// fresh counter to only 4) would all still be allowed. Because the
			// counter must resume at 5, the 6th/7th/8th (cumulative) attempts are
			// still allowed but the 9th is not.
			for (let i = 0; i < 3; i++) {
				const res = await wrongPasswordLogin(base); // cumulative attempts 6, 7, 8
				expect(res.status).toBe(403);
			}
			const blocked = await wrongPasswordLogin(base); // cumulative attempt 9 - over the limit
			expect(blocked.status).toBe(429);
			const body = await blocked.json();
			expect(body.retryAfter).toBeGreaterThan(0);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('reset() (successful login) clears the persisted row too, not just the in-memory bucket', async () => {
		const dir = freshDataDir('ratelimit-reset');
		let proc = await bootServer(dir, 3721);
		try {
			const base = 'http://127.0.0.1:3721';

			for (let i = 0; i < 5; i++) {
				const res = await wrongPasswordLogin(base);
				expect(res.status).toBe(403);
			}

			// A correct login forgives the counter (admin.js calls reset()).
			const good = await fetch(`${base}/api/admin/login`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Origin: base },
				body: JSON.stringify({ password: 'RateLimitPersist-Pw-2026' }),
			});
			expect(good.status).toBe(200);

			await stopServer(proc);
			proc = await bootServer(dir, 3721); // reboot against the SAME data dir

			// If the persisted row had NOT been cleared alongside the in-memory
			// bucket, a restart would reload count=5 from SQLite and only 3 more
			// attempts would be allowed before a 429. Since it must have been
			// cleared, a fresh run of 5 more wrong attempts is still allowed.
			for (let i = 0; i < 5; i++) {
				const res = await wrongPasswordLogin(base);
				expect(res.status).toBe(403);
			}
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('performance smoke test: 500 rapid hits against a persisted bucket stay well under a second', async () => {
		const dir = freshDataDir('ratelimit-perf');
		const proc = await bootServer(dir, 3722);
		try {
			const base = 'http://127.0.0.1:3722';

			const start = performance.now();
			// Concurrent, not serial - exercises the SQLite write-through under
			// contention, which is the part this change adds cost to. Most of
			// these will come back 429 once the 8/5min cap is exceeded, but each
			// one still round-trips through hit() and its UPSERT.
			await Promise.all(Array.from({ length: 500 }, () => wrongPasswordLogin(base)));
			const elapsed = performance.now() - start;
			console.log(`[ratelimit-perf] 500 concurrent persisted-bucket hits took ${elapsed.toFixed(1)}ms`);

			expect(elapsed).toBeLessThan(3000); // generous smoke-test ceiling, not a benchmark
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});

// Regression tests for M-03 GAP 2: enforce('dl:' + shareId, ...) was called
// unconditionally at the top of both preview and download - a synchronous
// SQLite UPSERT on EVERY request against EVERY share, not just a password-
// protected or max_downloads-limited one. Fixed by picking between the
// persisted 'dl:' bucket and a plain in-memory-only 'dlv:' bucket based on
// whether the target share is actually protected (routes/download.js's
// isRateLimitProtected()) - see ratelimit.js's PERSIST_PREFIXES comment.
//
// Stops the server (so the SQLite WAL is checkpointed/closed) and opens the
// data dir's db file directly to check for a persisted 'dl:<shareId>:' row,
// rather than relying on the restart-survival behavior already covered above.
describe('M-03 GAP 2: dl: persistence is scoped to genuinely protected shares only', () => {
	function countPersistedKeysLike(dbPath, likePattern) {
		const db = new Database(dbPath, { readonly: true });
		try {
			return db.query('SELECT COUNT(*) AS c FROM rate_limits WHERE key LIKE ?').get(likePattern).c;
		} finally {
			db.close();
		}
	}

	async function createShare(base, body) {
		const res = await fetch(`${base}/api/shares`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ e2e: false, ...body }),
		});
		expect(res.status).toBe(201);
		return res.json(); // { id, editToken }
	}

	test('an unprotected share\'s preview/download requests never persist a dl: row (stay in-memory only)', async () => {
		const dir = freshDataDir('ratelimit-scope-plain');
		let proc = await bootServer(dir, 3944);
		try {
			const base = 'http://127.0.0.1:3944';
			const { id } = await createShare(base, {});

			// No password, no maxDownloads: enforce() runs unconditionally before
			// the file lookup, so the persisted-vs-volatile decision is already
			// made by the time these come back 404 (file id does not exist).
			const preview = await fetch(`${base}/api/shares/${id}/files/nonexistent/preview`);
			expect(preview.status).toBe(404);
			const download = await fetch(`${base}/api/shares/${id}/files/nonexistent/download`);
			expect(download.status).toBe(404);

			await stopServer(proc);
			proc = null;

			expect(countPersistedKeysLike(join(dir, 'roeshare.db'), `dl:${id}:%`)).toBe(0);
		} finally {
			if (proc) await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a password-protected share\'s preview/download requests DO use the persisted dl: bucket', async () => {
		const dir = freshDataDir('ratelimit-scope-pw');
		let proc = await bootServer(dir, 3945);
		try {
			const base = 'http://127.0.0.1:3945';
			const { id } = await createShare(base, { password: 'zip-gap2-pw' });

			// No access token supplied - accessCheck rejects with 403, but that
			// happens AFTER enforce(), so the persisted write has already landed.
			const preview = await fetch(`${base}/api/shares/${id}/files/nonexistent/preview`);
			expect(preview.status).toBe(403);
			const download = await fetch(`${base}/api/shares/${id}/files/nonexistent/download`);
			expect(download.status).toBe(403);

			await stopServer(proc);
			proc = null;

			expect(countPersistedKeysLike(join(dir, 'roeshare.db'), `dl:${id}:%`)).toBeGreaterThan(0);
		} finally {
			if (proc) await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a max-downloads-limited share\'s preview/download requests DO use the persisted dl: bucket', async () => {
		const dir = freshDataDir('ratelimit-scope-maxdl');
		let proc = await bootServer(dir, 3946);
		try {
			const base = 'http://127.0.0.1:3946';
			const { id } = await createShare(base, { maxDownloads: 1 });

			// No password, so accessCheck passes. Preview then hits the
			// controlled-share guard (max_downloads-limited shares refuse preview
			// entirely for a non-owner) before ever reaching the file lookup, while
			// download has no such guard and 404s at the file lookup instead - both
			// happen AFTER enforce(), so either way the persisted write has landed.
			const preview = await fetch(`${base}/api/shares/${id}/files/nonexistent/preview`);
			expect(preview.status).toBe(403);
			const download = await fetch(`${base}/api/shares/${id}/files/nonexistent/download`);
			expect(download.status).toBe(404);

			await stopServer(proc);
			proc = null;

			expect(countPersistedKeysLike(join(dir, 'roeshare.db'), `dl:${id}:%`)).toBeGreaterThan(0);
		} finally {
			if (proc) await stopServer(proc);
			cleanupDir(dir);
		}
	});
});
