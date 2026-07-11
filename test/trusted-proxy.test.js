// Regression tests for F-04 (trusted-proxy client-IP spoofing): clientIp()
// (lib/http.js) must only honor X-Forwarded-For/X-Real-IP when the DIRECT
// socket peer is inside the configured TRUSTED_PROXY_CIDRS allowlist, must
// walk the forwarded chain from the right by exactly TRUSTED_PROXY_HOPS, and
// must fall back safely (never crash) on a malformed/oversized header or one
// with fewer entries than the configured hop count.
//
// Exercised end-to-end as a black box: POST /api/shares records ctx.ip (the
// resolved client IP) as the share's creator_ip, and GET /api/admin/shares/:id
// (admin-only) reads it back - so every scenario below is a real HTTP round
// trip through the real clientIp() logic, never a unit-level mock.
//
// Boots the real server as a child process (mirrors security-regressions.test.js).

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'TrustedProxyTest-Pw-2026';

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
			ADMIN_PASSWORD,
			SECRET: `trusted-proxy-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			TRUSTED_PROXY_CIDRS: '',
			TRUSTED_PROXY_HOPS: '',
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

// Create a share (real socket peer is always loopback in this test harness -
// fetch() runs on the same box), optionally with forwarding headers, and
// return the creator_ip the server recorded for it via the admin detail view.
async function createShareAndReadCreatorIp(base, cookie, headers = {}) {
	const shareRes = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body: JSON.stringify({ e2e: false }),
	});
	expect(shareRes.status).toBe(201);
	const { id } = await shareRes.json();

	const detail = await fetch(`${base}/api/admin/shares/${id}`, { headers: { Cookie: cookie } });
	expect(detail.status).toBe(200);
	const body = await detail.json();
	return body.creatorIp;
}

const LOOPBACK_CIDRS = '127.0.0.1/32,::1/128';

describe('trusted-proxy client IP resolution', () => {
	test('no trusted-proxy config: a forged X-Forwarded-For is ignored, socket peer is used', async () => {
		const dir = freshDataDir('untrusted-default');
		const proc = await bootServer(dir, 3610);
		try {
			const base = 'http://127.0.0.1:3610';
			const cookie = await adminCookie(base);

			// Baseline: what the real socket peer resolves to with no forwarding
			// headers at all.
			const baseline = await createShareAndReadCreatorIp(base, cookie);
			expect(baseline).toBeTruthy();

			// A forged chain must be completely ignored - the recorded IP must still
			// be the real socket peer, not the attacker-supplied header.
			const forged = await createShareAndReadCreatorIp(base, cookie, {
				'X-Forwarded-For': '6.6.6.6, 7.7.7.7',
			});
			expect(forged).toBe(baseline);
			expect(forged).not.toBe('6.6.6.6');
			expect(forged).not.toBe('7.7.7.7');
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('trusted proxy (loopback) with a valid chain: the correct client is extracted', async () => {
		const dir = freshDataDir('trusted-chain');
		const proc = await bootServer(dir, 3611, { TRUSTED_PROXY_CIDRS: LOOPBACK_CIDRS, TRUSTED_PROXY_HOPS: '1' });
		try {
			const base = 'http://127.0.0.1:3611';
			const cookie = await adminCookie(base);

			// Chain of 2: "<real client>, <this trusted proxy's own address>". With
			// hops=1 the rightmost entry is skipped and the one before it is taken.
			const ip = await createShareAndReadCreatorIp(base, cookie, {
				'X-Forwarded-For': '203.0.113.7, 127.0.0.1',
			});
			expect(ip).toBe('203.0.113.7');
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('TRUST_PROXY=1 back-compat alias behaves like loopback-only trust', async () => {
		const dir = freshDataDir('legacy-alias');
		const proc = await bootServer(dir, 3612, { TRUST_PROXY: '1', TRUSTED_PROXY_CIDRS: '' });
		try {
			const base = 'http://127.0.0.1:3612';
			const cookie = await adminCookie(base);

			const ip = await createShareAndReadCreatorIp(base, cookie, {
				'X-Forwarded-For': '198.51.100.9, 127.0.0.1',
			});
			expect(ip).toBe('198.51.100.9');
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('untrusted peer: X-Forwarded-For is ignored entirely regardless of content, even with hops configured', async () => {
		const dir = freshDataDir('untrusted-peer');
		// A CIDR that does NOT cover the loopback address the test harness always
		// connects from - so every request in this test arrives from an untrusted
		// peer no matter what it claims via headers.
		const proc = await bootServer(dir, 3613, { TRUSTED_PROXY_CIDRS: '10.99.99.0/24', TRUSTED_PROXY_HOPS: '1' });
		try {
			const base = 'http://127.0.0.1:3613';
			const cookie = await adminCookie(base);

			const baseline = await createShareAndReadCreatorIp(base, cookie);

			const withHeader = await createShareAndReadCreatorIp(base, cookie, {
				'X-Forwarded-For': '203.0.113.7, 198.51.100.1',
			});
			expect(withHeader).toBe(baseline);
			expect(withHeader).not.toBe('203.0.113.7');
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('malformed or oversized X-Forwarded-For falls back safely to the socket peer, no crash', async () => {
		const dir = freshDataDir('malformed-header');
		const proc = await bootServer(dir, 3614, { TRUSTED_PROXY_CIDRS: LOOPBACK_CIDRS, TRUSTED_PROXY_HOPS: '1' });
		try {
			const base = 'http://127.0.0.1:3614';
			const cookie = await adminCookie(base);

			const baseline = await createShareAndReadCreatorIp(base, cookie);

			// Not a parseable IP at the target position.
			const garbage = await createShareAndReadCreatorIp(base, cookie, {
				'X-Forwarded-For': 'not-an-ip, 127.0.0.1',
			});
			expect(garbage).toBe(baseline);

			// Oversized: more than the 20-entry cap.
			const oversized = Array.from({ length: 25 }, (_, i) => `10.0.0.${i}`).join(', ');
			const tooLong = await createShareAndReadCreatorIp(base, cookie, {
				'X-Forwarded-For': oversized,
			});
			expect(tooLong).toBe(baseline);

			// Fewer entries than the configured hop count.
			const tooFewEntries = await createShareAndReadCreatorIp(base, cookie, {
				'X-Forwarded-For': '127.0.0.1',
			});
			expect(tooFewEntries).toBe(baseline);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});
