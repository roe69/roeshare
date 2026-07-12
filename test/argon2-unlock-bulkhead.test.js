// Regression test for the security-audit finding "global argon2 semaphore
// exhausted via the unauthenticated share-unlock endpoint, causing
// instance-wide 503s for all password verification/creation operations"
// (2026-07).
//
// Before the fix, POST /api/shares/:id/unlock (auth: 'public', needing only
// a non-secret share id) shared ONE global, unkeyed 4-slot argon2 semaphore
// with share creation and the admin password edit. A burst of concurrent
// unlock attempts against ANY live password-protected share could exhaust
// that shared pool, causing an unrelated, concurrent share-creation request
// to fail with 503 even though it never touched the unlock endpoint at all.
//
// The fix gives unlock its own bulkhead pool ('argon2-unlock', separate from
// the 'argon2' pool share-creation/admin-edit still use), with a per-IP
// sub-limit. This test floods unlock from one IP while concurrently issuing
// an unrelated password-protected share-creation request, and asserts the
// share-creation request is NOT starved by the unlock flood - the exact
// cross-endpoint denial the finding demonstrated live against production.
//
// Boots the real server as a child process (mirrors semaphore.test.js).

import { test, expect, describe } from 'bun:test';
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
			ADMIN_PASSWORD: 'Argon2BulkheadTest-Pw-2026',
			SECRET: `argon2-bulkhead-secret-${port}`,
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

describe('argon2 semaphore bulkhead: unlock cannot starve unrelated share creation', () => {
	test('flooding /unlock on one share does not 503 a concurrent, unrelated password-protected share-create', async () => {
		const dir = freshDataDir('argon2-bulkhead');
		try {
			const proc = await bootServer(dir, 3985);
			try {
				const base = 'http://127.0.0.1:3985';

				// A disposable password-protected share to unlock-flood.
				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false, password: 'the-real-password' }),
				});
				expect(createRes.status).toBe(201);
				const { id } = await createRes.json();

				// Fire a burst of concurrent unlock attempts (wrong password - argon2
				// still runs the verify) alongside ONE unrelated share-creation
				// request that also needs an argon2 hash (a NEW password-protected
				// share). Before the fix, sharing one global 4-slot pool meant this
				// burst could plausibly starve the create call. After the fix, unlock
				// draws from its own separate 'argon2-unlock' pool, so the create
				// request must never see a 503 caused by this unlock flood.
				const UNLOCK_BURST = 12;
				const unlockPromises = Array.from({ length: UNLOCK_BURST }, () =>
					fetch(`${base}/api/shares/${id}/unlock`, {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ password: 'wrong-guess' }),
					})
				);
				const createPromise = fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false, password: 'another-real-password' }),
				});

				const [unlockResults, createResult] = await Promise.all([Promise.all(unlockPromises), createPromise]);

				// The unrelated create request must succeed - the whole point of the
				// bulkhead fix. (It does not depend on any unlock result.)
				expect(createResult.status).toBe(201);
				await createResult.json();

				// Sanity: the unlock burst itself is a mix of 403 (argon2 ran, wrong
				// password) and possibly 503 (unlock's OWN pool briefly saturated) -
				// but never anything that would indicate a crash/500.
				for (const r of unlockResults) {
					expect([403, 503]).toContain(r.status);
					await r.json();
				}
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
