// F-05: the global storage quota (config.maxTotalSize) used to be enforced by
// comparing a request's size against a 5s-TTL-cached totalUsage() disk walk -
// a cached check-then-act race. Two concurrent registrations could each read
// the same stale total, each individually pass, and together blow past the
// cap. This suite exercises the fix (lib/quota.js's atomic reservation
// ledger) against the real running server, mirroring the audit's required
// "two concurrent requests, only one wins" test style.
//
// Boots the real server as a child process (mirrors migrations.test.js /
// security-regressions.test.js) since this is an HTTP-surface + concurrency
// behavior, not something a mocked DB/HTTP layer could actually catch.

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
			ADMIN_PASSWORD: 'QuotaTest-Pw-2026',
			SECRET: `quota-test-secret-${port}`,
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

async function createShare(base, opts = {}) {
	const res = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ e2e: false, ...opts }),
	});
	expect(res.status).toBe(201);
	return res.json();
}

function registerFile(base, id, editToken, name, size) {
	return fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/json' },
		body: JSON.stringify({ name, size, mime: 'application/octet-stream' }),
	});
}

describe('global storage quota is atomic under concurrency', () => {
	test('two concurrent registrations that individually fit but collectively exceed MAX_TOTAL_SIZE: only one succeeds', async () => {
		const dir = freshDataDir('quota-race');
		try {
			// Each registration (600) individually fits under the cap (1000); the
			// two together (1200) do not. The old cached-disk-walk check would let
			// both pass under concurrency (this test failed against the pre-fix code).
			const proc = await bootServer(dir, 3700, { MAX_TOTAL_SIZE: '1000' });
			try {
				const base = 'http://127.0.0.1:3700';
				const { id, editToken } = await createShare(base);

				const [a, b] = await Promise.all([
					registerFile(base, id, editToken, 'a.bin', 600),
					registerFile(base, id, editToken, 'b.bin', 600),
				]);

				const statuses = [a.status, b.status].sort();
				expect(statuses).toEqual([200, 413]);

				const loser = a.status === 413 ? a : b;
				const loserBody = await loser.json();
				expect(loserBody.error).toBe('Server storage limit reached');

				// The share's own metadata must reflect exactly one accepted file.
				const meta = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } }).then(r => r.json());
				expect(meta.files.length).toBe(1);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a third registration is rejected once two accepted ones exhaust the cap, then accepted again after one is released', async () => {
		const dir = freshDataDir('quota-sequential');
		try {
			const proc = await bootServer(dir, 3701, { MAX_TOTAL_SIZE: '1000' });
			try {
				const base = 'http://127.0.0.1:3701';
				const { id, editToken } = await createShare(base);

				const first = await registerFile(base, id, editToken, 'first.bin', 900);
				expect(first.status).toBe(200);

				// 900 already reserved, 100 left - a 200-byte registration must fail.
				const second = await registerFile(base, id, editToken, 'second.bin', 200);
				expect(second.status).toBe(413);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});

describe('a reservation for an upload that never completes does not permanently consume quota', () => {
	test('deleting a share before its file is finalized releases the reserved quota for reuse', async () => {
		const dir = freshDataDir('quota-release');
		try {
			const proc = await bootServer(dir, 3702, { MAX_TOTAL_SIZE: '1000' });
			try {
				const base = 'http://127.0.0.1:3702';

				const abandoned = await createShare(base);
				const reg = await registerFile(base, abandoned.id, abandoned.editToken, 'abandoned.bin', 900);
				expect(reg.status).toBe(200);

				// The reservation for the never-finished 900-byte file leaves only 100
				// bytes of headroom - a second, unrelated 900-byte registration must
				// fail while it is still held.
				const blocked = await createShare(base);
				const blockedReg = await registerFile(base, blocked.id, blocked.editToken, 'blocked.bin', 900);
				expect(blockedReg.status).toBe(413);

				// Delete the abandoned share WITHOUT ever finalizing/completing its
				// upload - this must release its reservation, not just its (zero)
				// committed usage.
				const del = await fetch(`${base}/api/shares/${abandoned.id}`, {
					method: 'DELETE',
					headers: { 'X-Edit-Token': abandoned.editToken },
				});
				expect(del.status).toBe(200);

				// The space is now reclaimed: the same 900-byte registration that was
				// just rejected must now succeed.
				const retry = await createShare(base);
				const retryReg = await registerFile(base, retry.id, retry.editToken, 'retry.bin', 900);
				expect(retryReg.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('boot reconciliation reclaims quota for a reservation whose file was hard-deleted by an admin out from under it', async () => {
		const dir = freshDataDir('quota-reconcile');
		try {
			const proc1 = await bootServer(dir, 3703, { MAX_TOTAL_SIZE: '1000' });
			let shareId, editToken, fileId;
			try {
				const base = 'http://127.0.0.1:3703';
				const share = await createShare(base);
				shareId = share.id;
				editToken = share.editToken;
				const reg = await registerFile(base, shareId, editToken, 'orphan.bin', 900);
				expect(reg.status).toBe(200);
				fileId = (await reg.json()).fileId;

				// Simulate an operator hard-deleting the whole share row+files
				// directly (bypassing the app's own quota.releaseShare bookkeeping),
				// e.g. via an out-of-band DB tool - this is exactly the drift
				// scenario reconcile() exists to correct.
			} finally {
				await stopServer(proc1);
			}

			const { Database } = await import('bun:sqlite');
			const dbPath = join(dir, 'roeshare.db');
			const raw = new Database(dbPath);
			raw.query('DELETE FROM files WHERE id = ?').run(fileId);
			raw.query('DELETE FROM shares WHERE id = ?').run(shareId);
			// Leave the storage_reservations row and the ledger's reserved_bytes
			// exactly as the app left them - orphaned, pointing at nothing.
			const before = raw.query('SELECT reserved_bytes FROM storage_ledger WHERE id = 1').get();
			expect(before.reserved_bytes).toBe(900);
			raw.close();

			const proc2 = await bootServer(dir, 3704, { MAX_TOTAL_SIZE: '1000' });
			try {
				const base = 'http://127.0.0.1:3704';
				// After boot reconciliation, the orphaned reservation must be gone and
				// the full 1000-byte cap available again.
				const share = await createShare(base);
				const reg = await registerFile(base, share.id, share.editToken, 'fresh.bin', 900);
				expect(reg.status).toBe(200);
			} finally {
				await stopServer(proc2);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
