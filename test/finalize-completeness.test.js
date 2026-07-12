// Regression test for the ghost-share finding: finalize() never checked that
// every registered file had finished uploading before flipping a share to
// finalized = 1. A share finalized with an incomplete file becomes a
// permanent "ghost": it is not "abandoned" (server.js's selectAbandoned only
// matches finalized = 0) and it is not necessarily "expired" (its clock may
// not have elapsed, or the share may have no expiry at all) - so neither
// sweeper in server.js could ever reap it, permanently wasting quota.
//
// Fixed by gating the finalized flip on a completeness check, run in the SAME
// db.transaction() as the flip itself (shares.js's finalizeTx), so a
// concurrent file registration cannot land between the check and the write.
//
// Boots the real server as a child process (mirrors security-fixes.test.js).

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
			ADMIN_PASSWORD: 'FinalizeGhostTest-Pw-2026',
			SECRET: `finalize-ghost-secret-${port}`,
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

describe('finalize() refuses to publish a share with an incomplete file', () => {
	test('an under-uploaded file blocks finalize with 409, and never flips finalized', async () => {
		const dir = freshDataDir('finalize-ghost');
		try {
			const proc = await bootServer(dir, 3950);
			try {
				const base = 'http://127.0.0.1:3950';

				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false }),
				});
				expect(createRes.status).toBe(201);
				const { id, editToken } = await createRes.json();

				// Register a 20-byte file but only ever write 10 bytes of it - it
				// never reaches complete = 1.
				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'ghost.bin', size: 20, mime: 'application/octet-stream' }),
				});
				expect(regRes.status).toBe(200);
				const { fileId } = await regRes.json();

				const partial = new Uint8Array(10).fill(65);
				const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: partial,
				});
				expect(chunkRes.status).toBe(200);
				expect((await chunkRes.json()).complete).toBe(false);

				// The would-be ghost: finalize must be refused, not silently accepted.
				const finRes = await fetch(`${base}/api/shares/${id}/finalize`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken },
				});
				expect(finRes.status).toBe(409);

				const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				const meta = await metaRes.json();
				expect(meta.finalized).toBe(false);

				// Finish the upload, then finalize succeeds normally.
				const rest = new Uint8Array(10).fill(66);
				const chunk2Res = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=10`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: rest,
				});
				expect(chunk2Res.status).toBe(200);
				expect((await chunk2Res.json()).complete).toBe(true);

				const finRes2 = await fetch(`${base}/api/shares/${id}/finalize`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken },
				});
				expect(finRes2.status).toBe(200);

				const metaRes2 = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				expect((await metaRes2.json()).finalized).toBe(true);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a zero-file share still finalizes (the existing, intended edge case)', async () => {
		const dir = freshDataDir('finalize-zero-file');
		try {
			const proc = await bootServer(dir, 3951);
			try {
				const base = 'http://127.0.0.1:3951';

				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false }),
				});
				expect(createRes.status).toBe(201);
				const { id, editToken } = await createRes.json();

				const finRes = await fetch(`${base}/api/shares/${id}/finalize`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken },
				});
				expect(finRes.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
