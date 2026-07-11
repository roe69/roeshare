// F-14: filesystem operations under storageDir must never follow a symlink,
// whether it's planted in place of a share directory or in place of a blob
// file (including the "reopen an existing partial file to resume/reseal it"
// path used by chunked uploads). See lib/storage.js's assertRealDirIfExists /
// assertRealFileIfExists / openBlobForChunkWrite / O_NOFOLLOW.
//
// Boots the real server as a child process (mirrors migrations.test.js /
// security-regressions.test.js) and plants real symlinks via node:fs against
// the temp data dir, then drives everything through the real HTTP surface -
// no mocking of the DB or filesystem layer.
//
// Symlink creation requires a privilege bun:test can't assume every CI/dev
// box has (notably: plain Windows without Developer Mode or an elevated
// shell refuses it with EPERM). Every test here probes that up front and
// skips itself (not fails) when the runtime can't create symlinks at all -
// the real coverage runs wherever it can, which includes the actual Linux
// deploy target (see DEPLOY.md).

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, readdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
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

// Probe once, up front: can this process create symlinks at all? (Windows
// without Developer Mode/elevation: EPERM. Some sandboxes: ENOSYS/EACCES.)
const canSymlink = (() => {
	const dir = freshDataDir('symlink-probe');
	try {
		symlinkSync(dir, join(dir, 'self-probe-link'), 'dir');
		return true;
	} catch {
		return false;
	} finally {
		cleanupDir(dir);
	}
})();

async function bootServer(dataDir, port) {
	const proc = Bun.spawn({
		cmd: [process.execPath, 'run', 'src/server.js'],
		cwd: ROOT,
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(port),
			DATA_DIR: dataDir,
			ADMIN_PASSWORD: 'SymlinkSecTest-Pw-2026',
			SECRET: `symlink-sec-test-secret-${port}`,
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

async function createShare(base) {
	const res = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ e2e: false }),
	});
	expect(res.status).toBe(201);
	return res.json(); // { id, editToken, ... }
}

async function registerFile(base, id, editToken, name, size) {
	const res = await fetch(`${base}/api/shares/${id}/files`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
		body: JSON.stringify({ name, size, mime: 'application/octet-stream' }),
	});
	expect(res.status).toBe(200);
	return res.json(); // { fileId }
}

describe('symlinked share/blob paths are rejected, not followed', () => {
	test.skipIf(!canSymlink)('a symlink planted in place of the share directory is rejected on upload', async () => {
		const dataDir = freshDataDir('sym-sharedir');
		const outside = freshDataDir('sym-sharedir-outside');
		try {
			const proc = await bootServer(dataDir, 3651);
			try {
				const base = 'http://127.0.0.1:3651';
				const { id, editToken } = await createShare(base);
				const { fileId } = await registerFile(base, id, editToken, 'f.bin', 10);

				// Nothing has written to disk for this share yet (registration is a
				// pure DB insert), so storage/<id> doesn't exist yet - plant a
				// symlink there pointing at a directory entirely outside storageDir,
				// standing in for what the server would otherwise mkdir() into.
				const shareDirPath = join(dataDir, 'storage', id);
				mkdirSync(join(dataDir, 'storage'), { recursive: true });
				symlinkSync(outside, shareDirPath, 'dir');

				const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: new Uint8Array(10).fill(65),
				});
				// Rejected outright - never silently written through the symlink into
				// `outside`.
				expect(chunkRes.status).not.toBe(200);

				// The outside directory the symlink points to must be completely
				// untouched.
				expect(readdirSync(outside)).toEqual([]);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dataDir);
			cleanupDir(outside);
		}
	});

	test.skipIf(!canSymlink)('a symlink planted in place of a fresh blob file is rejected on the first chunk write', async () => {
		const dataDir = freshDataDir('sym-blob-fresh');
		const outsideDir = freshDataDir('sym-blob-fresh-outside');
		const outsideFile = join(outsideDir, 'secret.txt');
		writeFileSync(outsideFile, 'do-not-touch');
		try {
			const proc = await bootServer(dataDir, 3652);
			try {
				const base = 'http://127.0.0.1:3652';
				const { id, editToken } = await createShare(base);
				const { fileId } = await registerFile(base, id, editToken, 'f.bin', 10);

				// Pre-create the REAL share directory (as if a sibling file in this
				// share had already been uploaded) so writeChunk()'s mkdir() is a
				// no-op and the leaf-level guard is what's actually exercised, then
				// plant a symlink at the exact blob path pointing outside storageDir.
				const shareDirPath = join(dataDir, 'storage', id);
				mkdirSync(shareDirPath, { recursive: true });
				const blobPath = join(shareDirPath, fileId);
				symlinkSync(outsideFile, blobPath, 'file');

				const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: new Uint8Array(10).fill(66),
				});
				expect(chunkRes.status).not.toBe(200);

				// The file the symlink points at must be byte-for-byte untouched.
				expect(readFileSync(outsideFile, 'utf8')).toBe('do-not-touch');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dataDir);
			cleanupDir(outsideDir);
		}
	});

	test.skipIf(!canSymlink)('a blob file swapped for a symlink mid-upload is rejected when a later chunk tries to resume it', async () => {
		const dataDir = freshDataDir('sym-blob-resume');
		const outsideDir = freshDataDir('sym-blob-resume-outside');
		const outsideFile = join(outsideDir, 'secret.txt');
		writeFileSync(outsideFile, 'do-not-touch-either');
		try {
			const proc = await bootServer(dataDir, 3653);
			try {
				const base = 'http://127.0.0.1:3653';
				const { id, editToken } = await createShare(base);
				const { fileId } = await registerFile(base, id, editToken, 'f.bin', 20);

				// First chunk lands normally through the real server - a real,
				// legitimate partial blob file now exists on disk.
				const firstRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: new Uint8Array(10).fill(67),
				});
				expect(firstRes.status).toBe(200);
				expect((await firstRes.json()).received).toBe(10);

				// Now swap that real partial blob out for a symlink pointing
				// elsewhere - simulating an attacker with a foothold on the storage
				// volume racing the resumable-upload reopen.
				const blobPath = join(dataDir, 'storage', id, fileId);
				rmSync(blobPath, { force: true });
				symlinkSync(outsideFile, blobPath, 'file');

				// The next chunk (a legitimate resume at offset 10, per the DB's
				// `received` count) must refuse to reopen it for append, not follow
				// the symlink and write into `outsideFile`.
				const secondRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=10`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: new Uint8Array(10).fill(68),
				});
				expect(secondRes.status).not.toBe(200);

				expect(readFileSync(outsideFile, 'utf8')).toBe('do-not-touch-either');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dataDir);
			cleanupDir(outsideDir);
		}
	});
});
