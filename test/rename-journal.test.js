// F-19: share rename is not atomic across SQLite and the filesystem. A
// rename touches two independent systems - a DB transaction (row copy +
// children repoint + old row delete) and a directory rename on disk - and a
// crash between the two used to leave them split: the DB pointing at the new
// id while the blobs still sat under the old id's directory, 404ing every
// file until an admin hand-fixed it.
//
// The fix (lib/renames.js) journals the rename in a new `share_renames` table,
// flipped to 'db_committed' atomically WITH the DB-side rename, and rolled
// forward by reconcileShareRenames() at the next boot if the filesystem move
// never happened. This suite simulates exactly that crash window - stopping
// the server after the DB has committed a rename but before the directory
// move ran - and confirms the next boot's reconciliation repairs it, leaving
// the share fully downloadable under its new id. It also covers the other
// journal state ('requested', meaning the DB transaction itself never
// committed) and the ordinary, uninterrupted rename path end to end.
//
// Boots the real server as a child process (mirrors migrations.test.js) since
// reconciliation only runs at real boot time, before the server starts
// accepting requests.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import { createHash } from 'node:crypto';

const ROOT = join(import.meta.dir, '..');
const sha256Hex = s => createHash('sha256').update(s).digest('hex');
const nowSec = () => Math.floor(Date.now() / 1000);

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
			ADMIN_PASSWORD: 'RenameJournalTest-Pw-2026',
			SECRET: `rename-journal-secret-${port}`,
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
		body: JSON.stringify({ password: 'RenameJournalTest-Pw-2026' }),
	});
	expect(res.status).toBe(200);
	return res.headers.get('set-cookie').split(';')[0];
}

// Inserts a minimal, current-shape share+file row directly (bypassing the
// HTTP API), matching the columns db.js's `schema` declares today.
function insertShareAndFile(db, { shareId, fileId, rawEditToken, content }) {
	const ts = nowSec();
	db.query(
		`INSERT INTO shares (id, title, created_at, expires_at, password_hash, max_downloads, download_count, one_time, edit_token, finalized, deleted_at, creator_ip, creator_ua, e2e, view_count, api_key_id)
		 VALUES (?, ?, ?, NULL, NULL, NULL, 0, 0, ?, 1, NULL, '127.0.0.1', 'test', 0, 0, NULL)`,
	).run(shareId, 'journal test', ts, sha256Hex(rawEditToken));
	db.query(
		`INSERT INTO files (id, share_id, name, size, received, mime, complete, download_count, created_at, stored_name, iv, sha256, enc_version, key_id)
		 VALUES (?, ?, ?, ?, ?, 'text/plain', 1, 0, ?, ?, NULL, ?, 1, 1)`,
	).run(fileId, shareId, 'f.txt', content.length, content.length, ts, fileId, sha256Hex(content));
}

describe('share rename journal (F-19)', () => {
	test('a crash between the DB commit and the filesystem move is repaired on the next boot', async () => {
		const dir = freshDataDir('rename-crash');
		const port = 3930;
		try {
			// Boot once just to let db.js create the current schema (including
			// share_renames), then stop - the rest of this test manipulates the
			// database and filesystem directly to simulate the exact crash window
			// (DB already committed, directory move never ran).
			const boot1 = await bootServer(dir, port);
			await stopServer(boot1);

			const dbPath = join(dir, 'roeshare.db');
			const db = new Database(dbPath);
			insertShareAndFile(db, { shareId: 'renamed-target', fileId: 'file1', rawEditToken: 'RawEditTokenABCDEFGHIJ1234567890', content: 'hello journal' });
			// Journal row left at 'db_committed': exactly what performShareRename's
			// transaction leaves behind if the process dies right after it commits,
			// before renameShareDir() runs.
			const ts = nowSec();
			db.query("INSERT INTO share_renames (old_id, new_id, state, created_at, updated_at) VALUES (?, ?, 'db_committed', ?, ?)").run('rename-source', 'renamed-target', ts, ts);
			db.close();

			// The physical blob still sits under the OLD id - the DB already points
			// at the new id (the row above is 'renamed-target'), matching the state
			// right after a crash mid-rename.
			mkdirSync(join(dir, 'storage', 'rename-source'), { recursive: true });
			writeFileSync(join(dir, 'storage', 'rename-source', 'file1'), 'hello journal');

			const proc = await bootServer(dir, port);
			try {
				// Reconciliation must have moved the directory to the new id...
				expect(existsSync(join(dir, 'storage', 'renamed-target', 'file1'))).toBe(true);
				expect(existsSync(join(dir, 'storage', 'rename-source'))).toBe(false);

				// ...and the journal must be empty again.
				const after = new Database(dbPath);
				const rows = after.query('SELECT * FROM share_renames').all();
				expect(rows.length).toBe(0);
				after.close();

				// The share must be fully accessible under its new id end to end.
				const dl = await fetch(`http://127.0.0.1:${port}/api/shares/renamed-target/files/file1/download`);
				expect(dl.status).toBe(200);
				expect(await dl.text()).toBe('hello journal');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test("a 'requested' journal row (DB transaction never committed) is just dropped on reconcile", async () => {
		const dir = freshDataDir('rename-requested');
		const port = 3931;
		try {
			const boot1 = await bootServer(dir, port);
			await stopServer(boot1);

			const dbPath = join(dir, 'roeshare.db');
			const db = new Database(dbPath);
			insertShareAndFile(db, { shareId: 'untouched-share', fileId: 'file1', rawEditToken: 'RawEditTokenABCDEFGHIJ0987654321', content: 'still here' });
			const ts = nowSec();
			// No corresponding DB change ever happened - the transaction that would
			// have flipped this to 'db_committed' never ran (crash before/during it).
			db.query("INSERT INTO share_renames (old_id, new_id, state, created_at, updated_at) VALUES ('untouched-share', 'never-happened', 'requested', ?, ?)").run(ts, ts);
			db.close();

			mkdirSync(join(dir, 'storage', 'untouched-share'), { recursive: true });
			writeFileSync(join(dir, 'storage', 'untouched-share', 'file1'), 'still here');

			const proc = await bootServer(dir, port);
			try {
				// Nothing must have moved - the share is exactly where it always was.
				expect(existsSync(join(dir, 'storage', 'untouched-share', 'file1'))).toBe(true);
				expect(existsSync(join(dir, 'storage', 'never-happened'))).toBe(false);

				const after = new Database(dbPath);
				const rows = after.query('SELECT * FROM share_renames').all();
				expect(rows.length).toBe(0);
				const share = after.query('SELECT id FROM shares WHERE id = ?').get('untouched-share');
				expect(share).toBeTruthy();
				after.close();

				const dl = await fetch(`http://127.0.0.1:${port}/api/shares/untouched-share/files/file1/download`);
				expect(dl.status).toBe(200);
				expect(await dl.text()).toBe('still here');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('an ordinary, uninterrupted admin rename still works end to end and leaves an empty journal', async () => {
		const dir = freshDataDir('rename-happy');
		const port = 3932;
		try {
			const proc = await bootServer(dir, port);
			try {
				const base = `http://127.0.0.1:${port}`;
				const cookie = await adminCookie(base);

				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false }),
				});
				expect(createRes.status).toBe(201);
				const { id, editToken } = await createRes.json();

				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'a.bin', size: 5, mime: 'application/octet-stream' }),
				});
				expect(regRes.status).toBe(200);
				const { fileId } = await regRes.json();

				const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
					body: 'hello',
				});
				expect(chunkRes.status).toBe(200);

				const finalizeRes = await fetch(`${base}/api/shares/${id}/finalize`, {
					method: 'POST',
					headers: { 'X-Edit-Token': editToken },
				});
				expect(finalizeRes.status).toBe(200);

				const patchRes = await fetch(`${base}/api/admin/shares/${id}`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
					body: JSON.stringify({ slug: 'happy-new-slug' }),
				});
				expect(patchRes.status).toBe(200);
				const patchBody = await patchRes.json();
				expect(patchBody.id).toBe('happy-new-slug');

				// Old id is gone, new id serves the file.
				const oldGet = await fetch(`${base}/api/shares/${id}`);
				expect(oldGet.status).toBe(404);

				const dl = await fetch(`${base}/api/shares/happy-new-slug/files/${fileId}/download`);
				expect(dl.status).toBe(200);
				expect(await dl.text()).toBe('hello');

				expect(existsSync(join(dir, 'storage', 'happy-new-slug', fileId))).toBe(true);
				expect(existsSync(join(dir, 'storage', id))).toBe(false);
			} finally {
				await stopServer(proc);
			}

			// The journal must be empty (no in-flight row leftover) after a clean rename.
			const after = new Database(join(dir, 'roeshare.db'));
			const rows = after.query('SELECT * FROM share_renames').all();
			expect(rows.length).toBe(0);
			after.close();
		} finally {
			cleanupDir(dir);
		}
	});
});
