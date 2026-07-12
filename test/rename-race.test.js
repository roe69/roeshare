// F-19 follow-up: rename-then-fs-move (lib/renames.js) is non-atomic - between
// the DB transaction committing (the row now lives under the new id) and
// renameShareDir() finishing, the blob directory still sits under the OLD id.
// A read request for the NEW id landing in exactly that gap used to reach
// storage.js anyway: for a legacy/plaintext blob, plainSize()'s blobFile(...)
// .size silently returns 0 for a path that does not exist yet (Bun.file()
// never checks existence), fabricating an empty 200 instead of failing loud.
//
// The fix is a route-level gate, not a reordering of the DB/fs steps (see
// lib/renames.js's module comment for why the DB must stay authoritative):
// lib/renames.js's isRenamePending(id) checks a same-process in-memory set
// PLUS the durable share_renames journal (already written by performShareRename
// before either side changes - see rename-journal.test.js), so
// routes/download.js can refuse with 503 before ever touching storage.js.
//
// Per the note that a live/timing-based reproduction of the actual race is
// unreliable (sub-millisecond fs syscall vs. network jitter), this test
// reproduces the exact DB/fs split directly - same technique
// rename-journal.test.js already uses to simulate the crash window - rather
// than racing a real concurrent rename over HTTP.

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
			ADMIN_PASSWORD: 'RenameRaceTest-Pw-2026',
			SECRET: `rename-race-secret-${port}`,
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

// Minimal, current-shape share+file row directly (bypassing the HTTP API),
// matching rename-journal.test.js's helper.
function insertShareAndFile(db, { shareId, fileId, rawEditToken, content }) {
	const ts = nowSec();
	db.query(
		`INSERT INTO shares (id, title, created_at, expires_at, password_hash, max_downloads, download_count, one_time, edit_token, finalized, deleted_at, creator_ip, creator_ua, e2e, view_count, api_key_id)
		 VALUES (?, ?, ?, NULL, NULL, NULL, 0, 0, ?, 1, NULL, '127.0.0.1', 'test', 0, 0, NULL)`,
	).run(shareId, 'race test', ts, sha256Hex(rawEditToken));
	db.query(
		`INSERT INTO files (id, share_id, name, size, received, mime, complete, download_count, created_at, stored_name, iv, sha256, enc_version, key_id)
		 VALUES (?, ?, ?, ?, ?, 'text/plain', 1, 0, ?, ?, NULL, ?, 1, 1)`,
	).run(fileId, shareId, 'f.txt', content.length, content.length, ts, fileId, sha256Hex(content));
}

describe('rename in-flight gate (F-19 follow-up)', () => {
	test('a request for the new id during the DB-committed/fs-not-yet-moved gap gets 503, not a fabricated empty 200', async () => {
		const dir = freshDataDir('rename-race');
		const port = 3940;
		try {
			// Boot for real (empty data dir) and leave the server running: the
			// state below is set up WHILE it is live, via a second connection to the
			// same (WAL-mode) database - NOT before boot. reconcileShareRenames()
			// only ever runs once, at boot, before any request is accepted (see
			// server.js) - setting this up pre-boot would have it reconciled away
			// (fs moved, journal cleared) before a single fetch() ever ran, which
			// would defeat the whole point of this test: proving the live in-flight
			// window itself is gated, not just a post-crash state.
			const proc = await bootServer(dir, port);
			try {
				const base = `http://127.0.0.1:${port}`;
				const dbPath = join(dir, 'roeshare.db');

				const db = new Database(dbPath);
				insertShareAndFile(db, { shareId: 'race-target', fileId: 'file1', rawEditToken: 'RawEditTokenRaceABCDEFGHIJ123456', content: 'hello race' });
				const ts = nowSec();
				// Journal row left at 'db_committed' - exactly what performShareRename's
				// transaction leaves in place for the whole gap between the DB commit
				// and renameShareDir() finishing (see lib/renames.js).
				db.query("INSERT INTO share_renames (old_id, new_id, state, created_at, updated_at) VALUES (?, ?, 'db_committed', ?, ?)").run('race-source', 'race-target', ts, ts);
				db.close();

				// The physical blob still sits under the OLD id - the new id's
				// directory does not exist yet, matching the DB-committed/fs-pending gap.
				mkdirSync(join(dir, 'storage', 'race-source'), { recursive: true });
				writeFileSync(join(dir, 'storage', 'race-source', 'file1'), 'hello race');

				// Single-file download: must refuse with 503 + Retry-After, never a 200
				// with a fabricated empty (or wrong) body.
				const dl = await fetch(`${base}/api/shares/race-target/files/file1/download`);
				expect(dl.status).toBe(503);
				expect(dl.headers.get('retry-after')).toBeTruthy();
				const dlBody = await dl.json();
				expect(dlBody.error).toBeTruthy();

				// Preview: same gate, same route family.
				const pv = await fetch(`${base}/api/shares/race-target/files/file1/preview`);
				expect(pv.status).toBe(503);

				// Whole-share zip.
				const zip = await fetch(`${base}/api/shares/race-target/download-all`);
				expect(zip.status).toBe(503);

				// Once the journal clears (the fs move finally lands), the exact same
				// request succeeds normally - the gate is not a permanent wedge, only a
				// window.
				const after = new Database(dbPath);
				after.query('DELETE FROM share_renames').run();
				after.close();
				mkdirSync(join(dir, 'storage', 'race-target'), { recursive: true });
				writeFileSync(join(dir, 'storage', 'race-target', 'file1'), 'hello race');

				const dl2 = await fetch(`${base}/api/shares/race-target/files/file1/download`);
				expect(dl2.status).toBe(200);
				expect(await dl2.text()).toBe('hello race');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
