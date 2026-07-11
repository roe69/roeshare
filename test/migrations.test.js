// Guards the exact failure mode that took share.roelite.net down once already:
// a schema/format change that works against a brand-new database but crashes
// (or silently mishandles data) against an existing one. Each test boots the
// real server (a genuine child process, not an in-process import - the crash
// that caused the outage only showed up at real boot time) against a
// differently-shaped database and asserts it survives with no data lost.
//
// Run with `bun test`. CI (.github/workflows/publish.yml) runs this before
// every image publish, so a schema change that breaks upgrade compatibility
// fails the build instead of reaching a deployment.
//
// When you add a column to src/db.js's `schema` or a new src/db.js
// MIGRATIONS entry, this suite - especially the legacy-database test - is
// what should catch a mistake before it ships. If it doesn't cover something
// your change needs, extend it rather than assuming manual testing is enough.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import { createHash, createCipheriv, scryptSync, randomBytes } from 'node:crypto';

const ROOT = join(import.meta.dir, '..');
const sha256Hex = s => createHash('sha256').update(s).digest('hex');

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
}

// Boots the real app as a child process against `dataDir` and waits for it to
// report healthy. Throws (with the server's stderr attached) if it never
// does - a crash-at-boot shows up here exactly as it would in production.
async function bootServer(dataDir, port) {
	const proc = Bun.spawn({
		cmd: [process.execPath, 'run', 'src/server.js'],
		cwd: ROOT,
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(port),
			DATA_DIR: dataDir,
			ADMIN_PASSWORD: 'MigrationTest-Pw-2026',
			SECRET: `migration-test-secret-${port}`,
			UPLOAD_PASSWORD: 'migration-test-upload-pw',
			TRUST_PROXY: '0',
			BASE_URL: `http://127.0.0.1:${port}`,
		},
		stdout: 'pipe',
		stderr: 'pipe',
	});

	const deadline = Date.now() + 10_000;
	let lastErr;
	while (Date.now() < deadline) {
		if (proc.exitCode !== null) break; // process already died
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

// Waits for the process to actually exit (not just for kill() to be called)
// before returning, so the SQLite file handle is released before a caller
// tries to rmSync the data directory - on Windows, deleting a directory whose
// db file was just killed-but-not-yet-released throws EBUSY.
async function stopServer(proc) {
	try {
		proc.kill();
		await Promise.race([proc.exited, new Promise(r => setTimeout(r, 3000))]);
	} catch {}
}

// rmSync immediately after a process exits can still race a delayed Windows
// file-lock release; retry briefly instead of failing the whole test over a
// harmless cleanup timing issue.
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

const SHARES_COLUMNS_LEGACY =
	`id TEXT PRIMARY KEY, title TEXT, created_at INTEGER NOT NULL, expires_at INTEGER,
	 password_hash TEXT, max_downloads INTEGER, download_count INTEGER NOT NULL DEFAULT 0,
	 one_time INTEGER NOT NULL DEFAULT 0, edit_token TEXT NOT NULL, finalized INTEGER NOT NULL DEFAULT 0,
	 deleted_at INTEGER, creator_ip TEXT, creator_ua TEXT, e2e INTEGER NOT NULL DEFAULT 0,
	 view_count INTEGER NOT NULL DEFAULT 0, api_key_id TEXT`;

const FILES_COLUMNS_LEGACY =
	`id TEXT PRIMARY KEY, share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
	 name TEXT NOT NULL, size INTEGER NOT NULL, received INTEGER NOT NULL DEFAULT 0,
	 mime TEXT NOT NULL DEFAULT 'application/octet-stream', complete INTEGER NOT NULL DEFAULT 0,
	 download_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, stored_name TEXT NOT NULL, iv TEXT`;

const API_KEYS_COLUMNS =
	`id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
	 last_used_at INTEGER, expires_at INTEGER, revoked_at INTEGER, upload_count INTEGER NOT NULL DEFAULT 0,
	 bytes_uploaded INTEGER NOT NULL DEFAULT 0, max_file_size INTEGER, max_share_size INTEGER,
	 max_shares INTEGER, max_expiry INTEGER, allow_slug INTEGER NOT NULL DEFAULT 1, allow_password INTEGER NOT NULL DEFAULT 1`;

describe('database migrations', () => {
	test('boots clean against a brand-new data directory', async () => {
		const dir = freshDataDir('fresh');
		try {
			const proc = await bootServer(dir, 3591);
			await stopServer(proc);
		} finally {
			cleanupDir(dir);
		}
	});

	test('boots clean and leaves an already-current-shape database untouched', async () => {
		const dir = freshDataDir('current');
		const db = new Database(join(dir, 'roeshare.db'), { create: true });
		db.exec(`
			CREATE TABLE shares (${SHARES_COLUMNS_LEGACY});
			CREATE TABLE files (${FILES_COLUMNS_LEGACY}, sha256 TEXT);
			CREATE TABLE api_keys (${API_KEYS_COLUMNS});
		`);
		const editHash = sha256Hex('CURRENTtoken');
		db.query(
			`INSERT INTO shares (id,title,created_at,expires_at,password_hash,max_downloads,one_time,edit_token,finalized,deleted_at,creator_ip,creator_ua,e2e,view_count,api_key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run('currentshare1', 'e2e title', Math.floor(Date.now() / 1000), null, null, null, 0, editHash, 0, null, '127.0.0.1', 'test', 1, 9, null);
		db.close();

		try {
			const proc = await bootServer(dir, 3592);
			await stopServer(proc);

			const after = new Database(join(dir, 'roeshare.db'));
			const cols = after.query('PRAGMA table_info(files)').all().map(c => c.name);
			expect(cols).toContain('sha256');
			const row = after.query('SELECT edit_token, e2e, view_count FROM shares WHERE id = ?').get('currentshare1');
			// Must NOT be double-hashed or otherwise touched.
			expect(row.edit_token).toBe(editHash);
			expect(row.e2e).toBe(1);
			expect(row.view_count).toBe(9);
			after.close();
		} finally {
			cleanupDir(dir);
		}
	});

	test('migrates a legacy pre-hardening database with no data loss', async () => {
		const dir = freshDataDir('legacy');
		mkdirSync(join(dir, 'storage', 'legacyshare1'), { recursive: true });
		writeFileSync(join(dir, 'storage', 'legacyshare1', 'legacyfile1'), 'hello');

		const db = new Database(join(dir, 'roeshare.db'), { create: true });
		db.exec(`
			CREATE TABLE shares (${SHARES_COLUMNS_LEGACY});
			CREATE TABLE files (${FILES_COLUMNS_LEGACY});
			CREATE TABLE api_keys (${API_KEYS_COLUMNS});
		`);
		const rawToken = 'LEGACYtoken1234567890abcdefghXY'; // 32 chars, ids.js's pre-hashing raw-token shape
		db.query(
			`INSERT INTO shares (id,title,created_at,expires_at,password_hash,max_downloads,one_time,edit_token,finalized,deleted_at,creator_ip,creator_ua,e2e,view_count,api_key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run('legacyshare1', 'old', Math.floor(Date.now() / 1000), null, null, null, 0, rawToken, 0, null, '127.0.0.1', 'test', 0, 0, null);
		db.query(
			'INSERT INTO files (id,share_id,name,size,received,mime,complete,download_count,created_at,stored_name,iv) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
		).run('legacyfile1', 'legacyshare1', 'old.txt', 5, 5, 'text/plain', 1, 0, Math.floor(Date.now() / 1000), 'legacyfile1', null);
		db.close();

		try {
			const proc = await bootServer(dir, 3593);
			try {
				// The sha256 column must now exist (the automatic column migration).
				const after = new Database(join(dir, 'roeshare.db'));
				const cols = after.query('PRAGMA table_info(files)').all().map(c => c.name);
				expect(cols).toContain('sha256');

				// The edit_token must be rehashed, but the ORIGINAL raw token the
				// client already holds must still authenticate as owner.
				const row = after.query('SELECT edit_token, length(edit_token) AS len FROM shares WHERE id = ?').get('legacyshare1');
				expect(row.len).toBe(64);
				expect(row.edit_token).not.toBe(rawToken);

				const meta = await fetch('http://127.0.0.1:3593/api/shares/legacyshare1', { headers: { 'X-Edit-Token': rawToken } });
				expect(meta.status).toBe(200);
				const body = await meta.json();
				expect(body.owner).toBe(true);

				// The file that was already on disk before the migration must still
				// be downloadable, byte for byte, through the same token.
				const dl = await fetch('http://127.0.0.1:3593/api/shares/legacyshare1/files/legacyfile1/download', {
					headers: { 'X-Edit-Token': rawToken },
				});
				expect(dl.status).toBe(200);
				expect(await dl.text()).toBe('hello');

				// A pre-migration backup must have been taken.
				const backups = readdirSync(join(dir, 'backups'));
				expect(backups.some(f => f.startsWith('pre-migration-'))).toBe(true);
				after.close();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	// F-03/F-18: files gained enc_version/key_id columns (a plain column
	// migration, defaulting existing rows to enc_version=1 - the legacy
	// unauthenticated AES-256-CTR format) and the at-rest HMAC/HKDF key
	// separation. Neither change may disturb a file that was already
	// encrypted under the OLD code path: this fixture writes a v1 CTR blob
	// exactly as the pre-change filecrypt.js would have (same key derivation
	// - scrypt(SECRET, 'roeshare-fs-key-v1') - and the same AES-256-CTR
	// construction), against a database missing the new columns entirely, and
	// asserts both that the column migration lands the correct default AND
	// that the file still decrypts correctly through the real download path.
	test('migrates a legacy database missing enc_version/key_id, and its existing v1 CTR-encrypted blob still decrypts correctly', async () => {
		const dir = freshDataDir('v1-encrypted');
		const port = 3620;
		const secret = `migration-test-secret-${port}`;
		const plaintext = Buffer.from('Legacy encrypted content, sealed by the OLD v1 AES-256-CTR path.');
		const ivHex = randomBytes(16).toString('hex');
		const v1Key = scryptSync(secret, 'roeshare-fs-key-v1', 32);
		const cipher = createCipheriv('aes-256-ctr', v1Key, Buffer.from(ivHex, 'hex'));
		const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

		mkdirSync(join(dir, 'storage', 'v1share1'), { recursive: true });
		writeFileSync(join(dir, 'storage', 'v1share1', 'v1file1'), ciphertext);

		const db = new Database(join(dir, 'roeshare.db'), { create: true });
		db.exec(`
			CREATE TABLE shares (${SHARES_COLUMNS_LEGACY});
			CREATE TABLE files (${FILES_COLUMNS_LEGACY}, sha256 TEXT);
			CREATE TABLE api_keys (${API_KEYS_COLUMNS});
		`);
		const rawToken = 'V1CTRtoken1234567890abcdefghijk'; // 32 chars, pre-hashing raw-token shape
		db.query(
			`INSERT INTO shares (id,title,created_at,expires_at,password_hash,max_downloads,one_time,edit_token,finalized,deleted_at,creator_ip,creator_ua,e2e,view_count,api_key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run('v1share1', 'v1 encrypted', Math.floor(Date.now() / 1000), null, null, null, 0, sha256Hex(rawToken), 0, null, '127.0.0.1', 'test', 0, 0, null);
		db.query(
			'INSERT INTO files (id,share_id,name,size,received,mime,complete,download_count,created_at,stored_name,iv,sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
		).run('v1file1', 'v1share1', 'secret.txt', plaintext.length, plaintext.length, 'text/plain', 1, 0, Math.floor(Date.now() / 1000), 'v1file1', ivHex, sha256Hex(plaintext));
		db.close();

		try {
			const proc = await bootServer(dir, port);
			try {
				// The new columns must exist, defaulted for this pre-existing row to
				// enc_version=1 (legacy CTR) / key_id=1 - never enc_version=2, which
				// would make storage.js try to parse this CTR blob as chunked GCM.
				const after = new Database(join(dir, 'roeshare.db'));
				const cols = after.query('PRAGMA table_info(files)').all().map(c => c.name);
				expect(cols).toContain('enc_version');
				expect(cols).toContain('key_id');
				const row = after.query('SELECT enc_version, key_id FROM files WHERE id = ?').get('v1file1');
				expect(row.enc_version).toBe(1);
				expect(row.key_id).toBe(1);
				after.close();

				// The pre-existing v1 CTR blob must still decrypt correctly end to end.
				const dl = await fetch(`http://127.0.0.1:${port}/api/shares/v1share1/files/v1file1/download`, {
					headers: { 'X-Edit-Token': rawToken },
				});
				expect(dl.status).toBe(200);
				const got = Buffer.from(await dl.arrayBuffer());
				expect(got.equals(plaintext)).toBe(true);

				// And a Range read of it (v1's seekable CTR path) must also stay correct.
				const rangeDl = await fetch(`http://127.0.0.1:${port}/api/shares/v1share1/files/v1file1/download`, {
					headers: { 'X-Edit-Token': rawToken, Range: 'bytes=8-19' },
				});
				expect(rangeDl.status).toBe(206);
				const gotRange = Buffer.from(await rangeDl.arrayBuffer());
				expect(gotRange.equals(plaintext.subarray(8, 20))).toBe(true);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a failed pre-migration backup leaves the live database untouched, logs an actionable error, and exits non-zero', async () => {
		const dir = freshDataDir('backup-fail');
		// Force backupBeforeMigrating() to throw: put a plain FILE where the backups
		// directory needs to go, so mkdirSync(BACKUP_DIR, { recursive: true }) fails
		// (stands in for an unwritable/read-only mounted backups directory).
		writeFileSync(join(dir, 'backups'), 'not a directory');

		const db = new Database(join(dir, 'roeshare.db'), { create: true });
		db.exec(`
			CREATE TABLE shares (${SHARES_COLUMNS_LEGACY});
			CREATE TABLE files (${FILES_COLUMNS_LEGACY});
			CREATE TABLE api_keys (${API_KEYS_COLUMNS});
		`);
		const rawToken = 'LEGACYtoken1234567890abcdefghXY';
		db.query(
			`INSERT INTO shares (id,title,created_at,expires_at,password_hash,max_downloads,one_time,edit_token,finalized,deleted_at,creator_ip,creator_ua,e2e,view_count,api_key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run('legacyshare1', 'old', Math.floor(Date.now() / 1000), null, null, null, 0, rawToken, 0, null, '127.0.0.1', 'test', 0, 0, null);
		db.close();

		try {
			const proc = Bun.spawn({
				cmd: [process.execPath, 'run', 'src/server.js'],
				cwd: ROOT,
				env: {
					...process.env,
					HOST: '127.0.0.1',
					PORT: '3599',
					DATA_DIR: dir,
					ADMIN_PASSWORD: 'MigrationTest-Pw-2026',
					SECRET: 'migration-test-secret-3599',
					UPLOAD_PASSWORD: 'migration-test-upload-pw',
					TRUST_PROXY: '0',
					BASE_URL: 'http://127.0.0.1:3599',
				},
				stdout: 'pipe',
				stderr: 'pipe',
			});

			await Promise.race([proc.exited, new Promise(r => setTimeout(r, 10_000))]);
			const stderr = await new Response(proc.stderr).text();
			await stopServer(proc);

			// Must die loudly (non-zero exit), not hang or silently boot degraded.
			expect(proc.exitCode).not.toBe(0);
			expect(proc.exitCode).not.toBeNull();
			expect(stderr).toContain('[migrate] FAILED');
			expect(stderr).toContain('live database was NOT modified');

			// The live database must be exactly as it was before boot: no column
			// migration and no edit_token rehash applied.
			const after = new Database(join(dir, 'roeshare.db'));
			const cols = after.query('PRAGMA table_info(files)').all().map(c => c.name);
			expect(cols).not.toContain('sha256');
			const row = after.query('SELECT edit_token FROM shares WHERE id = ?').get('legacyshare1');
			expect(row.edit_token).toBe(rawToken);
			after.close();
		} finally {
			cleanupDir(dir);
		}
	});

	test('running the same legacy migration twice is a no-op the second time', async () => {
		const dir = freshDataDir('legacy-twice');
		const db = new Database(join(dir, 'roeshare.db'), { create: true });
		db.exec(`
			CREATE TABLE shares (${SHARES_COLUMNS_LEGACY});
			CREATE TABLE files (${FILES_COLUMNS_LEGACY});
			CREATE TABLE api_keys (${API_KEYS_COLUMNS});
		`);
		const rawToken = 'LEGACYtoken1234567890abcdefghXY';
		db.query(
			`INSERT INTO shares (id,title,created_at,expires_at,password_hash,max_downloads,one_time,edit_token,finalized,deleted_at,creator_ip,creator_ua,e2e,view_count,api_key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run('legacyshare1', null, Math.floor(Date.now() / 1000), null, null, null, 0, rawToken, 0, null, '127.0.0.1', 'test', 0, 0, null);
		db.close();

		try {
			const proc1 = await bootServer(dir, 3594);
			await stopServer(proc1);
			const afterFirst = new Database(join(dir, 'roeshare.db'));
			const hashedOnce = afterFirst.query('SELECT edit_token FROM shares WHERE id = ?').get('legacyshare1').edit_token;
			afterFirst.close();

			const proc2 = await bootServer(dir, 3595);
			await stopServer(proc2);
			const afterSecond = new Database(join(dir, 'roeshare.db'));
			const hashedTwice = afterSecond.query('SELECT edit_token FROM shares WHERE id = ?').get('legacyshare1').edit_token;
			afterSecond.close();

			// A second boot must not rehash an already-hashed token.
			expect(hashedTwice).toBe(hashedOnce);
		} finally {
			cleanupDir(dir);
		}
	});
});
