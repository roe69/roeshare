// SQLite layer built on bun:sqlite (no native module to compile). Opens the db,
// applies the schema, sets pragmatic pragmas, and exposes the connection plus a
// handful of helpers. All timestamps are unix epoch seconds.

import { Database } from 'bun:sqlite';
import { mkdirSync } from 'node:fs';
import { config } from './config.js';

mkdirSync(config.dataDir, { recursive: true });
mkdirSync(config.storageDir, { recursive: true });

export const db = new Database(config.dbPath, { create: true });

db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA busy_timeout = 5000;');
db.exec('PRAGMA synchronous = NORMAL;');

db.exec(`
	CREATE TABLE IF NOT EXISTS shares (
		id            TEXT PRIMARY KEY,
		title         TEXT,
		created_at    INTEGER NOT NULL,
		expires_at    INTEGER,                 -- null = never
		password_hash TEXT,                    -- null = public
		max_downloads INTEGER,                 -- null = unlimited (counts per share)
		download_count INTEGER NOT NULL DEFAULT 0,
		one_time      INTEGER NOT NULL DEFAULT 0, -- burn the whole share after first full download
		edit_token    TEXT NOT NULL,           -- lets the uploader manage their own share
		finalized     INTEGER NOT NULL DEFAULT 0,
		deleted_at    INTEGER,                 -- soft delete
		creator_ip    TEXT
	);

	CREATE TABLE IF NOT EXISTS files (
		id            TEXT PRIMARY KEY,
		share_id      TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
		name          TEXT NOT NULL,           -- original (display) filename, sanitized
		size          INTEGER NOT NULL,        -- declared total size in bytes
		received      INTEGER NOT NULL DEFAULT 0, -- bytes written so far (resume offset)
		mime          TEXT NOT NULL DEFAULT 'application/octet-stream',
		complete      INTEGER NOT NULL DEFAULT 0,
		download_count INTEGER NOT NULL DEFAULT 0,
		created_at    INTEGER NOT NULL,
		stored_name   TEXT NOT NULL            -- on-disk blob name (== id), never the original
	);

	CREATE TABLE IF NOT EXISTS download_events (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		share_id  TEXT NOT NULL,
		file_id   TEXT,
		ts        INTEGER NOT NULL,
		ip        TEXT,
		ua        TEXT
	);

	-- Lifetime counters that accumulate as events happen and are NEVER decremented,
	-- so historical totals survive a share being expired, burned, or deleted.
	CREATE TABLE IF NOT EXISTS metrics (
		key   TEXT PRIMARY KEY,
		value INTEGER NOT NULL DEFAULT 0
	);

	-- Per-uploader (by IP) lifetime stats, likewise persistent across deletion.
	CREATE TABLE IF NOT EXISTS uploaders (
		ip         TEXT PRIMARY KEY,
		shares     INTEGER NOT NULL DEFAULT 0,
		bytes      INTEGER NOT NULL DEFAULT 0,
		downloads  INTEGER NOT NULL DEFAULT 0,
		first_seen INTEGER,
		last_seen  INTEGER
	);

	CREATE INDEX IF NOT EXISTS idx_files_share ON files(share_id);
	CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares(expires_at);
	CREATE INDEX IF NOT EXISTS idx_events_share ON download_events(share_id);
`);

// Migrations for columns added after the initial release. SQLite has no
// "ADD COLUMN IF NOT EXISTS", so we attempt it and ignore the duplicate error.
for (const stmt of [
	'ALTER TABLE shares ADD COLUMN creator_ua TEXT',
	'ALTER TABLE files ADD COLUMN iv TEXT',
	'ALTER TABLE shares ADD COLUMN e2e INTEGER NOT NULL DEFAULT 0',
	'ALTER TABLE shares ADD COLUMN view_count INTEGER NOT NULL DEFAULT 0',
]) {
	try {
		db.exec(stmt);
	} catch {
		/* column already exists */
	}
}

// One-time seed of the lifetime tables from whatever shares already exist (live
// or soft-deleted), so the historical view is populated on the first run after
// this feature ships rather than starting empty. Detected by an empty `metrics`.
if (db.query('SELECT COUNT(*) AS n FROM metrics').get().n === 0) {
	const s = db.query('SELECT COUNT(*) AS shares, COALESCE(SUM(view_count),0) AS views, COALESCE(SUM(download_count),0) AS downloads FROM shares').get();
	const f = db.query('SELECT COUNT(*) AS files, COALESCE(SUM(size),0) AS bytes FROM files').get();
	const set = db.query('INSERT INTO metrics(key, value) VALUES (?, ?)');
	const seed = db.transaction(() => {
		set.run('shares_created', s.shares);
		set.run('files_uploaded', f.files);
		set.run('bytes_uploaded', f.bytes);
		set.run('downloads', s.downloads);
		set.run('views', s.views);
		db.query(`INSERT INTO uploaders(ip, shares, bytes, downloads, first_seen, last_seen)
			SELECT COALESCE(s.creator_ip, 'unknown'), COUNT(DISTINCT s.id),
				COALESCE(SUM(sz.total), 0), COALESCE(SUM(s.download_count), 0),
				MIN(s.created_at), MAX(s.created_at)
			FROM shares s LEFT JOIN (SELECT share_id, SUM(size) AS total FROM files GROUP BY share_id) sz ON sz.share_id = s.id
			GROUP BY COALESCE(s.creator_ip, 'unknown')`).run();
	});
	seed();
}

export const now = () => Math.floor(Date.now() / 1000);
