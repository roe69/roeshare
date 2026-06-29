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
]) {
	try {
		db.exec(stmt);
	} catch {
		/* column already exists */
	}
}

export const now = () => Math.floor(Date.now() / 1000);
