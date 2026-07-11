// SQLite layer built on bun:sqlite (no native module to compile). Opens the db,
// applies the full schema, and migrates an existing installation forward. All
// timestamps are unix epoch seconds.
//
// Schema changes never require an operator to wipe their data (the deploy
// workflow's "reset data" option is for an intentional reset only, not for
// applying a schema change - see .github/workflows/deploy.yml). There are two
// kinds of migration:
//
//   1. A new column: just add it to the `schema` object below. migrateSchema()
//      diffs PRAGMA table_info() against this declaration on every boot and
//      issues ALTER TABLE ADD COLUMN for anything an existing installation is
//      missing - no extra code needed. (SQLite's ALTER TABLE can only add
//      columns - no PRIMARY KEY/UNIQUE, and a NOT NULL column needs a DEFAULT
//      other than NULL, since ALTER TABLE forbids NOT NULL with no default.)
//
//   2. Anything else - a rename, a backfill, a value-format change (like the
//      edit_token hashing below) - add a named entry to MIGRATIONS. Each one
//      runs exactly once, tracked in the `meta` table, in the order listed.
//      Never edit or reorder an entry that may already have run in
//      production; add a new one instead.
//
// Before either kind of migration changes anything, the live database is
// snapshotted to DATA_DIR/backups (pruned to the last few) via VACUUM INTO,
// so a migration bug is always recoverable from disk without an operator
// needing their own backup discipline.
//
// This whole path - a fresh install, an already-migrated database, and a
// legacy pre-migration one - is exercised by test/migrations.test.js on every
// push (see .github/workflows/publish.yml, which gates the published image on
// it passing). That suite is what should have caught the outage that made
// this migration system exist in the first place; run it (`bun test`) before
// shipping any change to `schema` or `MIGRATIONS`.

import { Database } from 'bun:sqlite';
import { mkdirSync, readdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { config } from './config.js';
import { hashSecretToken } from './lib/crypto.js';

mkdirSync(config.dataDir, { recursive: true });
mkdirSync(config.storageDir, { recursive: true });

export const db = new Database(config.dbPath, { create: true });

db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA busy_timeout = 5000;');
db.exec('PRAGMA synchronous = NORMAL;');

// Declared before the migration logic below, which needs it (markMigrationRan).
export const now = () => Math.floor(Date.now() / 1000);

const schema = {
	shares: {
		id:             'TEXT PRIMARY KEY',
		title:          'TEXT',
		created_at:     'INTEGER NOT NULL',
		expires_at:     'INTEGER',                    // null = never
		password_hash:  'TEXT',                       // null = public
		max_downloads:  'INTEGER',                    // null = unlimited (counts per share)
		download_count: 'INTEGER NOT NULL DEFAULT 0',
		one_time:       'INTEGER NOT NULL DEFAULT 0', // burn the whole share after first full download
		edit_token:     'TEXT NOT NULL',               // lets the uploader manage their own share
		finalized:      'INTEGER NOT NULL DEFAULT 0',
		deleted_at:     'INTEGER',                     // soft delete
		creator_ip:     'TEXT',
		creator_ua:     'TEXT',
		e2e:            'INTEGER NOT NULL DEFAULT 0',  // 1 = client-side end-to-end encrypted
		view_count:     'INTEGER NOT NULL DEFAULT 0',
		api_key_id:     'TEXT',                        // key that created it (null = web portal)
	},
	files: {
		id:             'TEXT PRIMARY KEY',
		share_id:       'TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE',
		name:           'TEXT NOT NULL',              // original (display) filename, sanitized
		size:           'INTEGER NOT NULL',           // declared total size in bytes
		received:       'INTEGER NOT NULL DEFAULT 0', // bytes written so far (resume offset)
		mime:           "TEXT NOT NULL DEFAULT 'application/octet-stream'",
		complete:       'INTEGER NOT NULL DEFAULT 0',
		download_count: 'INTEGER NOT NULL DEFAULT 0',
		created_at:     'INTEGER NOT NULL',
		stored_name:    'TEXT NOT NULL',               // on-disk blob name (== id), never the original
		iv:             'TEXT',                        // at-rest AES-CTR IV; null = stored as plaintext / E2E
		sha256:         'TEXT',                         // content digest of the plaintext; null until upload completes
	},
	download_events: {
		id:       'INTEGER PRIMARY KEY AUTOINCREMENT',
		share_id: 'TEXT NOT NULL',
		file_id:  'TEXT',
		ts:       'INTEGER NOT NULL',
		ip:       'TEXT',
		ua:       'TEXT',
	},
	// Lifetime counters that accumulate as events happen and are NEVER decremented,
	// so historical totals survive a share being expired, burned, or deleted.
	metrics: {
		key:   'TEXT PRIMARY KEY',
		value: 'INTEGER NOT NULL DEFAULT 0',
	},
	// Per-uploader (by IP) lifetime stats, likewise persistent across deletion.
	uploaders: {
		ip:         'TEXT PRIMARY KEY',
		shares:     'INTEGER NOT NULL DEFAULT 0',
		bytes:      'INTEGER NOT NULL DEFAULT 0',
		downloads:  'INTEGER NOT NULL DEFAULT 0',
		first_seen: 'INTEGER',
		last_seen:  'INTEGER',
	},
	// Programmatic-access credentials. Other servers/scripts present a bearer
	// token of the form rsk_<id>_<secret>; only a SHA-256 hash of the secret is
	// stored here, so the row is never enough to recover a usable key. The public
	// id is the lookup key and the recognizable prefix shown in the admin UI.
	api_keys: {
		id:             'TEXT PRIMARY KEY',           // public key id (the rsk_<id> prefix)
		name:           'TEXT NOT NULL',               // human label
		key_hash:       'TEXT NOT NULL',               // sha256(secret) hex; never the secret
		created_at:     'INTEGER NOT NULL',
		last_used_at:   'INTEGER',                     // null until first use
		expires_at:     'INTEGER',                     // null = never
		revoked_at:     'INTEGER',                     // null = active
		upload_count:   'INTEGER NOT NULL DEFAULT 0',  // shares created with this key
		bytes_uploaded: 'INTEGER NOT NULL DEFAULT 0',
		max_file_size:  'INTEGER',                     // per-file byte cap (null = server default)
		max_share_size: 'INTEGER',                     // per-share byte cap (null = server default)
		max_shares:     'INTEGER',                     // lifetime share cap (null = unlimited)
		max_expiry:     'INTEGER',                     // max share lifetime in seconds (null = no cap)
		allow_slug:     'INTEGER NOT NULL DEFAULT 1',  // may set custom share links
		allow_password: 'INTEGER NOT NULL DEFAULT 1',  // may set share passwords
	},
	// Small persistent key/value store, currently just for migration bookkeeping
	// (see MIGRATIONS below).
	meta: {
		key:   'TEXT PRIMARY KEY',
		value: 'TEXT',
	},
};

for (const [table, columns] of Object.entries(schema)) {
	const cols = Object.entries(columns).map(([name, def]) => `${name} ${def}`).join(',\n\t\t');
	db.exec(`CREATE TABLE IF NOT EXISTS ${table} (\n\t\t${cols}\n\t);`);
}

db.exec(`
	CREATE INDEX IF NOT EXISTS idx_files_share ON files(share_id);
	CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares(expires_at);
	CREATE INDEX IF NOT EXISTS idx_shares_apikey ON shares(api_key_id);
	CREATE INDEX IF NOT EXISTS idx_events_share ON download_events(share_id);
`);

const getMeta = db.query('SELECT value FROM meta WHERE key = ?');
const setMeta = db.query('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
const migrationRan = id => !!getMeta.get(`migration:${id}`);
const markMigrationRan = id => setMeta.run(`migration:${id}`, String(now()));

// ---- Column migrations (automatic - add columns to `schema` above) --------

function pendingColumns() {
	const pending = [];
	for (const [table, columns] of Object.entries(schema)) {
		const existing = new Set(db.query(`PRAGMA table_info(${table})`).all().map(c => c.name));
		for (const [name, def] of Object.entries(columns)) {
			if (!existing.has(name)) pending.push({ table, name, def });
		}
	}
	return pending;
}

function applyColumns(pending) {
	for (const { table, name, def } of pending) {
		db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${def}`);
		console.log(`  [migrate] added column ${table}.${name}`);
	}
}

// ---- Named migrations (manual - anything ADD COLUMN can't express) --------

const MIGRATIONS = [
	{
		id: 'rehash-legacy-edit-tokens',
		// Rehashes shares created before edit_token started being stored as a
		// SHA-256 hash rather than the raw token. hashSecretToken's output is
		// always a 64-char hex digest, so length alone tells the two formats
		// apart. The client still holds the original raw token from when their
		// share was created, so this is transparent to them.
		run() {
			const rows = db.query('SELECT id, edit_token FROM shares WHERE length(edit_token) != 64').all();
			const rehash = db.query('UPDATE shares SET edit_token = ? WHERE id = ?');
			for (const row of rows) rehash.run(hashSecretToken(row.edit_token), row.id);
			return rows.length;
		},
	},
];

function pendingMigrations() {
	return MIGRATIONS.filter(m => !migrationRan(m.id));
}

function applyMigrations(pending) {
	for (const m of pending) {
		const n = m.run();
		markMigrationRan(m.id);
		console.log(`  [migrate] ran '${m.id}'${typeof n === 'number' ? ` (${n} row${n === 1 ? '' : 's'})` : ''}`);
	}
}

// ---- Backup before migrating ------------------------------------------------

const BACKUP_DIR = join(config.dataDir, 'backups');
const KEEP_BACKUPS = 5;

// One consistent, compacted snapshot of the database as it was immediately
// before a migration touches it. VACUUM INTO (rather than copying the .db
// file directly) is safe regardless of the live WAL state - a plain file copy
// can miss committed-but-not-checkpointed WAL data or copy a torn file
// mid-write.
function backupBeforeMigrating() {
	mkdirSync(BACKUP_DIR, { recursive: true });
	const stamp = new Date().toISOString().replace(/[:.]/g, '-');
	const path = join(BACKUP_DIR, `pre-migration-${stamp}.db`);
	db.exec(`VACUUM INTO '${path.replace(/'/g, "''")}'`);
	console.log(`  [migrate] backed up database to ${path} before migrating`);

	const backups = readdirSync(BACKUP_DIR).filter(f => f.startsWith('pre-migration-')).sort();
	for (const f of backups.slice(0, Math.max(0, backups.length - KEEP_BACKUPS))) {
		unlinkSync(join(BACKUP_DIR, f));
	}
}

const pendingCols = pendingColumns();
const pendingMigs = pendingMigrations();
if (pendingCols.length || pendingMigs.length) {
	backupBeforeMigrating();
	applyColumns(pendingCols);
	applyMigrations(pendingMigs);
}
