// SQLite layer built on bun:sqlite (no native module to compile). Opens the db,
// applies the full schema, sets pragmatic pragmas, and exposes the connection
// plus a couple of helpers. All timestamps are unix epoch seconds.
//
// The schema below is declared once, as data, and used for two things: (1)
// CREATE TABLE IF NOT EXISTS, which is a no-op against a table that already
// exists on disk, and (2) migrateSchema() below, which diffs PRAGMA
// table_info() for each table against this same declaration and issues
// ALTER TABLE ADD COLUMN for anything an existing installation is missing.
// That second step is what makes it safe to add a column here - relying on
// the CREATE TABLE block alone only reaches a brand-new DATA_DIR, and
// shipping a schema change with no matching migration for existing
// installations is exactly what caused a production outage previously.
// Every new column added below MUST be something SQLite can ADD COLUMN in
// place (no PRIMARY KEY/UNIQUE, and a NOT NULL column needs a DEFAULT other
// than NULL, since ALTER TABLE forbids NOT NULL with no default).

import { Database } from 'bun:sqlite';
import { mkdirSync } from 'node:fs';
import { config } from './config.js';
import { hashSecretToken } from './lib/crypto.js';

mkdirSync(config.dataDir, { recursive: true });
mkdirSync(config.storageDir, { recursive: true });

export const db = new Database(config.dbPath, { create: true });

db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA busy_timeout = 5000;');
db.exec('PRAGMA synchronous = NORMAL;');

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

// Diffs the declared schema above against what actually exists on disk for
// each table and ALTER TABLE ADD COLUMNs anything missing. Idempotent and
// cheap to run on every boot: a table whose columns already match (a brand
// new DATA_DIR right after the CREATE TABLE block above, or any install
// that's already been migrated) does nothing.
function migrateSchema() {
	for (const [table, columns] of Object.entries(schema)) {
		const existing = new Set(db.query(`PRAGMA table_info(${table})`).all().map(c => c.name));
		for (const [name, def] of Object.entries(columns)) {
			if (!existing.has(name)) {
				db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${def}`);
			}
		}
	}
}
migrateSchema();

// Rehashes shares created before edit_token started being stored as a
// SHA-256 hash rather than the raw token. Idempotent and safe on every boot:
// hashSecretToken's output is always a 64-char hex digest, so length alone
// tells the two formats apart, and once a row is rehashed it's excluded on
// the next run. The client still holds the original raw token from when
// their share was created, so this is transparent to them.
const legacyEditTokens = db.query('SELECT id, edit_token FROM shares WHERE length(edit_token) != 64').all();
if (legacyEditTokens.length) {
	const rehashEditToken = db.query('UPDATE shares SET edit_token = ? WHERE id = ?');
	for (const row of legacyEditTokens) rehashEditToken.run(hashSecretToken(row.edit_token), row.id);
}

export const now = () => Math.floor(Date.now() / 1000);
