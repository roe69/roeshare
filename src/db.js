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
// 0700: only this process's owner should ever read/write the storage volume -
// see storage.js's symlink/O_NOFOLLOW guards and DEPLOY.md's note on not
// sharing the volume writable with any other process/container.
mkdirSync(config.storageDir, { recursive: true, mode: 0o700 });

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
		// At-rest format marker. NULL iv = stored as plaintext / E2E (the sole
		// "no server crypto" signal, regardless of enc_version). Otherwise iv's
		// meaning depends on enc_version - v1: 16-byte AES-CTR IV (hex); v2:
		// 16-byte per-file HKDF salt (hex) - both 32 hex chars, disambiguated
		// only via enc_version, never by content. See lib/filecrypt.js.
		iv:             'TEXT',
		sha256:         'TEXT',                         // content digest of the plaintext; null until upload completes
		// At-rest format version: 1 = legacy unauthenticated AES-CTR (kept
		// forever, never migrated), 2 = authenticated per-chunk AES-GCM (every
		// new file). Existing rows default to 1, which is correct for them.
		enc_version:    'INTEGER NOT NULL DEFAULT 1',
		// Which lib/keys.js AT_REST_KEYS entry the file's v2 per-file key was
		// derived from (inert for v1/plaintext/E2E rows).
		key_id:         'INTEGER NOT NULL DEFAULT 1',
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
		// Operation-level scopes (F-06): a compromised key is limited to only the
		// operations it actually needs (e.g. a backup-writer key that can never
		// list/read/delete). DEFAULT 0 makes storage deny-by-default - a row that
		// somehow appears without explicit scope values can do nothing. Existing
		// (pre-scopes) keys are grandfathered to full access by the
		// 'grant-legacy-apikey-scopes' migration below; every key created after
		// scopes shipped gets explicit values from createApiKey/sanitizeLimits.
		scope_create:   'INTEGER NOT NULL DEFAULT 0',  // may create shares (POST /api/v1/shares, /upload)
		scope_write:    'INTEGER NOT NULL DEFAULT 0',  // may upload/register/finalize files
		scope_read:     'INTEGER NOT NULL DEFAULT 0',  // may list/inspect its shares, and read-owns them
		scope_delete:   'INTEGER NOT NULL DEFAULT 0',  // may delete its shares
	},
	// Small persistent key/value store, currently just for migration bookkeeping
	// (see MIGRATIONS below).
	meta: {
		key:   'TEXT PRIMARY KEY',
		value: 'TEXT',
	},
	// Single-row running total backing the atomic global storage quota (see
	// lib/quota.js). Counts LOGICAL (plaintext-declared) bytes - files.size -
	// not physical disk bytes, so it can be maintained purely from SQL without
	// touching the filesystem. used_bytes is the sum of `size` over complete
	// files of live (non-soft-deleted) shares; reserved_bytes is in-flight
	// uploads that have not finished yet (see storage_reservations below). The
	// CHECK pins this to exactly one row, updated in place.
	storage_ledger: {
		id:             'INTEGER PRIMARY KEY CHECK (id = 1)',
		used_bytes:     'INTEGER NOT NULL DEFAULT 0',
		reserved_bytes: 'INTEGER NOT NULL DEFAULT 0',
	},
	// One row per in-flight (not yet committed) upload, so a burst of concurrent
	// registrations can never together exceed MAX_TOTAL_SIZE even though none of
	// them individually would (the race lib/quota.js closes). share_id is
	// nullable: the api.js one-shot upload path reserves space before the share
	// row exists yet. A reservation is TTL'd (see lib/quota.js's
	// RESERVATION_TTL) and lazily reaped so an abandoned upload cannot pin
	// quota forever.
	storage_reservations: {
		file_id:    'TEXT PRIMARY KEY',
		share_id:   'TEXT',
		bytes:      'INTEGER NOT NULL',
		created_at: 'INTEGER NOT NULL',
		expires_at: 'INTEGER NOT NULL',
	},
	// Write-through persistence for the credential-brute-force rate-limit
	// buckets (see lib/ratelimit.js's PERSIST_PREFIXES) - lets those counters
	// survive a process restart/redeploy and eviction from the in-memory Map
	// under a flood of unrelated keys. key is the exact "<bucket>:<id>" string
	// the in-memory limiter uses; reset_at is epoch MILLISECONDS (matches the
	// in-memory resetAt exactly, NOT the epoch-seconds convention `now()` uses
	// elsewhere in this file).
	rate_limits: {
		key:      'TEXT PRIMARY KEY',
		count:    'INTEGER NOT NULL',
		reset_at: 'INTEGER NOT NULL',
	},
	// Durable journal for an in-flight admin share rename (F-19), so a crash
	// between the DB-side rename and the filesystem directory move is always
	// recoverable at the next boot rather than leaving the two split. A new
	// table, not a MIGRATIONS entry: the CREATE TABLE IF NOT EXISTS loop below
	// creates it on every install (fresh or existing) with no backfill needed.
	// See lib/renames.js for the state machine this backs.
	share_renames: {
		id:         'INTEGER PRIMARY KEY AUTOINCREMENT',
		old_id:     'TEXT NOT NULL',
		new_id:     'TEXT NOT NULL',
		// 'requested' | 'db_committed'. A finished rename DELETEs its row, so no
		// 'complete' state is ever stored.
		state:      "TEXT NOT NULL DEFAULT 'requested'",
		created_at: 'INTEGER NOT NULL',
		updated_at: 'INTEGER NOT NULL',
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
	CREATE INDEX IF NOT EXISTS idx_reservations_share ON storage_reservations(share_id);
	CREATE INDEX IF NOT EXISTS idx_reservations_expires ON storage_reservations(expires_at);
	CREATE INDEX IF NOT EXISTS idx_rate_limits_reset ON rate_limits(reset_at);
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
	{
		id: 'grant-legacy-apikey-scopes',
		// Keys minted before operation scopes existed implicitly held every scope;
		// grandfather them to full access so no key that works today breaks. Keys
		// created after this ships always get explicit scope values from
		// createApiKey, so this once-only blanket grant can never widen a
		// deliberately-restricted future key.
		run() {
			return db.query('UPDATE api_keys SET scope_create = 1, scope_write = 1, scope_read = 1, scope_delete = 1').run().changes;
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
	console.warn('[migrate] Pending schema/data migrations detected. Backing up and migrating now - THIS CAN TAKE SEVERAL MINUTES ON A LARGE DATABASE AND THE APP WILL NOT SERVE ANY REQUESTS (INCLUDING /health) UNTIL IT COMPLETES. DO NOT restart the container or re-run the deploy while this is in progress.');
	// Diagnostics wrapper only - it does not itself break the crash-loop. backupBeforeMigrating()
	// runs before either write step, so a failure caught here always means the live database was
	// NOT modified (applyColumns/applyMigrations, the only ALTER/UPDATE writes, never ran). We
	// still re-throw: a persistent disk/permission fault should keep failing loudly on every
	// restart rather than silently skip the backup and boot into an unmigrated/half-migrated db.
	try {
		backupBeforeMigrating();
		applyColumns(pendingCols);
		applyMigrations(pendingMigs);
	} catch (err) {
		console.error(`[migrate] FAILED - the live database was NOT modified (the pre-migration backup did not complete, or a migration step failed after it): ${err.message}`);
		console.error('[migrate] Most likely cause: DATA_DIR is full (VACUUM INTO needs room for a full copy of the database), or the backups directory is unwritable / a read-only mount.');
		console.error('[migrate] Free up disk space or fix the backups directory permissions, then restart the container to retry.');
		throw err;
	}
}
