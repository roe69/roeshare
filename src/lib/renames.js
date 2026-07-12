// F-19: a share rename (admin-set custom slug) touches two independent
// systems - a SQLite transaction (copy the row under the new id, repoint
// files/download_events, drop the old row) and a filesystem directory rename
// (storage.js's renameShareDir) - and a crash between the two used to leave
// them split: the DB pointing at the new id while the blobs still sat under
// the old id's directory, 404ing every file until an admin noticed and
// hand-fixed it on disk.
//
// The fix is a durable journal (the share_renames table - see db.js's
// schema) written BEFORE either side changes, flipped to 'db_committed'
// ATOMICALLY with the DB-side rename (same transaction), and only deleted
// once the filesystem side finishes too. At any point in time the journal
// tells you exactly how far a rename got:
//
//   (no row)       - nothing in flight, or a rename fully completed
//   'requested'    - intent recorded, but the DB transaction never committed
//                    (crash before/during it) - nothing happened, safe to drop
//   'db_committed' - the DB is authoritative and already points at new_id;
//                    the directory move may or may not have happened yet
//
// reconcileShareRenames() (called once at boot - see server.js, right after
// quota.reconcile(), which this mirrors) rolls any leftover 'db_committed'
// row forward by finishing the directory move. It never rolls the DB back:
// by the time that state is reached the DB transaction has already committed
// and IS the truth - recovery here is always roll-forward.
import { existsSync } from 'node:fs';
import { db, now } from '../db.js';
import { shareDir, renameShareDir } from './storage.js';
import { audit } from './audit.js';

// Thrown by performShareRename when another rename is already running.
// Exported so the route can recognize it and answer 409 instead of 500.
export const BUSY = Symbol('rename-in-progress');

// Single global maintenance lock. This app is a single-instance deployment
// (no distributed locking) - a plain module-level flag is enough to keep two
// concurrent admin rename requests from interleaving their transactions.
let renameInFlight = false;

// Non-atomic-window guard: rename-then-fs-move (see below) has a gap, between
// the DB transaction committing and renameShareDir() finishing, where a
// download/preview request for either id would hit storage.js against a
// directory that is momentarily absent (old id) or not yet populated (new
// id) - a fabricated empty 200 for a legacy (v1/plaintext) blob, or an
// uncaught mid-stream failure for a v2 blob. Populated with both ids right
// when a rename starts and cleared in the same `finally` as renameInFlight,
// so isRenamePending() below lets the read routes (routes/download.js) refuse
// with a 503 instead of touching storage during that window. Separate from
// renameInFlight, which only serializes concurrent admin rename REQUESTS.
const inFlightIds = new Set();

// Row copy + children repoint + old row delete + journal flip to
// 'db_committed', all inside ONE transaction, so the DB-side rename can never
// commit without the journal atomically recording it as done - that
// atomicity is the entire point (see the module comment above). Unchanged
// from the version this replaces (formerly routes/admin.js's `renameShare`),
// extended only with the trailing journal UPDATE.
const renameShareTx = db.transaction((oldId, newId, jid) => {
	db.query(
		`INSERT INTO shares (id, title, created_at, expires_at, password_hash, max_downloads, download_count, one_time, edit_token, finalized, deleted_at, creator_ip, creator_ua, api_key_id, e2e, view_count)
		 SELECT ?, title, created_at, expires_at, password_hash, max_downloads, download_count, one_time, edit_token, finalized, deleted_at, creator_ip, creator_ua, api_key_id, e2e, view_count FROM shares WHERE id = ?`,
	).run(newId, oldId);
	db.query('UPDATE files SET share_id = ? WHERE share_id = ?').run(newId, oldId);
	db.query('UPDATE download_events SET share_id = ? WHERE share_id = ?').run(newId, oldId);
	db.query('DELETE FROM shares WHERE id = ?').run(oldId);
	db.query("UPDATE share_renames SET state = 'db_committed', updated_at = ? WHERE id = ?").run(now(), jid);
});

const insertJournalStmt = db.query(
	"INSERT INTO share_renames (old_id, new_id, state, created_at, updated_at) VALUES (?, ?, 'requested', ?, ?)",
);
const deleteJournalStmt = db.query('DELETE FROM share_renames WHERE id = ?');
const allJournalStmt = db.query('SELECT * FROM share_renames ORDER BY id');

// Moves a share from oldId to newId end to end: durable intent, then the DB
// side (atomic with the journal flip), then the filesystem side. Throws BUSY
// (never rejects with it - throws synchronously before any await) if another
// rename is already in flight.
export async function performShareRename(oldId, newId) {
	if (renameInFlight) throw BUSY;
	renameInFlight = true;
	inFlightIds.add(oldId);
	inFlightIds.add(newId);
	try {
		// Durable intent recorded BEFORE any state changes.
		const ts = now();
		const jid = insertJournalStmt.run(oldId, newId, ts, ts).lastInsertRowid;

		// DB side: row copy + repoint + old row delete + journal flip, atomic.
		renameShareTx(oldId, newId, jid);

		// Filesystem side. If this throws (disk error, not a crash) the DB has
		// already committed and IS authoritative - never roll it back. Leave the
		// journal row at 'db_committed' so reconcileShareRenames() finishes the
		// move on the next boot, and rethrow so the route surfaces the deferred
		// state to the caller instead of claiming success.
		try {
			await renameShareDir(oldId, newId);
		} catch (e) {
			console.error(`[rename] filesystem move failed for ${oldId} -> ${newId}; DB already committed, a restart will finish moving files:`, e);
			audit('share.rename.fs_deferred', { target: `${oldId}->${newId}` });
			throw e;
		}

		// Completion is row removal - no 'complete' state is ever persisted, so
		// the journal only ever contains in-flight work.
		deleteJournalStmt.run(jid);
	} finally {
		renameInFlight = false;
		inFlightIds.delete(oldId);
		inFlightIds.delete(newId);
	}
}

// Whether `id` (old or new side) is part of a rename that has not fully
// finished yet - either still running in this process (inFlightIds), or left
// mid-flight by a crash (a 'db_committed' journal row - see the module
// comment above; reconcileShareRenames() clears it at the next boot, so this
// is the fs-failure/pre-restart safety net the in-memory set alone can't
// cover). Checked by routes/download.js before any storage.js call.
export function isRenamePending(id) {
	if (inFlightIds.has(id)) return true;
	return allJournalStmt.all().some(r => r.old_id === id || r.new_id === id);
}

// Rolls forward any rename journal rows left behind by a crash. Called once
// at boot (see server.js), before the server accepts any request, so no
// request can race a half-finished rename. The whole pass is idempotent - a
// crash mid-reconcile just re-runs it on the next boot.
export async function reconcileShareRenames() {
	for (const row of allJournalStmt.all()) {
		if (row.state === 'requested') {
			// The DB transaction never committed (the flip to 'db_committed' lives
			// inside it) - nothing happened. The intent record is stale; drop it.
			deleteJournalStmt.run(row.id);
			continue;
		}

		// 'db_committed': the DB already points at new_id. Roll the filesystem
		// forward to match.
		const from = shareDir(row.old_id);
		const to = shareDir(row.new_id);
		if (existsSync(from) && !existsSync(to)) {
			await renameShareDir(row.old_id, row.new_id);
		} else if (existsSync(from) && existsSync(to)) {
			// A POSIX rename onto a non-empty directory fails anyway, so this is
			// never attempted. Needs a human: shareDir(old_id) is an orphaned
			// leftover next to the (already correct) new directory.
			console.error(`[rename] orphaned leftover directory needs manual attention: ${from} (share already renamed to '${row.new_id}' in the database)`);
		}
		// Else: the old dir is already absent - either the share had no blobs, or
		// the move already happened before the crash. Either way, already done.

		deleteJournalStmt.run(row.id);
	}
}
