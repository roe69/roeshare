// Atomic global storage quota (F-05). config.maxTotalSize used to be enforced
// by comparing a request's size against a 5s-TTL-cached totalUsage() disk
// walk (sharedTotalUsage() in routes/uploads.js) - a classic cached
// check-then-act race: several concurrent registrations can each read the
// same stale total, each individually pass, and together blow past the cap.
// It also could not account for an upload that was accepted but had not
// finished writing yet, so a burst of large in-flight uploads was invisible
// to the check entirely.
//
// This module replaces that with a single-row running total (storage_ledger)
// plus a reservation table (storage_reservations), maintained purely in SQL -
// see db.js for both tables. Every mutator below has two forms:
//
//   fooInTx(...)  - a plain sequence of prepared statements, safe to call
//                   from INSIDE a caller's own db.transaction() (so it is
//                   never ambiguous whether we are nesting a transaction).
//   foo(...)      - db.transaction(fooInTx), for standalone use.
//
// The ledger counts LOGICAL (plaintext-declared) bytes - files.size - not
// physical disk bytes: config.maxTotalSize is enforced against logical bytes.
// Actual disk usage exceeds this by the v2 at-rest format's small per-chunk
// framing overhead (~0.012%), which is accepted. storage.js's totalUsage()
// (a real recursive disk walk) remains as an independent physical-bytes
// cross-check for the admin dashboard and for reconcile() below - it is just
// no longer on the hot path.
import { config } from '../config.js';
import { db, now } from '../db.js';
import { audit } from './audit.js';

// Same clock as the abandoned-share sweeper (config.js) - deliberately, so a
// reservation for an upload that is still actively resuming/chunking never
// outlives the point at which the sweeper would otherwise consider the share
// abandoned anyway.
const RESERVATION_TTL = () => config.abandonedUploadTtl;

// ---- Lazy reap + reserve ----------------------------------------------------

const reapLedgerStmt = db.query(
	`UPDATE storage_ledger
	 SET reserved_bytes = MAX(0, reserved_bytes - (SELECT COALESCE(SUM(bytes), 0) FROM storage_reservations WHERE expires_at < ?))
	 WHERE id = 1`
);
const reapDeleteStmt = db.query('DELETE FROM storage_reservations WHERE expires_at < ?');
const getLedgerStmt = db.query('SELECT used_bytes, reserved_bytes FROM storage_ledger WHERE id = 1');
const insertReservationStmt = db.query(
	'INSERT INTO storage_reservations (file_id, share_id, bytes, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'
);
const addReservedStmt = db.query('UPDATE storage_ledger SET reserved_bytes = reserved_bytes + ? WHERE id = 1');

// Reserve `bytes` of quota for `fileId` (optionally attributed to `shareId`,
// null for the api.js one-shot path which reserves before the share row
// exists). Returns false (and reserves nothing) when the reservation would
// push used+reserved over config.maxTotalSize; true otherwise. Always
// creates the reservation row - even when maxTotalSize is 0/unlimited - so
// accounting stays uniform regardless of whether a cap is configured.
//
// Called from inside a caller's own db.transaction() (the fresh-read-then-
// write pattern uploads.js already uses for the per-share cap), so the
// lazy-reap + read + insert here can never interleave with another request's
// continuation - that is what closes the race.
export function reserveInTx(fileId, shareId, bytes) {
	const ts = now();
	// Lazy reaper: an abandoned reservation (upload that never finished within
	// RESERVATION_TTL) is dropped here, on the next reservation attempt that
	// happens to run after it expired, rather than needing its own timer.
	reapLedgerStmt.run(ts);
	reapDeleteStmt.run(ts);

	if (config.maxTotalSize > 0) {
		const ledger = getLedgerStmt.get() || { used_bytes: 0, reserved_bytes: 0 };
		if (ledger.used_bytes + ledger.reserved_bytes + bytes > config.maxTotalSize) {
			audit('quota.reservation.denied', { target: fileId, detail: { requestedBytes: bytes } });
			return false;
		}
	}

	insertReservationStmt.run(fileId, shareId ?? null, bytes, ts, ts + RESERVATION_TTL());
	addReservedStmt.run(bytes);
	return true;
}
export const reserve = db.transaction(reserveInTx);

// ---- Touch (keep a live multi-day upload's reservation alive) --------------

const touchStmt = db.query('UPDATE storage_reservations SET expires_at = ? WHERE file_id = ?');

// Called on every accepted chunk PATCH so a slow-but-live resumable upload's
// reservation is never reaped out from under it just because it is taking
// longer than RESERVATION_TTL to finish.
export function touchInTx(fileId) {
	touchStmt.run(now() + RESERVATION_TTL(), fileId);
}
export const touch = db.transaction(touchInTx);

// ---- Commit (reservation -> counted usage) ---------------------------------

const getReservationStmt = db.query('SELECT bytes FROM storage_reservations WHERE file_id = ?');
const deleteReservationByFileStmt = db.query('DELETE FROM storage_reservations WHERE file_id = ?');
const subReservedStmt = db.query('UPDATE storage_ledger SET reserved_bytes = MAX(0, reserved_bytes - ?) WHERE id = 1');
const addUsedStmt = db.query('UPDATE storage_ledger SET used_bytes = used_bytes + ? WHERE id = 1');

// Called exactly when a file transitions to complete. Releases the
// reservation (if one is still on record - it may already have been lazily
// reaped, in which case this only adds to used_bytes) and adds sizeBytes to
// used_bytes unconditionally. The MAX(0, ...) clamps in both this and every
// other mutator here mean a reaped-then-completed reservation can never drive
// reserved_bytes negative.
export function commitInTx(fileId, sizeBytes) {
	const r = getReservationStmt.get(fileId);
	if (r) {
		deleteReservationByFileStmt.run(fileId);
		subReservedStmt.run(r.bytes);
	}
	addUsedStmt.run(sizeBytes);
}
export const commit = db.transaction(commitInTx);

// ---- Release (failure / delete cleanup) ------------------------------------

const getFileForReleaseStmt = db.query('SELECT size, complete FROM files WHERE id = ?');
const subUsedStmt = db.query('UPDATE storage_ledger SET used_bytes = MAX(0, used_bytes - ?) WHERE id = 1');

// Releases whatever quota a single file is holding: its committed usage (if
// it was ever marked complete) and/or its still-open reservation (if any).
// Must work even when the files row does not exist yet - the api.js one-shot
// path reserves before inserting the file row, so its failure-cleanup path
// calls this with nothing in `files` to find; it then only releases the
// reservation.
export function releaseFileInTx(fileId) {
	const file = getFileForReleaseStmt.get(fileId);
	if (file && file.complete) subUsedStmt.run(file.size);
	const r = getReservationStmt.get(fileId);
	if (r) {
		deleteReservationByFileStmt.run(fileId);
		subReservedStmt.run(r.bytes);
	}
}
export const releaseFile = db.transaction(releaseFileInTx);

const sumCommittedByShareStmt = db.query('SELECT COALESCE(SUM(size), 0) AS total FROM files WHERE share_id = ? AND complete = 1');
const sumReservedByShareStmt = db.query('SELECT COALESCE(SUM(bytes), 0) AS total FROM storage_reservations WHERE share_id = ?');
const deleteReservationsByShareStmt = db.query('DELETE FROM storage_reservations WHERE share_id = ?');

// Releases every byte a share is holding - both its committed files' usage
// and any still-open reservations under it - in one shot.
//
// IDEMPOTENCY RULE (callers must follow this literally): call this exactly
// once per share, at the moment it transitions OUT of live - i.e. alongside
// the write that sets deleted_at from NULL, or a hard DELETE of a share whose
// deleted_at was still NULL - and never for a share that is already
// soft-deleted (its bytes were already released when it was soft-deleted).
// This matches reconcile() below, which counts only deleted_at IS NULL
// shares, so a share counted once here is never double-subtracted or missed.
export function releaseShareInTx(shareId) {
	const committed = sumCommittedByShareStmt.get(shareId).total;
	subUsedStmt.run(committed);
	const resv = sumReservedByShareStmt.get(shareId).total;
	deleteReservationsByShareStmt.run(shareId);
	subReservedStmt.run(resv);
}
export const releaseShare = db.transaction(releaseShareInTx);

// ---- Boot reconciliation ----------------------------------------------------

const initLedgerStmt = db.query('INSERT OR IGNORE INTO storage_ledger (id, used_bytes, reserved_bytes) VALUES (1, 0, 0)');
// Drops reservations whose file has already finished (now correctly counted
// in used_bytes instead) or whose file row has vanished entirely while it was
// still attributed to a share (e.g. a hard-deleted file/share that somehow
// missed its release call). A reservation for a still-incomplete file is
// deliberately KEPT - a resumable upload survives a server restart, so its
// reservation must too. A share_id-less reservation (the api.js one-shot
// path, which reserves before the file row exists) is also kept when its
// file has not appeared yet - it is still a legitimately in-flight request,
// not something reconcile() can distinguish from "abandoned" - the lazy
// reaper in reserveInTx()/its TTL is what eventually clears it.
const reapVanishedStmt = db.query(
	`DELETE FROM storage_reservations
	 WHERE file_id IN (SELECT id FROM files WHERE complete = 1)
	    OR file_id NOT IN (SELECT id FROM files) AND share_id IS NOT NULL`
);
const recomputeLedgerStmt = db.query(
	`UPDATE storage_ledger SET
		used_bytes = (SELECT COALESCE(SUM(f.size), 0) FROM files f JOIN shares s ON s.id = f.share_id WHERE f.complete = 1 AND s.deleted_at IS NULL),
		reserved_bytes = (SELECT COALESCE(SUM(bytes), 0) FROM storage_reservations)
	 WHERE id = 1`
);

// Authoritative recompute from the database itself, run once at boot (see
// server.js) so the ledger is self-initializing (no seed MIGRATIONS entry
// needed - the row is created here) and self-healing: a crash between a disk
// write and its ledger update, or any missed release call, is corrected at
// the next restart rather than silently diverging forever. Pure SQL
// aggregates over indexed columns, so this is milliseconds even on a large
// install - unlike the recursive disk walk (storage.js's totalUsage(), which
// remains as an independent physical-bytes cross-check on the admin
// dashboard) this replaces on the hot path.
export function reconcile() {
	const before = getLedgerStmt.get();
	db.transaction(() => {
		initLedgerStmt.run();
		reapVanishedStmt.run();
		recomputeLedgerStmt.run();
	})();
	const after = getLedgerStmt.get();
	if (!before || before.used_bytes !== after.used_bytes || before.reserved_bytes !== after.reserved_bytes) {
		console.log(
			`[quota] reconciled storage ledger: used_bytes ${before?.used_bytes ?? 0} -> ${after.used_bytes}, reserved_bytes ${before?.reserved_bytes ?? 0} -> ${after.reserved_bytes}`
		);
	}
}
