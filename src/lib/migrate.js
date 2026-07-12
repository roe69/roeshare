// M-06: automatic, transparent v1 (AES-256-CTR, unauthenticated) -> v2
// (AES-256-GCM, per-chunk authenticated) at-rest migration. See
// lib/filecrypt.js's module comment for the two formats and
// lib/storage.js's M-06 section for the on-disk temp/backup helpers this
// module drives.
//
// Non-negotiable invariant: the original v1 bytes are NEVER deleted or
// overwritten until a full v2 re-encryption of them has been written, read
// back end to end, and cryptographically verified to reproduce the exact
// same plaintext (length, and sha256 when known). Any failure at any step
// aborts, leaves the v1 file and its DB row completely untouched, and is
// only ever logged - a file already stuck on the legacy format never
// becomes MORE inaccessible because of this module.
//
// Triggers (never require an operator to do anything):
//   - Lazy: download.js schedules a migration for a v1 file right after
//     handing its response stream to the client - fire-and-forget, adds no
//     latency to that request.
//   - Sweep: sweepMigrations() (started once at boot, then on a slow timer -
//     see server.js) walks enc_version=1 rows so even a file nobody ever
//     reads again still converges.
//
// Two separate in-process guards coordinate this with concurrent readers:
//   - `inProgress` dedupes a lazy trigger and the sweep landing on the same
//     file at once; held for the WHOLE migration (re-encrypt, verify, swap).
//   - `swapLock` is held only for the risky rename+rename+UPDATE window
//     (steps 4-6 below) - download.js's read path awaits this (via
//     awaitFileMigration) before opening a blob it already fetched as v1,
//     so a read can never race the moment the row's format and the bytes on
//     disk briefly disagree. It is NOT held during the (potentially slow,
//     for a large file) re-encrypt/verify steps, so a concurrent read of a
//     file mid-migration is never slowed down - only the final swap is
//     synchronized.
//
// Crash recovery (reconcileMigrations, called once at boot before the sweep
// starts - see server.js) makes the whole thing self-healing across a
// restart: it walks the filesystem for leftover '-mig'/'-v1' siblings and
// reconciles each against the DB-is-truth row, per the state table in each
// branch below.

import { open, rename, unlink, readdir, statfs } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { Readable } from 'node:stream';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { db } from '../db.js';
import { config } from '../config.js';
import { audit } from './audit.js';
import {
	shareDir,
	blobPath,
	isCleanupPending,
	migrationTempPath,
	migrationBackupPath,
	openMigrationTemp,
	fsyncDir,
	assertRealFileIfExists,
	withFileLock,
	O_NOFOLLOW,
	O_RDONLY,
} from './storage.js';
import { decryptStream, sealRecordV2, openRecordV2, newFileSalt, fileKeyForV2, PLAIN_CHUNK, RECORD_OVERHEAD } from './filecrypt.js';
import { CURRENT_AT_REST_KEY_ID } from './keys.js';

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- in-process coordination -----------------------------------------------

const inProgress = new Set(); // fileId currently running the whole migration (dedup lazy+sweep)
const swapLock = new Map(); // fileId -> Promise, held only during the rename/UPDATE swap window
// Files whose verify step found a sha256 mismatch - i.e. the v1 blob is
// itself already corrupt on disk, not a bug in this migration. Deterministic
// across retries, so the sweep must not retry-loop it forever; scoped to
// this process's lifetime (a restart gets a fresh chance, matching every
// other best-effort in-memory guard in this codebase, e.g. storage.js's
// cleanupPending).
const failedSkip = new Set();

// Awaited by a reader (download.js) that already fetched a file row as v1,
// right before it opens the blob - so it never races the swap window. Only
// resolves non-trivially while a migration for this exact file is actually
// in the swap window; the common case (no migration in flight) returns
// `false` immediately with no extra work.
export async function awaitFileMigration(fileId) {
	const pending = swapLock.get(fileId);
	if (!pending) return false;
	await pending;
	return true;
}

// Fire-and-forget entry point for the lazy trigger.
export function scheduleMigration(fileId) {
	migrateFile(fileId).catch(e => console.error('[migrate] background migration failed for', fileId, ':', e));
}

// ---- queries ----------------------------------------------------------------

const getMigratable = db.query('SELECT * FROM files WHERE id = ? AND enc_version = 1 AND iv IS NOT NULL AND complete = 1');
const getRowByIdAndShare = db.query('SELECT id, share_id, enc_version FROM files WHERE id = ?');
const sweepSelect = db.query('SELECT id, share_id, size, sha256, key_id FROM files WHERE enc_version = 1 AND iv IS NOT NULL AND complete = 1 LIMIT ?');
const countRemaining = db.query('SELECT COUNT(*) AS n FROM files WHERE enc_version = 1 AND iv IS NOT NULL AND complete = 1');
const promoteStmt = db.query('UPDATE files SET enc_version = 2, iv = ?, key_id = ? WHERE id = ? AND enc_version = 1');

async function safeUnlink(path) {
	try {
		await unlink(path);
	} catch (e) {
		if (e.code !== 'ENOENT') console.error('[migrate] cleanup unlink failed for', path, ':', e);
	}
}

// ---- record layout (mirrors storage.js's v2 write path: every record is
// exactly PLAIN_CHUNK plaintext bytes except the last) -----------------------

function recordLayout(size) {
	if (size <= 0) return [];
	const n = Math.ceil(size / PLAIN_CHUNK);
	const layout = [];
	for (let i = 0; i < n; i++) {
		const plainLen = i === n - 1 ? size - i * PLAIN_CHUNK : PLAIN_CHUNK;
		layout.push({ chunkIndex: i, diskStart: i * (PLAIN_CHUNK + RECORD_OVERHEAD), plainLen });
	}
	return layout;
}

// ---- step 2: re-encrypt the v1 plaintext to a sibling v2 temp --------------

async function reencryptToTemp(origPath, tempPath, row, newKey) {
	assertRealFileIfExists(origPath);
	const src = Readable.toWeb(createReadStream(origPath));
	const plain = decryptStream(row.iv, 0, src);
	const reader = plain.getReader();

	const fh = await openMigrationTemp(tempPath);
	try {
		let buffered = Buffer.alloc(0);
		let chunkIndex = 0;
		let diskPos = 0;
		let sourceDone = false;
		while (!sourceDone) {
			const { value, done } = await reader.read();
			if (done) sourceDone = true;
			else buffered = Buffer.concat([buffered, Buffer.from(value)]);

			while (buffered.length >= PLAIN_CHUNK || (sourceDone && buffered.length > 0)) {
				const take = Math.min(buffered.length, PLAIN_CHUNK);
				const piece = buffered.subarray(0, take);
				const record = sealRecordV2(newKey, CURRENT_AT_REST_KEY_ID, row.id, chunkIndex, piece);
				await fh.write(record, 0, record.length, diskPos);
				diskPos += record.length;
				chunkIndex++;
				buffered = buffered.subarray(take);
			}
		}
		await fh.sync();
	} finally {
		await fh.close();
	}
	await fsyncDir(shareDir(row.share_id));
}

// ---- step 3: verify by read-back, end to end -------------------------------

async function verifyTemp(tempPath, row, newKey) {
	assertRealFileIfExists(tempPath);
	const layout = recordLayout(row.size);
	const hash = createHash('sha256');
	let total = 0;

	const fh = await open(tempPath, O_RDONLY | O_NOFOLLOW);
	try {
		for (const rec of layout) {
			const recLen = RECORD_OVERHEAD + rec.plainLen;
			const buf = Buffer.alloc(recLen);
			const { bytesRead } = await fh.read(buf, 0, recLen, rec.diskStart);
			if (bytesRead !== recLen) {
				const err = new Error(`short read of record ${rec.chunkIndex} (expected ${recLen} bytes, got ${bytesRead})`);
				err.stage = 'verify';
				throw err;
			}
			let plain;
			try {
				plain = openRecordV2(newKey, CURRENT_AT_REST_KEY_ID, row.id, rec.chunkIndex, buf);
			} catch (e) {
				e.stage = 'verify';
				throw e;
			}
			hash.update(plain);
			total += plain.length;
		}
		const st = await fh.stat();
		const expectedDiskSize = layout.length ? layout[layout.length - 1].diskStart + RECORD_OVERHEAD + layout[layout.length - 1].plainLen : 0;
		if (st.size !== expectedDiskSize) {
			const err = new Error(`unexpected temp file size (disk ${st.size}, expected ${expectedDiskSize})`);
			err.stage = 'verify';
			throw err;
		}
	} finally {
		await fh.close();
	}

	if (total !== row.size) {
		const err = new Error(`plaintext length mismatch (recovered ${total}, expected ${row.size})`);
		err.stage = 'verify';
		throw err;
	}
	if (row.sha256) {
		const digest = hash.digest('hex');
		if (digest !== row.sha256) {
			const err = new Error('sha256 mismatch - likely pre-existing v1 disk corruption, not a migration bug');
			err.stage = 'sha256_mismatch';
			throw err;
		}
	}
	return { recordCount: layout.length };
}

// ---- the whole per-file state machine ---------------------------------------

async function migrateFile(fileId) {
	if (inProgress.has(fileId) || failedSkip.has(fileId)) return;
	inProgress.add(fileId);
	try {
		// 1. Re-check the row.
		const row = getMigratable.get(fileId);
		if (!row) return; // no longer eligible: deleted, already v2, incomplete, or E2E/plaintext
		if (isCleanupPending(row.share_id)) return;

		const origPath = blobPath(row.share_id, fileId);
		const tempPath = migrationTempPath(row.share_id, fileId);
		const backupPath = migrationBackupPath(row.share_id, fileId);
		const newSalt = newFileSalt();
		const newKey = fileKeyForV2(fileId, newSalt, CURRENT_AT_REST_KEY_ID);
		const startedAt = Date.now();

		// 2. Re-encrypt to a sibling temp.
		try {
			await reencryptToTemp(origPath, tempPath, row, newKey);
		} catch (e) {
			await safeUnlink(tempPath);
			audit('file.migrate_failure', { target: fileId, detail: { stage: 'reseal', error: String(e?.message || e) } });
			return;
		}

		// 3. Verify by read-back.
		let verified;
		try {
			verified = await verifyTemp(tempPath, row, newKey);
		} catch (e) {
			await safeUnlink(tempPath);
			const stage = e?.stage || 'verify';
			audit('file.migrate_failure', { target: fileId, detail: { stage, error: String(e?.message || e) } });
			if (stage === 'sha256_mismatch') {
				failedSkip.add(fileId);
				console.warn(`[migrate] WARNING: file ${fileId} failed sha256 verification during v1->v2 migration - this means the existing v1 ciphertext is already corrupt on disk, not a bug in the migration. Left on v1 (still readable via the original path); will not be retried this run.`);
			}
			return;
		}

		// 4-6. The atomic swap: preserve the original, promote the temp, flip
		// the DB row - all under withFileLock (mutual exclusion with an admin
		// per-file delete for this exact file id) and swapLock (so a concurrent
		// reader that already holds a v1 row waits here rather than racing it -
		// see awaitFileMigration / download.js's resolveFile()).
		const swapSucceeded = await withFileLock(fileId, async () => {
			// Re-check eligibility now that the lock is held: step 1's checks ran
			// before the (potentially slow, for a large file) re-encrypt/verify
			// above, so a per-file admin delete (blocked on this same lock) or a
			// whole-share delete (isCleanupPending) may have landed since then.
			// Catching it here - immediately before any filesystem mutation, not
			// just once at the start - is what closes the TOCTOU: a delete that
			// already committed is never raced by a swap recreating the blob
			// underneath it, and a delete that arrives after this check simply
			// queues behind this lock holder and finds nothing left to delete.
			if (isCleanupPending(row.share_id) || !getMigratable.get(fileId)) {
				await safeUnlink(tempPath);
				audit('file.migrate_failure', { target: fileId, detail: { stage: 'deleted_concurrently' } });
				return false;
			}

			let releaseSwap;
			swapLock.set(fileId, new Promise(res => { releaseSwap = res; }));
			try {
				// 4. Preserve the original (rename, never delete/overwrite).
				try {
					await rename(origPath, backupPath);
				} catch (e) {
					await safeUnlink(tempPath);
					audit('file.migrate_failure', { target: fileId, detail: { stage: 'rename', error: String(e?.message || e) } });
					return false;
				}

				// 5. Promote the temp, then flip enc_version/iv/key_id atomically.
				try {
					await rename(tempPath, origPath);
				} catch (e) {
					// Roll straight back: the temp never landed, restore the original
					// from its backup so v1 access is never interrupted.
					try {
						await rename(backupPath, origPath);
					} catch (e2) {
						console.error('[migrate] CRITICAL: failed to restore v1 original for', fileId, 'after a failed promote - manual recovery needed:', e2);
					}
					audit('file.migrate_failure', { target: fileId, detail: { stage: 'rename', error: String(e?.message || e) } });
					return false;
				}
				await fsyncDir(shareDir(row.share_id));

				const changed = promoteStmt.run(newSalt, CURRENT_AT_REST_KEY_ID, fileId).changes;
				if (changed !== 1) {
					// Lost race (row is no longer enc_version=1 - e.g. deleted between
					// step 1's recheck and here). Roll the filesystem back to match the
					// untouched row: move the just-promoted v2 bytes aside, restore v1
					// as canonical, discard the orphaned v2 bytes.
					try {
						await rename(origPath, tempPath);
						await rename(backupPath, origPath);
						await safeUnlink(tempPath);
					} catch (e2) {
						console.error('[migrate] CRITICAL: failed to roll back a lost-race promote for', fileId, '- manual recovery needed:', e2);
					}
					audit('file.migrate_failure', { target: fileId, detail: { stage: 'db' } });
					return false;
				}

				// 6. Only now, with the DB committed, drop the backup.
				await safeUnlink(backupPath);
				return true;
			} finally {
				swapLock.delete(fileId);
				releaseSwap();
			}
		});
		if (!swapSucceeded) return;

		audit('file.migrate_success', {
			target: fileId,
			detail: { bytes: row.size, records: verified.recordCount, ms: Date.now() - startedAt },
		});
	} finally {
		inProgress.delete(fileId);
	}
}

// ---- crash recovery (startup, before the sweep) ----------------------------

// Deterministic, DB-is-truth reconciliation over readdir - see the module
// comment's state table. Called once at boot, before the server accepts any
// request (mirrors lib/renames.js's reconcileShareRenames, which this is
// modeled on).
export async function reconcileMigrations() {
	let shareDirs;
	try {
		shareDirs = await readdir(config.storageDir, { withFileTypes: true });
	} catch {
		return;
	}
	for (const d of shareDirs) {
		if (!d.isDirectory()) continue;
		const shareId = d.name;
		let entries;
		try {
			entries = await readdir(join(config.storageDir, shareId), { withFileTypes: true });
		} catch {
			continue;
		}
		for (const f of entries) {
			if (!f.isFile()) continue;
			if (f.name.endsWith('-mig')) {
				await reconcileLeftover(shareId, f.name.slice(0, -4), 'mig');
			} else if (f.name.endsWith('-v1')) {
				await reconcileLeftover(shareId, f.name.slice(0, -3), 'v1');
			} else if (!f.name.includes('-')) {
				// A bare blob (no '-mig'/'-v1' suffix - the storage-path convention
				// migrated content, and only migrated content, ever uses; see
				// storage.js's migrationTempPath/migrationBackupPath and the module
				// comment there noting real file ids (lib/ids.js) never contain '-').
				// Cross-reference it against the files table: with no matching row at
				// all, it is the permanent-leak case a delete racing migrateFile's
				// swap can produce (see withFileLock in storage.js) - orphaned bytes
				// with nothing in the DB ever pointing at them, invisible to a plain
				// '-mig'/'-v1' scan. Best-effort: never let one bad entry abort the
				// rest of the reconcile pass.
				try {
					await reconcileOrphanBlob(shareId, f.name);
				} catch (e) {
					console.error(`[migrate] failed to reconcile possible orphan blob ${shareId}/${f.name}:`, e);
				}
			}
		}
	}
}

async function reconcileLeftover(shareId, fileId, kind) {
	const row = getRowByIdAndShare.get(fileId);
	const migPath = blobPath(shareId, `${fileId}-mig`);
	const v1Path = blobPath(shareId, `${fileId}-v1`);
	const origPath = blobPath(shareId, fileId);

	if (row && row.share_id !== shareId) {
		// The row exists but claims a different share - something else is
		// already wrong (e.g. an interrupted admin rename). Never guess; leave
		// it for manual attention rather than touching a file whose identity
		// doesn't match what the DB says.
		console.error(`[migrate] leftover ${kind === 'mig' ? migPath : v1Path} belongs to file ${fileId}, but the DB row's share is '${row.share_id}', not '${shareId}' - needs manual attention.`);
		return;
	}

	if (!row) {
		// Orphan: no matching row at all (file/share since deleted).
		await safeUnlink(kind === 'mig' ? migPath : v1Path);
		audit('file.migrate_recovered', { target: fileId, detail: { action: 'orphan_removed', kind } });
		return;
	}

	if (kind === 'mig') {
		// A '-mig' temp only ever matters while the row is still v1 (crashed
		// before or during step 4, so the v1 original at `origPath` is intact
		// and untouched). If the row is already v2, this temp is simply stale
		// leftover from a run that otherwise completed - safe to discard.
		await safeUnlink(migPath);
		audit('file.migrate_recovered', { target: fileId, detail: { action: 'temp_removed' } });
		return;
	}

	// kind === 'v1'
	if (row.enc_version === 1) {
		// Crashed between step 4's rename and step 5's rename, or after step
		// 5's rename but before its UPDATE committed: origPath (if present) is
		// an orphaned, never-referenced v2 blob - restore the canonical v1
		// bytes over it.
		try {
			await rename(v1Path, origPath);
			await safeUnlink(migPath);
			audit('file.migrate_recovered', { target: fileId, detail: { action: 'restored_v1' } });
		} catch (e) {
			console.error(`[migrate] CRITICAL: failed to restore v1 original for ${fileId} from ${v1Path} - manual recovery needed:`, e);
		}
	} else if (row.enc_version === 2) {
		// Crashed between the UPDATE committing and the backup cleanup:
		// migration already succeeded - just finish the cleanup.
		await safeUnlink(v1Path);
		audit('file.migrate_recovered', { target: fileId, detail: { action: 'backup_removed' } });
	}
}

// A bare blob (no '-mig'/'-v1' sibling suffix) with no corresponding `files`
// row at all is dead weight nothing else will ever find or remove: every real
// blob's row is inserted (routes/uploads.js) BEFORE any bytes are written to
// it, and this only runs once at boot, before the server accepts any request
// - so there is no in-flight upload this could ever mistake for garbage.
async function reconcileOrphanBlob(shareId, fileId) {
	const row = getRowByIdAndShare.get(fileId);
	if (!row) {
		const path = blobPath(shareId, fileId);
		await safeUnlink(path);
		audit('file.migrate_recovered', { target: fileId, detail: { action: 'orphan_blob_removed', share: shareId } });
		console.warn(`[migrate] removed orphaned blob with no DB row: ${path}`);
		return;
	}
	if (row.share_id !== shareId) {
		// Same conservative stance as reconcileLeftover above: never guess at a
		// file whose identity doesn't match what the DB says - leave it for
		// manual attention.
		console.error(`[migrate] blob ${blobPath(shareId, fileId)} has no DB row under share '${shareId}', but a row for id ${fileId} exists under share '${row.share_id}' - needs manual attention.`);
	}
	// Else: row exists under this exact share - a live, referenced blob. Not an orphan.
}

// ---- sweep (secondary trigger, so a never-read file still converges) ------

const SWEEP_BATCH = 25;
const SWEEP_SLEEP_MS = 250;
const SWEEP_INTERVAL_MS = 10 * 60 * 1000;
const DISK_HEADROOM_BYTES = 64 * 1024 * 1024;

export async function sweepMigrations() {
	const candidates = sweepSelect.all(SWEEP_BATCH);
	let migrated = 0;
	let failed = 0;
	let skipped = 0;

	for (const row of candidates) {
		if (isCleanupPending(row.share_id) || inProgress.has(row.id) || failedSkip.has(row.id)) {
			skipped++;
			continue;
		}

		try {
			const fsStat = await statfs(config.storageDir);
			const free = fsStat.bavail * fsStat.bsize;
			const overhead = Math.ceil(row.size / PLAIN_CHUNK) * RECORD_OVERHEAD;
			if (row.size + overhead + DISK_HEADROOM_BYTES > free) {
				skipped++;
				continue;
			}
		} catch {
			// statfs unsupported on this platform/filesystem - proceed without
			// the disk-space guard rather than blocking migration entirely.
		}

		await migrateFile(row.id).catch(e => console.error('[migrate] sweep: unexpected error migrating', row.id, ':', e));
		const after = getRowByIdAndShare.get(row.id);
		if (after && after.enc_version === 2) migrated++;
		else failed++;

		await sleep(SWEEP_SLEEP_MS);
	}

	if (candidates.length) {
		const remaining = countRemaining.get()?.n ?? 0;
		audit('file.migrate_sweep', { detail: { migrated, failed, skipped, remaining } });
	}
}

// Started once at boot (see server.js), after reconcileMigrations() has run.
export function startMigrationSweep() {
	sweepMigrations().catch(e => console.error('[migrate] sweep failed:', e));
	setInterval(() => {
		sweepMigrations().catch(e => console.error('[migrate] sweep failed:', e));
	}, SWEEP_INTERVAL_MS);
}
