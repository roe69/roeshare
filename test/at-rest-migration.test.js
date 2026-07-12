// M-06: automatic, transparent v1 -> v2 at-rest migration. Exercises the
// real HTTP surface (mirrors at-rest-v2.test.js / migrations.test.js): seed
// a v1 (AES-256-CTR) encrypted file directly against the schema (the same
// shape createShare/registerFile/finalize would have produced before this
// change), let the server boot and its lazy migration trigger fire on the
// next read, and confirm it converges to v2 while the file stays
// downloadable throughout. A second test forces the migration's verify step
// to fail (a deliberately wrong stored sha256, standing in for "the v1
// ciphertext was already corrupt on disk") and confirms the original v1
// file and its DB row are left completely untouched - and still readable -
// rather than the failure bricking access or laundering corruption into an
// "authenticated" v2 blob.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, watch } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import { createHash, createCipheriv, scryptSync, randomBytes } from 'node:crypto';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'MigrationM06Test-Pw-2026';
const sha256Hex = buf => createHash('sha256').update(buf).digest('hex');

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
}

async function bootServer(dataDir, port, secret) {
	const proc = Bun.spawn({
		cmd: [process.execPath, 'run', 'src/server.js'],
		cwd: ROOT,
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(port),
			DATA_DIR: dataDir,
			ADMIN_PASSWORD,
			SECRET: secret,
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

// Polls `fn` against a fresh read-only connection (WAL mode allows a reader
// to run alongside the live server process) until it returns something
// truthy, or throws once `timeoutMs` elapses.
async function waitFor(dbPath, fn, timeoutMs = 8000) {
	const deadline = Date.now() + timeoutMs;
	let last;
	while (Date.now() < deadline) {
		const db = new Database(dbPath, { readonly: true });
		try {
			last = fn(db);
			if (last) return last;
		} finally {
			db.close();
		}
		await new Promise(r => setTimeout(r, 100));
	}
	throw new Error(`waitFor timed out after ${timeoutMs}ms (last=${JSON.stringify(last)})`);
}

// Polls the filesystem directly (not via HTTP) for `path` to appear - used to
// detect, from outside the server process, that lib/migrate.js's migrateFile()
// has reached a specific step (the '-mig' temp appears at the very start of
// re-encrypt; the '-v1' backup appears only once the atomic swap has begun).
// This is the only externally-observable, precise signal of migration
// progress, and is what lets these tests race an admin delete against a
// specific in-flight step without any artificial delay/hook in production code.
async function waitForPath(path, timeoutMs = 8000) {
	const deadline = Date.now() + timeoutMs;
	while (!existsSync(path)) {
		if (Date.now() > deadline) throw new Error(`waitForPath timed out after ${timeoutMs}ms waiting for ${path}`);
		await new Promise(r => setTimeout(r, 2));
	}
}

// Like waitForPath, but event-driven (fs.watch, backed by the OS's own
// change notifications) instead of polled. The '-v1' backup this is used for
// (see the test below) only exists for as long as migrateFile's locked swap
// takes to finish its remaining steps - a fixed handful of syscalls
// (rename, directory fsync, one DB write, one unlink), independent of file
// size, and possibly well under waitForPath's 2ms poll granularity. A poll
// can step right over a window that narrow and never observe it at all;
// fs.watch cannot miss it, because the OS queues the notification the
// instant the entry is created, regardless of when the callback gets to run.
function waitForEntryEvent(dir, name, timeoutMs = 8000) {
	const path = join(dir, name);
	if (existsSync(path)) return Promise.resolve();
	return new Promise((resolve, reject) => {
		const watcher = watch(dir, () => {
			if (existsSync(path)) {
				clearTimeout(timer);
				watcher.close();
				resolve();
			}
		});
		const timer = setTimeout(() => {
			watcher.close();
			reject(new Error(`waitForEntryEvent timed out after ${timeoutMs}ms waiting for ${name} in ${dir}`));
		}, timeoutMs);
	});
}

// Logs in as admin (CSRF-checked - Origin: base simulates a same-origin
// browser request, mirroring security-regressions.test.js's adminCookie).
async function adminCookie(base) {
	const res = await fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	if (res.status !== 200) throw new Error(`admin login failed: ${res.status} ${await res.text()}`);
	return res.headers.get('set-cookie').split(';')[0];
}

// Seeds one v1-CTR-encrypted file, sealed exactly as the pre-M-06
// filecrypt.js would have written it, directly against the CURRENT schema.
// The schema itself must already exist on disk (from an earlier boot) -
// this only inserts rows and blob bytes, never CREATE TABLEs, so it can
// never drift from db.js's real shape.
function seedV1File(dir, secret, { shareId, fileId, plaintext, sha256 }) {
	mkdirSync(join(dir, 'storage', shareId), { recursive: true });
	const ivHex = randomBytes(16).toString('hex');
	const key = scryptSync(secret, 'roeshare-fs-key-v1', 32);
	const cipher = createCipheriv('aes-256-ctr', key, Buffer.from(ivHex, 'hex'));
	const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	writeFileSync(join(dir, 'storage', shareId, fileId), ciphertext);

	const db = new Database(join(dir, 'roeshare.db'));
	try {
		const editHash = sha256Hex(Buffer.from(`edit-${shareId}`));
		db.query(
			`INSERT INTO shares (id,title,created_at,expires_at,password_hash,max_downloads,download_count,one_time,edit_token,finalized,deleted_at,creator_ip,creator_ua,e2e,view_count,api_key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run(shareId, 'm06 test', Math.floor(Date.now() / 1000), null, null, null, 0, 0, editHash, 1, null, '127.0.0.1', 'test', 0, 0, null);
		db.query(
			`INSERT INTO files (id,share_id,name,size,received,mime,complete,download_count,created_at,stored_name,iv,sha256,enc_version,key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run(fileId, shareId, 'secret.txt', plaintext.length, plaintext.length, 'text/plain', 1, 0, Math.floor(Date.now() / 1000), fileId, ivHex, sha256, 1, 1);
	} finally {
		db.close();
	}
	return { ciphertext, ivHex };
}

describe('M-06: automatic v1 -> v2 at-rest migration', () => {
	test('a v1 file migrates to v2 on next read, stays downloadable throughout, and the backup is cleaned up', async () => {
		const dir = freshDataDir('m06-success');
		const port = 3640;
		const secret = `m06-migrate-secret-${port}`;
		try {
			// Boot once against a brand-new dir just to create the schema, then
			// stop it before seeding data directly.
			const bootProc = await bootServer(dir, port, secret);
			await stopServer(bootProc);

			const plaintext = Buffer.from('M-06 migration test content, encrypted the old v1 AES-256-CTR way. '.repeat(50));
			const shareId = 'm06share1';
			const fileId = 'm06file111111111';
			const { ciphertext: originalCiphertext } = seedV1File(dir, secret, {
				shareId,
				fileId,
				plaintext,
				sha256: sha256Hex(plaintext),
			});

			const proc = await bootServer(dir, port, secret);
			try {
				const base = `http://127.0.0.1:${port}`;

				// The lazy trigger fires on this first read; the response itself must
				// still be served correctly from the (still-v1-at-this-point) blob.
				const dl1 = await fetch(`${base}/api/shares/${shareId}/files/${fileId}/download`);
				expect(dl1.status).toBe(200);
				expect(Buffer.from(await dl1.arrayBuffer()).equals(plaintext)).toBe(true);

				// Wait for the background migration to actually land.
				const dbPath = join(dir, 'roeshare.db');
				await waitFor(dbPath, db => db.query('SELECT * FROM audit_events WHERE event = ? AND target = ?').get('file.migrate_success', fileId));

				const after = new Database(dbPath, { readonly: true });
				let row;
				try {
					row = after.query('SELECT enc_version, iv, key_id, sha256, size FROM files WHERE id = ?').get(fileId);
				} finally {
					after.close();
				}
				expect(row.enc_version).toBe(2);
				expect(row.key_id).toBe(1);
				expect(row.sha256).toBe(sha256Hex(plaintext)); // sha256 (of the plaintext) never changes
				expect(row.size).toBe(plaintext.length);

				// The blob on disk must now be v2-shaped: bigger than the plaintext
				// (per-record framing overhead - proof it's really chunked GCM, not a
				// passthrough) and different bytes than the original v1 ciphertext.
				const blobBytes = readFileSync(join(dir, 'storage', shareId, fileId));
				expect(blobBytes.length).toBeGreaterThan(plaintext.length);
				expect(blobBytes.equals(originalCiphertext)).toBe(false);

				// No leftover temp/backup blob after a successful migration.
				expect(readdirSync(join(dir, 'storage', shareId))).toEqual([fileId]);

				// Still downloads correctly, now via the v2 path.
				const dl2 = await fetch(`${base}/api/shares/${shareId}/files/${fileId}/download`);
				expect(dl2.status).toBe(200);
				expect(Buffer.from(await dl2.arrayBuffer()).equals(plaintext)).toBe(true);

				// And a Range read is still correct post-migration.
				const rangeDl = await fetch(`${base}/api/shares/${shareId}/files/${fileId}/download`, { headers: { Range: 'bytes=10-49' } });
				expect(rangeDl.status).toBe(206);
				expect(Buffer.from(await rangeDl.arrayBuffer()).equals(plaintext.subarray(10, 50))).toBe(true);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a failed verify (mismatched sha256) leaves the v1 file and DB row completely untouched, and the file stays readable', async () => {
		const dir = freshDataDir('m06-failure');
		const port = 3641;
		const secret = `m06-migrate-secret-${port}`;
		try {
			const bootProc = await bootServer(dir, port, secret);
			await stopServer(bootProc);

			const plaintext = Buffer.from('M-06 verify-failure test content - this must never be lost. '.repeat(50));
			const shareId = 'm06share2';
			const fileId = 'm06file222222222';
			// Deliberately WRONG stored sha256 (as if the v1 ciphertext were already
			// corrupt on disk before this migration ever ran) - forces the verify
			// step's read-back digest check to fail, simulating an interrupted /
			// failed migration mid-way.
			const wrongSha256 = sha256Hex(Buffer.from('not the right content at all'));
			const { ciphertext: originalCiphertext, ivHex } = seedV1File(dir, secret, {
				shareId,
				fileId,
				plaintext,
				sha256: wrongSha256,
			});

			const proc = await bootServer(dir, port, secret);
			try {
				const base = `http://127.0.0.1:${port}`;

				const dl1 = await fetch(`${base}/api/shares/${shareId}/files/${fileId}/download`);
				expect(dl1.status).toBe(200);
				expect(Buffer.from(await dl1.arrayBuffer()).equals(plaintext)).toBe(true);

				const dbPath = join(dir, 'roeshare.db');
				const failureEvent = await waitFor(dbPath, db =>
					db.query('SELECT * FROM audit_events WHERE event = ? AND target = ?').get('file.migrate_failure', fileId),
				);
				const detail = JSON.parse(failureEvent.detail);
				expect(detail.stage).toBe('sha256_mismatch');

				// The DB row must be exactly the row we seeded: still v1, same iv,
				// same (deliberately wrong, but original) sha256, same key_id.
				const after = new Database(dbPath, { readonly: true });
				let row;
				try {
					row = after.query('SELECT enc_version, iv, key_id, sha256 FROM files WHERE id = ?').get(fileId);
				} finally {
					after.close();
				}
				expect(row.enc_version).toBe(1);
				expect(row.iv).toBe(ivHex);
				expect(row.key_id).toBe(1);
				expect(row.sha256).toBe(wrongSha256);

				// The original ciphertext on disk must be byte-for-byte untouched,
				// and no leftover temp/backup blob remains next to it.
				const blobBytes = readFileSync(join(dir, 'storage', shareId, fileId));
				expect(blobBytes.equals(originalCiphertext)).toBe(true);
				expect(readdirSync(join(dir, 'storage', shareId))).toEqual([fileId]);

				// And the file must still be fully readable through the (unchanged)
				// v1 path - a failed migration must never brick access.
				const dl2 = await fetch(`${base}/api/shares/${shareId}/files/${fileId}/download`);
				expect(dl2.status).toBe(200);
				expect(Buffer.from(await dl2.arrayBuffer()).equals(plaintext)).toBe(true);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	// TOCTOU fix: an admin per-file delete used to have zero coordination with
	// migrateFile()'s swap - a delete landing while origPath was transiently
	// absent (between the preserve-original and promote-temp renames) would
	// silently no-op (rm() of an absent path), delete the DB row, and then let
	// the migration recreate the blob underneath it: an orphaned blob with no
	// DB row, permanently invisible to reconcileMigrations()'s old '-mig'/'-v1'
	// -only scan. storage.js's withFileLock + migrate.js's pre-swap recheck
	// close this: the delete now either runs first (and the migration's
	// recheck, done right before it ever touches the filesystem, sees the row
	// is gone and aborts) or queues behind an in-flight swap (and by the time
	// it runs, the row/blob are already consistently in their post-swap state).
	test('an admin per-file delete racing an in-flight migration leaves no orphaned blob behind', async () => {
		const dir = freshDataDir('m06-delete-race');
		const port = 3642;
		const secret = `m06-migrate-secret-${port}`;
		try {
			const bootProc = await bootServer(dir, port, secret);
			await stopServer(bootProc);

			// Large enough that the re-encrypt/verify steps (which run BEFORE
			// migrateFile ever takes the per-file lock guarding the swap) take
			// long enough to reliably observe the in-flight '-mig' temp file from
			// the test process and fire a concurrent admin delete while the
			// migration is still busy with it.
			const plaintext = randomBytes(24 * 1024 * 1024); // 24 MiB
			const shareId = 'm06share3';
			const fileId = 'm06file333333333';
			seedV1File(dir, secret, { shareId, fileId, plaintext, sha256: sha256Hex(plaintext) });

			const proc = await bootServer(dir, port, secret);
			try {
				const base = `http://127.0.0.1:${port}`;
				const cookie = await adminCookie(base);

				// Fire the lazy migration trigger; don't wait for it to finish
				// (a large-file download completing is not what this test times).
				const dlPromise = fetch(`${base}/api/shares/${shareId}/files/${fileId}/download`).catch(() => {});

				// The '-mig' temp appearing is the earliest, most reliable signal
				// that a migration for this file is now actively re-encrypting.
				const migPath = join(dir, 'storage', shareId, `${fileId}-mig`);
				await waitForPath(migPath);

				// Race the admin per-file delete against the still-running migration.
				const delRes = await fetch(`${base}/api/admin/shares/${shareId}/files/${fileId}`, {
					method: 'DELETE',
					headers: { Cookie: cookie, Origin: base },
				});
				expect(delRes.status).toBe(200);

				await dlPromise;

				// Let the now-doomed migration run to completion - it must detect
				// the row is gone at its pre-swap recheck and abort cleanly, never
				// recreating the blob it can no longer see a row for.
				const dbPath = join(dir, 'roeshare.db');
				const failureEvent = await waitFor(dbPath, db =>
					db.query('SELECT * FROM audit_events WHERE event = ? AND target = ?').get('file.migrate_failure', fileId),
				);
				const detail = JSON.parse(failureEvent.detail);
				expect(detail.stage).toBe('deleted_concurrently');

				// No orphan: the DB row is gone, and nothing is left on disk for this
				// file id - no bare blob (the leak this fix closes), and no leftover
				// '-mig'/'-v1' temp/backup sibling either.
				const after = new Database(dbPath, { readonly: true });
				try {
					expect(after.query('SELECT id FROM files WHERE id = ?').get(fileId)).toBeNull();
				} finally {
					after.close();
				}
				const remaining = readdirSync(join(dir, 'storage', shareId)).filter(n => n === fileId || n.startsWith(`${fileId}-`));
				expect(remaining).toEqual([]);

				// The server itself must still be healthy - the abort path must
				// never throw an unhandled rejection that takes the process down.
				const health = await fetch(`${base}/health`);
				expect(health.status).toBe(204);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	// Same TOCTOU class, the whole-share side: deleteShareFiles() sets the
	// isCleanupPending flag before it starts removing files, but migrateFile
	// used to check it only once at the very start - never again right before
	// the swap. A whole-share delete landing during the (potentially long)
	// re-encrypt/verify window would sail straight through that stale check and
	// still perform the swap on a share that is mid-teardown. The fix re-checks
	// isCleanupPending() immediately before the swap (see migrate.js), so this
	// must now abort instead.
	test('a whole-share delete racing an in-flight migration is re-checked right before the swap, not just once at the start', async () => {
		const dir = freshDataDir('m06-share-delete-race');
		const port = 3643;
		const secret = `m06-migrate-secret-${port}`;
		try {
			const bootProc = await bootServer(dir, port, secret);
			await stopServer(bootProc);

			const plaintext = randomBytes(24 * 1024 * 1024); // 24 MiB
			const shareId = 'm06share4';
			const fileId = 'm06file444444444';
			seedV1File(dir, secret, { shareId, fileId, plaintext, sha256: sha256Hex(plaintext) });

			const proc = await bootServer(dir, port, secret);
			try {
				const base = `http://127.0.0.1:${port}`;
				const cookie = await adminCookie(base);

				const dlPromise = fetch(`${base}/api/shares/${shareId}/files/${fileId}/download`).catch(() => {});

				const migPath = join(dir, 'storage', shareId, `${fileId}-mig`);
				await waitForPath(migPath);

				const delRes = await fetch(`${base}/api/admin/shares/${shareId}`, {
					method: 'DELETE',
					headers: { Cookie: cookie, Origin: base },
				});
				expect(delRes.status).toBe(200);

				await dlPromise;

				// Whichever stage catches it first - the concurrent rm() can just as
				// easily fail an in-progress re-encrypt/verify read as it can land
				// exactly in the pre-swap recheck's own narrow window - the migration
				// must abort cleanly (never succeed) once the share is mid-teardown.
				const dbPath = join(dir, 'roeshare.db');
				const failureEvent = await waitFor(dbPath, db =>
					db.query('SELECT * FROM audit_events WHERE event = ? AND target = ?').get('file.migrate_failure', fileId),
				);
				expect(failureEvent).toBeTruthy();
				const successEvent = new Database(dbPath, { readonly: true });
				try {
					expect(successEvent.query('SELECT 1 FROM audit_events WHERE event = ? AND target = ?').get('file.migrate_success', fileId)).toBeNull();
				} finally {
					successEvent.close();
				}

				// The whole share (and its file row) must be fully gone, and the
				// on-disk directory must not have been recreated by the aborted
				// migration's cleanup.
				const after = new Database(dbPath, { readonly: true });
				try {
					expect(after.query('SELECT id FROM shares WHERE id = ?').get(shareId)).toBeNull();
					expect(after.query('SELECT id FROM files WHERE id = ?').get(fileId)).toBeNull();
				} finally {
					after.close();
				}
				expect(existsSync(join(dir, 'storage', shareId))).toBe(false);

				const health = await fetch(`${base}/health`);
				expect(health.status).toBe(204);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	// storage.js's deleteShareFiles() TOCTOU fix: it used to remove a share's
	// whole directory with a single unguarded rm(), with zero per-file lock
	// coordination against migrate.js's swap - only the isCleanupPending flag
	// above protected it, and only at the two points migrateFile happens to
	// check it (once at the very start, once right before the swap). The test
	// above lands the delete before migrateFile ever takes the lock (it fires
	// the instant the '-mig' temp appears, which is always well before the
	// lock is touched, no matter the file's size) - it can never land the
	// delete AFTER migrateFile has already entered the lock and passed that
	// pre-swap recheck, because that window (a rename, a directory fsync, one
	// DB write, an unlink) is a fixed handful of syscalls entirely
	// independent of file size: a bigger file only widens the UNLOCKED
	// re-encrypt/verify phase before it, never this one, and it is easily
	// narrower than any external poll loop's granularity.
	//
	// This test targets exactly that window. It waits for the ONE fact on
	// disk that can only become true once migrateFile already holds
	// storage.js's per-file lock, past the recheck: the '-v1' backup existing
	// (created by the very first rename inside the locked swap callback,
	// which only ever runs after the recheck has already passed - see
	// migrate.js's migrateFile()). fs.watch (not a poll) is what makes
	// observing it reliable - the window can be narrower than a poll
	// interval, but the OS-level watch cannot miss an event that already
	// happened. Once observed, the admin delete fired here is provably
	// issued only after migrateFile already holds the lock for this exact
	// fileId - so deleteShareFiles()'s own withFileLock(fileId) call is
	// guaranteed (same Map, same fileId, FIFO) to queue behind it rather than
	// race it at the filesystem level, regardless of exactly how much of the
	// remaining swap is still in flight when the delete request arrives.
	test('a whole-share delete arriving after migrateFile has already entered the per-file lock (past the pre-swap recheck) never races the swap, and the migration always completes cleanly first', async () => {
		const dir = freshDataDir('m06-share-delete-lockwin');
		const port = 3646;
		const secret = `m06-migrate-secret-${port}`;
		try {
			const bootProc = await bootServer(dir, port, secret);
			await stopServer(bootProc);

			// Large enough only so the UNLOCKED re-encrypt/verify phase gives the
			// external test process a comfortable window to register the fs.watch
			// below before that phase ends - NOT to widen the locked swap window
			// itself (see the comment above; that window is fixed-size regardless
			// of file size, which is exactly why '-mig' was the wrong thing for
			// the test above to watch for, and '-v1' is watched here instead).
			const plaintext = randomBytes(24 * 1024 * 1024); // 24 MiB
			const shareId = 'm06share6';
			const fileId = 'm06file666666666';
			seedV1File(dir, secret, { shareId, fileId, plaintext, sha256: sha256Hex(plaintext) });

			const proc = await bootServer(dir, port, secret);
			try {
				const base = `http://127.0.0.1:${port}`;
				const cookie = await adminCookie(base);

				const dlPromise = fetch(`${base}/api/shares/${shareId}/files/${fileId}/download`).catch(() => {});

				const shareStorageDir = join(dir, 'storage', shareId);
				const v1Wait = waitForEntryEvent(shareStorageDir, `${fileId}-v1`);
				await v1Wait;

				const delRes = await fetch(`${base}/api/admin/shares/${shareId}`, {
					method: 'DELETE',
					headers: { Cookie: cookie, Origin: base },
				});
				expect(delRes.status).toBe(200);

				await dlPromise;

				// migrateFile had already passed its recheck before the delete
				// request above was even sent (proven by '-v1' already existing at
				// that point) - once past that point it always runs its
				// already-entered swap to completion, so it must have succeeded,
				// never aborted.
				const dbPath = join(dir, 'roeshare.db');
				const successEvent = await waitFor(dbPath, db => db.query('SELECT * FROM audit_events WHERE event = ? AND target = ?').get('file.migrate_success', fileId));
				expect(successEvent).toBeTruthy();
				const afterAudit = new Database(dbPath, { readonly: true });
				try {
					expect(afterAudit.query('SELECT 1 FROM audit_events WHERE event = ? AND target = ?').get('file.migrate_failure', fileId)).toBeNull();
				} finally {
					afterAudit.close();
				}

				// The whole share (and its file row) must be fully gone, and - the
				// bug this closes - the on-disk directory must never be left
				// half-torn-down (rm()'s recursive walk racing migrateFile's rename
				// sequence at the filesystem level, which can throw ENOTEMPTY on the
				// final rmdir) nor leave an orphaned blob of any kind behind.
				const after = new Database(dbPath, { readonly: true });
				try {
					expect(after.query('SELECT id FROM shares WHERE id = ?').get(shareId)).toBeNull();
					expect(after.query('SELECT id FROM files WHERE id = ?').get(fileId)).toBeNull();
				} finally {
					after.close();
				}
				expect(existsSync(shareStorageDir)).toBe(false);

				const health = await fetch(`${base}/health`);
				expect(health.status).toBe(204);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	// The second TOCTOU bug: download.js's resolveFile() used to fall back to
	// the STALE pre-migration row ("getFile.get(...) || file") whenever the
	// re-fetch after genuinely awaiting an in-flight swap came back empty -
	// silently handing a caller that only null-checks `file` a row for content
	// that no longer exists. The fix returns null instead. The exact window
	// this guards (a reader's resolveFile() call landing precisely inside
	// migrateFile's few-syscall swapLock window, concurrently with a delete
	// that wins the race for the row) is sub-millisecond and not deterministically
	// reproducible without a test-only delay hook in production code - so this
	// exercises it as a concurrency stress/invariant test instead: many readers
	// hammer the file throughout an in-flight migration while a whole-share
	// delete races it, and no response may ever be anything other than a clean
	// success (full, correct bytes) or a clean client error - never a crash, and
	// never a 200 whose body is wrong/truncated (the symptom the old stale
	// fallback caused: a caller proceeding against a row/blob that no longer
	// existed).
	test('concurrent reads never observe a stale row while a delete races an in-flight migration', async () => {
		const dir = freshDataDir('m06-resolve-race');
		const port = 3644;
		const secret = `m06-migrate-secret-${port}`;
		try {
			const bootProc = await bootServer(dir, port, secret);
			await stopServer(bootProc);

			const plaintext = randomBytes(24 * 1024 * 1024); // 24 MiB
			const shareId = 'm06share5';
			const fileId = 'm06file555555555';
			seedV1File(dir, secret, { shareId, fileId, plaintext, sha256: sha256Hex(plaintext) });

			const proc = await bootServer(dir, port, secret);
			try {
				const base = `http://127.0.0.1:${port}`;
				const cookie = await adminCookie(base);
				const url = `${base}/api/shares/${shareId}/files/${fileId}/download`;

				const migPath = join(dir, 'storage', shareId, `${fileId}-mig`);
				const firstDl = fetch(url).catch(() => {});
				await waitForPath(migPath);

				// A burst of concurrent readers spread across the rest of the
				// migration's lifetime, plus a whole-share delete racing them all.
				const reads = [];
				for (let i = 0; i < 40; i++) reads.push(fetch(url));
				const delPromise = fetch(`${base}/api/admin/shares/${shareId}`, {
					method: 'DELETE',
					headers: { Cookie: cookie, Origin: base },
				});

				const results = await Promise.all([firstDl, ...reads, delPromise]);
				const delRes = results[results.length - 1];
				expect(delRes.status).toBe(200);

				for (const res of results.slice(0, -1)) {
					if (!res) continue; // firstDl's fetch() itself may have been aborted
					// Never an unhandled server error - the abort/rollback paths this
					// fix added must never throw past their try/catch.
					expect(res.status).not.toBe(500);
					if (res.status === 200) {
						const body = Buffer.from(await res.arrayBuffer());
						expect(body.equals(plaintext)).toBe(true);
					} else {
						// A clean client-facing outcome: not-found (share/file already
						// gone), or admission control/byte-rate throttling this many
						// concurrent full-file reads legitimately triggers - never
						// anything that indicates a corrupted/half-served response.
						expect([403, 404, 409, 410, 429, 503]).toContain(res.status);
					}
				}

				const health = await fetch(`${base}/health`);
				expect(health.status).toBe(204);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
