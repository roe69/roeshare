// M-5 regression: the download-all (zip) handler fetches every file row once
// up front (a batch snapshot), then loops over it awaiting any in-flight v1->v2
// at-rest migration swap (see lib/migrate.js) one file at a time. Before the
// fix, the per-entry blob stream captured at that point kept using whichever
// row object the batch loop happened to be holding for it - safe only for the
// file actually being awaited at that exact moment. If a DIFFERENT file's
// migration completed its swap while the loop was awaiting on some other
// entry, that file's stale (batch-snapshot) v1 row was used to open what is,
// by the time the archive actually streams it, already v2-encrypted bytes on
// disk: blobRangeStream would read it as v1 CTR, which never authenticates -
// silently producing garbage in the archive instead of failing loudly. The
// fix re-resolves each file immediately before the zip writer actually reads
// its bytes (see resolveFile()/download.js), not from the batch snapshot.
//
// The exact race window is a handful of filesystem syscalls (sub-millisecond -
// see lib/migrate.js's swapLock comment and at-rest-migration.test.js's
// "second TOCTOU bug" test, which notes this class of race is not
// deterministically reproducible without a test-only delay hook in production
// code) - so, like that test, this is a concurrency stress/invariant test:
// many v1 files have their lazy migrations triggered concurrently while
// several overlapping zip downloads are fired, repeated across a few rounds.
// The invariant checked is unconditional and cheap to falsify if the bug is
// present: whenever a zip response comes back 200, every file's EXACT
// plaintext must appear byte-for-byte in the archive (zip.js uses store/no
// compression, so a correctly-decrypted entry's bytes are embedded verbatim
// and literally contained in the response body) - CTR-over-GCM-ciphertext
// "decryption" essentially never reproduces the right plaintext by chance.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import { createHash, createCipheriv, scryptSync, randomBytes } from 'node:crypto';

const ROOT = join(import.meta.dir, '..');
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
			ADMIN_PASSWORD: 'ZipMigrationRace-Pw-2026',
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

// Same v1-CTR seeding as at-rest-migration.test.js: inserts rows/blobs
// directly against the schema created by an earlier boot, shaped exactly as
// the pre-M-06 filecrypt.js would have written them.
function seedV1File(dir, secret, { shareId, fileId, name, plaintext }) {
	mkdirSync(join(dir, 'storage', shareId), { recursive: true });
	const ivHex = randomBytes(16).toString('hex');
	const key = scryptSync(secret, 'roeshare-fs-key-v1', 32);
	const cipher = createCipheriv('aes-256-ctr', key, Buffer.from(ivHex, 'hex'));
	const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	writeFileSync(join(dir, 'storage', shareId, fileId), ciphertext);

	const db = new Database(join(dir, 'roeshare.db'));
	try {
		db.query(
			`INSERT INTO files (id,share_id,name,size,received,mime,complete,download_count,created_at,stored_name,iv,sha256,enc_version,key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run(fileId, shareId, name, plaintext.length, plaintext.length, 'application/octet-stream', 1, 0, Math.floor(Date.now() / 1000), fileId, ivHex, sha256Hex(plaintext), 1, 1);
	} finally {
		db.close();
	}
}

function seedShare(dir, secret, shareId) {
	const editHash = sha256Hex(Buffer.from(`edit-${shareId}`));
	const db = new Database(join(dir, 'roeshare.db'));
	try {
		db.query(
			`INSERT INTO shares (id,title,created_at,expires_at,password_hash,max_downloads,download_count,one_time,edit_token,finalized,deleted_at,creator_ip,creator_ua,e2e,view_count,api_key_id)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		).run(shareId, 'zip race test', Math.floor(Date.now() / 1000), null, null, null, 0, 0, editHash, 1, null, '127.0.0.1', 'test', 0, 0, null);
	} finally {
		db.close();
	}
}

async function waitFor(dbPath, fn, timeoutMs = 15000) {
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
		await new Promise(r => setTimeout(r, 25));
	}
	throw new Error(`waitFor timed out after ${timeoutMs}ms`);
}

describe('M-5: a zip download never uses a stale file row across a concurrent migration swap', () => {
	test('concurrent zip downloads while multiple files migrate never contain corrupted/garbage entries', async () => {
		const dir = freshDataDir('zip-migration-race');
		const port = 3960;
		const secret = `zip-migration-race-secret-${port}`;
		try {
			// Boot once to create the schema, then stop before seeding directly.
			const bootProc = await bootServer(dir, port, secret);
			await stopServer(bootProc);

			const ROUNDS = 3;
			const FILES_PER_ROUND = 5;
			// Mix of sizes: a couple of larger files (slower re-encrypt/verify,
			// widening the window other files' migrations can complete inside) and
			// several small ones (whose whole migration lifecycle - reencrypt,
			// verify, locked swap - completes fast enough to plausibly land inside
			// that window).
			const sizesBytes = [1_500_000, 1_500_000, 6_000, 6_000, 6_000];

			const proc = await bootServer(dir, port, secret);
			try {
				const base = `http://127.0.0.1:${port}`;
				const dbPath = join(dir, 'roeshare.db');

				for (let round = 0; round < ROUNDS; round++) {
					const shareId = `zmr${round}share`;
					seedShare(dir, secret, shareId);

					const files = sizesBytes.map((size, i) => {
						const fileId = `zmr${round}f${i}file${i}`.padEnd(16, '0');
						const plaintext = randomBytes(size);
						seedV1File(dir, secret, { shareId, fileId, name: `file${i}.bin`, plaintext });
						return { fileId, plaintext };
					});

					// Kick off every file's lazy migration concurrently (a single-file
					// download schedules the background migration for that file - see
					// lib/migrate.js's module comment).
					// Body is drained (not just the response awaited) so the request's
					// semaphore slot is released promptly and doesn't starve later
					// rounds - scheduleMigration() already fired synchronously the
					// moment the server handled the request (download.js), well before
					// the body finishes streaming, so draining here does not narrow the
					// race window with the zip burst fired in the same tick below.
					const triggerDownloads = files.map(f =>
						fetch(`${base}/api/shares/${shareId}/files/${f.fileId}/download`)
							.then(r => r.arrayBuffer())
							.catch(() => {}),
					);

					// Immediately fire a burst of overlapping zip downloads while those
					// migrations are in flight - the exact window M-5 concerns.
					const ZIP_BURST = 4;
					const zipResults = [];
					for (let i = 0; i < ZIP_BURST; i++) {
						zipResults.push(
							fetch(`${base}/api/shares/${shareId}/download-all`)
								.then(async res => ({ status: res.status, body: res.status === 200 ? Buffer.from(await res.arrayBuffer()) : null }))
								.catch(e => ({ status: null, error: e })),
						);
					}

					await Promise.all(triggerDownloads);
					const zips = await Promise.all(zipResults);

					for (const z of zips) {
						// Never a raw server error, and never a dropped/failed fetch.
						expect(z.status).not.toBe(500);
						expect(z.status).not.toBeNull();
						if (z.status !== 200) {
							// Admission control (only 2 concurrent zip slots per IP) is the
							// only expected non-200 outcome here - never anything indicating
							// a corrupted response.
							expect([404, 429, 503]).toContain(z.status);
							continue;
						}
						// The safety invariant: every file's exact plaintext must appear
						// byte-for-byte in the archive (store/no-compression zip - see
						// lib/zip.js - embeds entry bytes verbatim). A stale v1 row read
						// against already-v2 disk bytes would never reproduce this.
						for (const f of files) {
							expect(z.body.indexOf(f.plaintext)).toBeGreaterThanOrEqual(0);
						}
					}

					// Let this round's migrations fully settle before seeding the next
					// round, so migration activity never bleeds across rounds.
					for (const f of files) {
						await waitFor(dbPath, db => {
							const row = db.query('SELECT enc_version FROM files WHERE id = ?').get(f.fileId);
							return row && row.enc_version === 2 ? row : null;
						});
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
	}, 60000);
});
