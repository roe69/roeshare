// Filesystem storage. Blobs live at <storageDir>/<shareId>/<fileId>. The on-disk
// name is always the opaque file id - never the user-supplied filename - which
// removes the entire class of path-traversal and overwrite bugs. Every public
// path is additionally validated to stay within storageDir.
//
// At-rest encryption has two on-disk formats, selected per file via
// fileEnc() below (built from the file row's iv/enc_version/key_id columns;
// see lib/filecrypt.js for the format details):
//   v1 - AES-256-CTR. Ciphertext length == plaintext length, so disk size and
//        plaintext size always agree (legacy; kept forever, never migrated).
//   v2 - AES-256-GCM in independently-authenticated PLAIN_CHUNK-byte records.
//        Disk size != plaintext size (each record carries framing overhead),
//        so callers needing the LOGICAL file length must use plainSize()
//        below, never stat()/blobFile().size.

import { mkdir, open, rm, stat, readdir, rename } from 'node:fs/promises';
import { existsSync, createReadStream, statSync, lstatSync, constants as FS_CONST } from 'node:fs';
import { Readable } from 'node:stream';
import { join, resolve, sep } from 'node:path';
import { config } from '../config.js';
import { transformAt, decryptStream, PLAIN_CHUNK, FULL_RECORD, fileKeyForV2, sealRecordV2, openRecordV2 } from './filecrypt.js';
import { audit } from './audit.js';

// Random ids use the ids.js alphabet; custom share slugs add - and _. Neither
// dots nor path separators are allowed, so a segment can never escape its dir.
const ID = /^[0-9A-Za-z_-]+$/;

// O_NOFOLLOW isn't defined on every platform (notably: absent from
// node:fs.constants on Windows) - fall back to 0 (no-op flag) there. On a
// platform that lacks it, the lstat-based checks below (assertRealDirIfExists
// / assertRealFileIfExists) are the only symlink defense; where it IS defined
// (Linux/macOS - the actual deploy target, see DEPLOY.md) it additionally
// closes the lstat-then-open TOCTOU race at the syscall level.
const O_NOFOLLOW = FS_CONST.O_NOFOLLOW || 0;
const { O_WRONLY, O_RDONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC } = FS_CONST;

function safeSegment(id) {
	if (typeof id !== 'string' || !ID.test(id)) throw new Error('invalid storage id');
	return id;
}

// Throws if `dir` exists but is not a real directory - e.g. a symlink planted
// in its place (pointing anywhere, including outside storageDir) or a plain
// file. Uses lstat, never stat, so a symlink is never followed to decide "yes
// this resolves to a directory" (which is exactly what Node's recursive
// mkdir() does internally, and why it alone is not a sufficient guard). A
// missing path is not an error here - callers create it on demand.
function assertRealDirIfExists(dir) {
	let st;
	try {
		st = lstatSync(dir);
	} catch (e) {
		if (e.code === 'ENOENT') return false;
		throw e;
	}
	if (!st.isDirectory()) throw new Error(`refusing to use non-directory storage path: ${dir}`);
	return true;
}

// Throws if `path` exists but is not a regular file (e.g. a symlink planted
// there). Uses lstat, never stat. A missing path is not an error - it just
// means "not created yet" and returns false so the caller knows to O_CREAT.
function assertRealFileIfExists(path) {
	let st;
	try {
		st = lstatSync(path);
	} catch (e) {
		if (e.code === 'ENOENT') return false;
		throw e;
	}
	if (!st.isFile()) throw new Error(`refusing to open non-regular-file storage path: ${path}`);
	return true;
}

export function shareDir(shareId) {
	return join(config.storageDir, safeSegment(shareId));
}

export function blobPath(shareId, fileId) {
	const dir = shareDir(shareId);
	const p = resolve(dir, safeSegment(fileId));
	// Defense in depth: the resolved path must stay under storageDir.
	if (p !== config.storageDir && !p.startsWith(config.storageDir + sep)) {
		throw new Error('path escapes storage root');
	}
	// Reject a symlink planted in place of the storage root or the share
	// directory - every parent directory component under storageDir must be a
	// real directory, never a link followed somewhere else. The leaf (the blob
	// file itself) is checked separately at open time by the read/write paths
	// below, which also need to tell "doesn't exist yet" from "exists".
	assertRealDirIfExists(config.storageDir);
	assertRealDirIfExists(dir);
	return p;
}

// Build the at-rest encryption descriptor writeChunk()/blobRangeStream()/
// plainSize() need from a `files` row (any query that selected at least
// id, iv, enc_version, key_id). iv === null is the sole "no server crypto"
// signal (E2E share, or ENCRYPT_AT_REST=0 at upload time) and always means
// null here regardless of enc_version - existing rows default enc_version to
// 1, which is correct for every pre-v2 encrypted row and is simply ignored
// for plaintext/E2E rows.
export function fileEnc(fileRow) {
	if (fileRow.iv == null) return null;
	if (fileRow.enc_version === 2) return { version: 2, keyId: fileRow.key_id, fileSalt: fileRow.iv, fileId: fileRow.id };
	return { version: 1, iv: fileRow.iv };
}

// The file's LOGICAL (plaintext) length. For v2 the DB is authoritative (disk
// holds more bytes than that, see the format comment above); for v1/
// plaintext/E2E, ciphertext length equals plaintext length so the on-disk
// size is exact. Only meaningful for a COMPLETE file (fileRow.size is the
// declared total, not the in-progress `received` count).
export function plainSize(fileRow, shareId) {
	const enc = fileEnc(fileRow);
	if (enc?.version === 2) return fileRow.size;
	return blobFile(shareId, fileRow.id).size;
}

// ---- v1 / plaintext write path (unchanged) ---------------------------------

async function writeChunkPlain(path, offset, buf) {
	const fh = await openBlobForChunkWrite(path, offset);
	try {
		await fh.write(buf, 0, buf.length, offset);
	} finally {
		await fh.close();
	}
	const s = await stat(path);
	return s.size;
}

// Open a blob file for a chunk write at PLAINTEXT/on-disk offset `diskOffset`,
// never following a symlink into it. Shared by the v1/plaintext and v2 write
// paths (they differ only in how "offset 0" maps to disk position).
//
//   - diskOffset === 0 and nothing exists there yet: a genuinely new blob -
//     O_CREAT|O_EXCL, so the create fails outright (rather than silently
//     reusing) if anything - file or symlink - appears at this path between
//     our lstat and the open.
//   - diskOffset === 0 and a real file already exists: an idempotent retry of
//     the first chunk after it landed on disk but the DB commit that would
//     have advanced `received` never happened (a crash between the two - see
//     uploads.js's offset===received check). O_EXCL doesn't apply here since
//     the file legitimately exists; O_TRUNC restarts it cleanly.
//   - diskOffset > 0: resuming a partial upload. The blob must already exist
//     as a real regular file (verified via lstat above) - reopened without
//     O_CREAT, so a missing file still fails exactly as it did before.
//
// O_NOFOLLOW (where supported - see the constant above) additionally blocks a
// symlink swapped in for the path in the window between the lstat check and
// this open.
async function openBlobForChunkWrite(path, diskOffset) {
	const existed = assertRealFileIfExists(path);
	if (diskOffset === 0) {
		// O_CREAT is included even when the file already exists (harmless
		// without O_EXCL - it just opens it) because some platforms reject
		// O_TRUNC without O_CREAT outright (e.g. Windows: EINVAL).
		const flags = existed ? O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW : O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW;
		return open(path, flags, 0o600);
	}
	return open(path, O_RDWR | O_NOFOLLOW);
}

// ---- v2 chunked-GCM write path ----------------------------------------------

// Read the tail record currently on disk (the last, possibly partial, record
// - by construction there is nothing after it) so a non-chunk-aligned write
// can verify it before resealing it with the new bytes appended.
async function readTailRecord(path, recordStart) {
	// The tail record must already be a real file on disk (this is only called
	// when resealing an existing partial v2 blob) - reject a symlink rather
	// than reading through it. A missing file falls through to open()'s own
	// ENOENT, unchanged from before.
	assertRealFileIfExists(path);
	const fh = await open(path, O_RDONLY | O_NOFOLLOW);
	try {
		const st = await fh.stat();
		const len = st.size - recordStart;
		if (len <= 0) throw new Error('at-rest reseal: expected tail record missing on disk');
		const buf = Buffer.alloc(len);
		const { bytesRead } = await fh.read(buf, 0, len, recordStart);
		if (bytesRead !== len) throw new Error('at-rest reseal: short read of tail record');
		return buf;
	} finally {
		await fh.close();
	}
}

async function writeChunkV2(path, offset, data, enc) {
	const fileKey = fileKeyForV2(enc.fileId, enc.fileSalt, enc.keyId);
	const startRec = Math.floor(offset / PLAIN_CHUNK);
	let plaintext = Buffer.from(data);

	if (offset % PLAIN_CHUNK !== 0) {
		// This write starts mid-chunk: the last record on disk is partial and
		// must be verified and RESEALED (fresh nonce) with the new bytes
		// appended, never blindly appended to - see filecrypt.js's nonce note.
		const existing = await readTailRecord(path, startRec * FULL_RECORD);
		const existingPlain = openRecordV2(fileKey, enc.keyId, enc.fileId, startRec, existing);
		plaintext = Buffer.concat([existingPlain, plaintext]);
	}

	const records = [];
	for (let o = 0; o < plaintext.length; o += PLAIN_CHUNK) {
		const chunkIndex = startRec + records.length;
		const chunkPlain = plaintext.subarray(o, Math.min(o + PLAIN_CHUNK, plaintext.length));
		records.push(sealRecordV2(fileKey, enc.keyId, enc.fileId, chunkIndex, chunkPlain));
	}

	// Records only ever grow or append at this position, never shrink, so no
	// truncation is needed beyond the very first bytes of the file (disk
	// offset 0) - see openBlobForChunkWrite() above for the symlink-safe open.
	const diskOffset = startRec * FULL_RECORD;
	const fh = await openBlobForChunkWrite(path, diskOffset);
	try {
		let pos = diskOffset;
		for (const rec of records) {
			await fh.write(rec, 0, rec.length, pos);
			pos += rec.length;
		}
	} finally {
		await fh.close();
	}

	// Disk size != plaintext size for v2 (see the format comment above), so the
	// new plaintext total is computed directly rather than stat()'d.
	return offset + data.length;
}

// Append a chunk at a known PLAINTEXT byte offset. Returns the new total
// PLAINTEXT bytes received (v1/plaintext: equal to the resulting on-disk
// size; v2: the disk holds more bytes than this - see plainSize()). Writing
// at an explicit position makes retries idempotent and lets a client resume
// from the server-reported offset after an interruption. `enc` (build with
// fileEnc()) selects the at-rest format; null means the blob is stored raw.
export async function writeChunk(shareId, fileId, offset, data, enc) {
	const dir = shareDir(shareId);
	// Checked BEFORE mkdir: Node's recursive mkdir stats (follows symlinks) to
	// decide "does this already resolve to a directory", so a symlink planted
	// at the share-dir path would otherwise be silently reused rather than
	// rejected. lstat here catches that up front.
	assertRealDirIfExists(config.storageDir);
	assertRealDirIfExists(dir);
	await mkdir(dir, { recursive: true, mode: 0o700 });
	const path = blobPath(shareId, fileId);
	const buf = data instanceof Uint8Array ? data : new Uint8Array(data);

	if (enc?.version === 2) return writeChunkV2(path, offset, buf, enc);

	const plain = enc?.version === 1 ? transformAt(enc.iv, offset, buf) : buf;
	return writeChunkPlain(path, offset, plain);
}

// ---- v2 chunked-GCM read path -----------------------------------------------

// Pull ciphertext bytes from `reader` until a full FULL_RECORD is buffered, or
// the source ends (in which case whatever remains is the file's final,
// naturally-partial record). Returns null once nothing is left to read.
function tailRecordReader(reader) {
	let buffered = Buffer.alloc(0);
	let sourceDone = false;
	return async function next() {
		while (buffered.length < FULL_RECORD && !sourceDone) {
			const { done, value } = await reader.read();
			if (done) {
				sourceDone = true;
				break;
			}
			buffered = Buffer.concat([buffered, Buffer.from(value)]);
		}
		if (buffered.length === 0) return null;
		const take = Math.min(buffered.length, FULL_RECORD);
		const rec = buffered.subarray(0, take);
		buffered = buffered.subarray(take);
		return rec;
	};
}

// A plaintext ReadableStream for the byte range [start, end] inclusive of a v2
// (chunked AES-256-GCM) blob. Maps the plaintext range onto its covering
// records, decrypts+authenticates each one in full BEFORE any of that
// record's plaintext is enqueued, and trims the first/last record down to
// exactly the requested bytes. A record that fails authentication, or a disk
// layout that runs out of bytes before the requested range is satisfied,
// errors the stream rather than releasing unverified or partial plaintext.
function blobRangeStreamV2(shareId, fileId, start, end, enc) {
	const firstRec = Math.floor(start / PLAIN_CHUNK);
	const lastRec = Math.floor(end / PLAIN_CHUNK);
	const path = blobPath(shareId, fileId);
	// Reject a symlink planted at the blob leaf itself (blobPath() already
	// checked the directory components above it). A missing file is not
	// rejected here - it falls through to diskSize=0 below, unchanged.
	assertRealFileIfExists(path);
	const diskStart = firstRec * FULL_RECORD;
	let diskSize;
	try {
		diskSize = statSync(path).size;
	} catch {
		diskSize = 0;
	}
	const diskEnd = Math.min(diskSize, (lastRec + 1) * FULL_RECORD) - 1;
	if (diskEnd < diskStart) {
		return new ReadableStream({
			start(c) {
				c.error(new Error('at-rest record layout mismatch: no data at the requested range'));
			},
		});
	}

	const reader = Readable.toWeb(createReadStream(path, { start: diskStart, end: diskEnd })).getReader();
	const nextRecord = tailRecordReader(reader);
	const fileKey = fileKeyForV2(enc.fileId, enc.fileSalt, enc.keyId);

	let chunkIndex = firstRec;
	let skip = start % PLAIN_CHUNK; // plaintext bytes to drop from the first record
	const wantTotal = end - start + 1;
	let emitted = 0;

	return new ReadableStream({
		async pull(controller) {
			try {
				while (emitted < wantTotal) {
					const rec = await nextRecord();
					if (!rec) {
						controller.error(new Error('at-rest record layout mismatch: unexpected end of blob'));
						return;
					}
					let plain;
					try {
						plain = openRecordV2(fileKey, enc.keyId, enc.fileId, chunkIndex, rec);
					} catch (e) {
						// The GCM auth-tag (or malformed-record) throw - tamper/corruption
						// signal. Audited here, at the exact point it surfaces, then
						// rethrown so the outer catch below still errors the stream exactly
						// as before.
						audit('file.integrity_failure', { target: fileId, detail: { chunkIndex } });
						throw e;
					}
					chunkIndex++;
					let out = plain;
					if (skip > 0) {
						const drop = Math.min(skip, out.length);
						out = out.subarray(drop);
						skip -= drop;
					}
					const remaining = wantTotal - emitted;
					if (out.length > remaining) out = out.subarray(0, remaining);
					if (out.length > 0) {
						controller.enqueue(new Uint8Array(out));
						emitted += out.length;
						return; // one enqueue per pull(); the runtime calls pull() again
					}
					// out.length === 0 (fully consumed by `skip`): loop for the next record.
				}
				controller.close();
			} catch (e) {
				controller.error(e);
			}
		},
		cancel(reason) {
			reader.cancel(reason);
		},
	});
}

// A plaintext ReadableStream for the byte range [start, end] inclusive. Reads the
// ciphertext slice and decrypts it (when the file has an at-rest format). Used
// for download, preview, and zip so plaintext is only ever produced for an
// authorized request. `enc` (build with fileEnc()) selects the at-rest
// format; null means the blob is stored raw.
export function blobRangeStream(shareId, fileId, start, end, enc) {
	if (end < start) return new ReadableStream({ start(c) { c.close(); } });
	if (enc?.version === 2) return blobRangeStreamV2(shareId, fileId, start, end, enc);
	const path = blobPath(shareId, fileId);
	// Reject a symlink planted at the blob leaf itself (blobPath() already
	// checked the directory components above it). A missing file is not
	// rejected here - createReadStream below emits its own ENOENT, unchanged.
	assertRealFileIfExists(path);
	// Not Bun.file().slice(start, end).stream(): Bun ignores the slice end when
	// streaming and reads from `start` to EOF in huge buffered chunks, so on a
	// large blob a small Range request never terminates (the client hangs after
	// Content-Length bytes) and each seek materializes the file tail in memory.
	// fs.createReadStream honors start/end and reads in small chunks.
	const src = Readable.toWeb(createReadStream(path, { start, end }));
	if (enc?.version === 1) return decryptStream(enc.iv, start, src);
	return src;
}

// Bytes actually occupied on DISK. For a v2 file this is MORE than the
// plaintext size (per-chunk framing overhead - see the format comment
// above); callers that want the logical length must use plainSize() instead.
// Not used by any route today; kept for callers that specifically want the
// physical footprint.
export function blobSize(shareId, fileId) {
	const path = blobPath(shareId, fileId);
	if (!existsSync(path)) return 0;
	try {
		assertRealFileIfExists(path); // reject a symlink at the leaf; treat like "absent"
		return Bun.file(path).size;
	} catch {
		return 0;
	}
}

// A Bun file handle for streaming. Callers use .stream() / .slice() / .size.
export function blobFile(shareId, fileId) {
	const path = blobPath(shareId, fileId);
	assertRealFileIfExists(path); // reject a symlink at the leaf (missing is fine - not created yet)
	return Bun.file(path);
}

// Tracks share ids whose on-disk blobs are currently being removed by an
// in-flight deleteShareFiles() call, so a slug-reuse hard-delete-and-reinsert
// (routes/api.js) can tell "this id's directory is still being torn down"
// apart from "already gone" and wait/retry instead of writing into a
// directory a concurrent rm() is still walking. Tracked here (not per-caller)
// so every route that deletes a share's files - the web portal (shares.js),
// the API-key backup flow (api.js), and the sweeper (server.js) - shares one
// source of truth, regardless of which of them triggered the cleanup.
const cleanupPending = new Set();
export function isCleanupPending(shareId) {
	return cleanupPending.has(shareId);
}

export async function deleteShareFiles(shareId) {
	cleanupPending.add(shareId);
	try {
		await rm(shareDir(shareId), { recursive: true, force: true });
	} finally {
		cleanupPending.delete(shareId);
	}
}

// Rename a share's storage directory (used when an admin changes the slug).
// Both ids are validated by shareDir(); no-op if the source does not exist.
export async function renameShareDir(oldId, newId) {
	const from = shareDir(oldId);
	const to = shareDir(newId);
	if (from === to) return;
	if (existsSync(from)) await rename(from, to);
}

export async function deleteBlob(shareId, fileId) {
	await rm(blobPath(shareId, fileId), { force: true });
}

// Total bytes currently on disk under storageDir. Used for the storage cap and
// the admin dashboard.
export async function totalUsage() {
	let total = 0;
	let dirs;
	try {
		dirs = await readdir(config.storageDir, { withFileTypes: true });
	} catch {
		return 0;
	}
	for (const d of dirs) {
		if (!d.isDirectory()) continue;
		let files;
		try {
			files = await readdir(join(config.storageDir, d.name), { withFileTypes: true });
		} catch {
			continue;
		}
		for (const f of files) {
			if (!f.isFile()) continue;
			try {
				total += (await stat(join(config.storageDir, d.name, f.name))).size;
			} catch {
				/* ignore */
			}
		}
	}
	return total;
}
