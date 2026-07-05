// Filesystem storage. Blobs live at <storageDir>/<shareId>/<fileId>. The on-disk
// name is always the opaque file id - never the user-supplied filename - which
// removes the entire class of path-traversal and overwrite bugs. Every public
// path is additionally validated to stay within storageDir.

import { mkdir, open, rm, stat, readdir, rename } from 'node:fs/promises';
import { existsSync, createReadStream } from 'node:fs';
import { Readable } from 'node:stream';
import { join, resolve, sep } from 'node:path';
import { config } from '../config.js';
import { transformAt, decryptStream } from './filecrypt.js';

// Random ids use the ids.js alphabet; custom share slugs add - and _. Neither
// dots nor path separators are allowed, so a segment can never escape its dir.
const ID = /^[0-9A-Za-z_-]+$/;

function safeSegment(id) {
	if (typeof id !== 'string' || !ID.test(id)) throw new Error('invalid storage id');
	return id;
}

export function shareDir(shareId) {
	return join(config.storageDir, safeSegment(shareId));
}

export function blobPath(shareId, fileId) {
	const p = resolve(shareDir(shareId), safeSegment(fileId));
	// Defense in depth: the resolved path must stay under storageDir.
	if (p !== config.storageDir && !p.startsWith(config.storageDir + sep)) {
		throw new Error('path escapes storage root');
	}
	return p;
}

// Append a chunk at a known byte offset. Returns the new total bytes on disk.
// Writing at an explicit position makes retries idempotent and lets a client
// resume from the server-reported offset after an interruption. When `iv` is
// given the chunk is encrypted (AES-CTR) at its offset before being written, so
// the on-disk blob is always ciphertext. Ciphertext length == plaintext length,
// so the offset math and reported sizes are unchanged.
export async function writeChunk(shareId, fileId, offset, data, iv) {
	await mkdir(shareDir(shareId), { recursive: true });
	const path = blobPath(shareId, fileId);
	const flags = offset === 0 ? 'w' : 'r+';
	const fh = await open(path, flags);
	try {
		let buf = data instanceof Uint8Array ? data : new Uint8Array(data);
		if (iv) buf = transformAt(iv, offset, buf);
		await fh.write(buf, 0, buf.length, offset);
	} finally {
		await fh.close();
	}
	const s = await stat(path);
	return s.size;
}

// A plaintext ReadableStream for the byte range [start, end] inclusive. Reads the
// ciphertext slice and decrypts it (when the file has an iv). Used for download,
// preview, and zip so plaintext is only ever produced for an authorized request.
export function blobRangeStream(shareId, fileId, start, end, iv) {
	// Not Bun.file().slice(start, end).stream(): Bun ignores the slice end when
	// streaming and reads from `start` to EOF in huge buffered chunks, so on a
	// large blob a small Range request never terminates (the client hangs after
	// Content-Length bytes) and each seek materializes the file tail in memory.
	// fs.createReadStream honors start/end and reads in small chunks.
	if (end < start) return new ReadableStream({ start(c) { c.close(); } });
	const src = Readable.toWeb(createReadStream(blobPath(shareId, fileId), { start, end }));
	if (iv) return decryptStream(iv, start, src);
	return src;
}

export function blobSize(shareId, fileId) {
	const path = blobPath(shareId, fileId);
	if (!existsSync(path)) return 0;
	try {
		return Bun.file(path).size;
	} catch {
		return 0;
	}
}

// A Bun file handle for streaming. Callers use .stream() / .slice() / .size.
export function blobFile(shareId, fileId) {
	return Bun.file(blobPath(shareId, fileId));
}

export async function deleteShareFiles(shareId) {
	await rm(shareDir(shareId), { recursive: true, force: true });
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
