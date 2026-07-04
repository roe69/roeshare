// Resumable upload endpoints (share owner only, via X-Edit-Token). A file is
// registered first (declaring name/size/mime), then its bytes are streamed in
// with PATCH requests at explicit offsets so an interrupted upload can resume
// from the server-reported `received` count. Caps are enforced server-side:
// per-file, per-share, and (optionally) total on-disk usage.

import { config } from '../config.js';
import { db, now } from '../db.js';
import { json, error } from '../lib/http.js';
import { safeEqual } from '../lib/crypto.js';
import { writeChunk, totalUsage } from '../lib/storage.js';
import { newFileId } from '../lib/ids.js';
import { newIv } from '../lib/filecrypt.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';
import { recordKeyUsage, apiKeyRow, effectiveCaps } from '../lib/apikeys.js';
import { enforce } from '../lib/ratelimit.js';

const getShare = db.query('SELECT id, edit_token, expires_at, e2e, creator_ip, api_key_id FROM shares WHERE id = ? AND deleted_at IS NULL');
const shareTotal = db.query('SELECT COALESCE(SUM(size), 0) AS total, COUNT(*) AS count FROM files WHERE share_id = ?');
const insertFile = db.query(
	'INSERT INTO files (id, share_id, name, size, received, mime, complete, download_count, created_at, stored_name, iv) VALUES (?, ?, ?, ?, 0, ?, 0, 0, ?, ?, ?)'
);
const getFile = db.query('SELECT id, size, received, complete, iv FROM files WHERE id = ? AND share_id = ?');
const updateReceived = db.query('UPDATE files SET received = ?, complete = ? WHERE id = ?');

// Keep a SAFE relative path so dragged folders preserve their structure (used as
// the display name and the zip entry path). Drops any "." / ".." / empty / drive
// segments and control chars, so it can never traverse - and it is never used as
// an on-disk path anyway (blobs are stored under the generated file id).
function sanitizeName(name) {
	const parts = String(name ?? '')
		.split(/[/\\]+/)
		.map(s => s.replace(/[\x00-\x1f\x7f]/g, '').replace(/^[A-Za-z]:$/, '').trim())
		.filter(s => s && s !== '.' && s !== '..');
	return parts.join('/').slice(0, 1024) || 'file';
}

// Resolve the share and verify the edit token. Returns the share row, or a
// Response to short-circuit on failure (404 missing/deleted, 403 bad token).
function authShare(req, id) {
	const share = getShare.get(id);
	// Reject missing, soft-deleted, and expired shares (mirrors the read-path
	// liveShare gate) so writes cannot land on a share that view/download already
	// treat as gone.
	if (!share || (share.expires_at !== null && share.expires_at < now())) return { res: error(404, 'Share not found') };
	const token = req.headers.get('x-edit-token');
	if (!token || !safeEqual(token, share.edit_token)) return { res: error(403, 'Forbidden') };
	return { share };
}

// Serialize chunk writes per file id: concurrent PATCHes for the same file
// would otherwise all pass the offset===received check and race, each
// buffering a body. Chain them so only one runs at a time.
const fileLocks = new Map();
function withFileLock(fileId, fn) {
	const prev = fileLocks.get(fileId) || Promise.resolve();
	// Run after prev settles either way, so one failed chunk never wedges the
	// chain for the ones behind it.
	const task = prev.then(fn, fn);
	fileLocks.set(fileId, task);
	const cleanup = () => {
		// Only the current tail clears the entry - if another PATCH has already
		// chained onto us, the map must keep pointing at that newer tail.
		if (fileLocks.get(fileId) === task) fileLocks.delete(fileId);
	};
	task.then(cleanup, cleanup);
	return task;
}

export default function uploads(router) {
	// Register a file against a share before streaming its bytes.
	router.post('/api/shares/:id/files', async ({ req, params, ip }) => {
		const { share, res } = authShare(req, params.id);
		if (res) return res;

		// Bounds the 10000-file-flood metadata-bloat vector (each registration is
		// cheap on its own, but a flood of them still grows the files table).
		const limited = enforce('file-reg', ip, 300, 60_000);
		if (limited) return limited;

		let body;
		try {
			body = await req.json();
		} catch {
			return error(400, 'Invalid JSON body');
		}

		const name = sanitizeName(body?.name);
		const size = Number(body?.size);
		if (!Number.isFinite(size) || size < 0 || !Number.isInteger(size)) return error(400, 'Invalid size');
		const mime = typeof body?.mime === 'string' && body.mime ? body.mime : 'application/octet-stream';

		// When the share was created via an API key, its per-file/per-share caps
		// apply on top of the server limits (clamped, never larger).
		const caps = share.api_key_id ? effectiveCaps(apiKeyRow(share.api_key_id)) : { maxFileSize: config.maxFileSize, maxShareSize: config.maxShareSize };

		if (size > caps.maxFileSize) return error(413, 'File exceeds the per-file size limit');

		const agg = shareTotal.get(share.id);
		// Cap the number of files so a flood of (e.g. zero-byte) registrations
		// cannot bloat the files table and the metadata/admin code paths.
		if (agg.count >= config.maxFilesPerShare) return error(413, 'Too many files in this share');
		if (agg.total + size > caps.maxShareSize) return error(413, 'Share exceeds the per-share size limit');

		if (config.maxTotalSize > 0 && (await totalUsage()) + size > config.maxTotalSize) {
			return error(413, 'Server storage limit reached');
		}

		const fileId = newFileId();
		// E2E shares arrive already encrypted by the client - store the bytes raw
		// (iv = null means storage does not apply its own encryption layer).
		insertFile.run(fileId, share.id, name, size, mime, now(), fileId, share.e2e ? null : newIv());
		return json({ fileId, received: 0 });
	});

	// Report how many bytes are on disk so a client can resume.
	router.get('/api/shares/:id/files/:fileId/status', ({ req, params }) => {
		const { share, res } = authShare(req, params.id);
		if (res) return res;
		const file = getFile.get(params.fileId, share.id);
		if (!file) return error(404, 'File not found');
		return json({ received: file.received, size: file.size, complete: !!file.complete });
	});

	// Append a chunk of raw bytes at the given offset.
	router.patch('/api/shares/:id/files/:fileId', async ({ req, params, query }) => {
		const { share, res } = authShare(req, params.id);
		if (res) return res;

		// Everything below is serialized per file id: concurrent PATCHes for the
		// same file would otherwise all read the same `received` and race past the
		// offset check, each buffering a body before either one has written.
		return withFileLock(params.fileId, async () => {
			const file = getFile.get(params.fileId, share.id);
			if (!file) return error(404, 'File not found');

			const offset = Number(query.get('offset'));
			if (!Number.isFinite(offset) || offset < 0) return error(400, 'Invalid offset');
			if (offset !== file.received) return error(409, 'Offset mismatch', { received: file.received });

			// Reject oversized chunks BEFORE buffering the body into memory. A single
			// chunk may never exceed chunkSize, and offset+len may never exceed the
			// declared file size. This caps per-request memory and stops a flood of
			// max-body PATCHes (each ~64 MiB) from being read in just to 413 them.
			// E2E chunks carry a small per-record overhead (12-byte IV + 16-byte GCM
			// tag); allow a 64-byte margin over chunkSize so they are not rejected.
			const declaredLen = Number(req.headers.get('content-length'));
			if (Number.isFinite(declaredLen) && declaredLen >= 0) {
				if (declaredLen > config.chunkSize + 64) return error(413, 'Chunk exceeds the maximum chunk size');
				if (offset + declaredLen > file.size) return error(413, 'Chunk exceeds declared file size');
			}

			const buf = await req.arrayBuffer();
			const chunk = new Uint8Array(buf);
			// The Content-Length guard above is skipped entirely when the client
			// omits it (e.g. chunked transfer encoding, where Number(null) === 0
			// would otherwise pass as "0 <= 0"). Cap the actual bytes read too, so
			// that path cannot smuggle an oversized chunk past the header check.
			if (chunk.length > config.chunkSize + 64) return error(413, 'Chunk exceeds the maximum chunk size');
			if (file.received + chunk.length > file.size) return error(413, 'Chunk exceeds declared file size');

			const received = await writeChunk(share.id, file.id, offset, chunk, file.iv);
			const complete = received === file.size ? 1 : 0;
			updateReceived.run(received, complete, file.id);
			// Lifetime stats when a file first finishes (persist past deletion).
			if (complete && !file.complete) {
				bumpMetric('files_uploaded');
				bumpMetric('bytes_uploaded', file.size);
				bumpUploader(share.creator_ip, { bytes: file.size });
				// Attribute the bytes to the API key when this share was created via one.
				if (share.api_key_id) recordKeyUsage(share.api_key_id, { bytes: file.size });
			}
			return json({ received, complete: !!complete });
		});
	});
}
