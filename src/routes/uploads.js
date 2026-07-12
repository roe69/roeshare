// Resumable upload endpoints (share owner only, via X-Edit-Token). A file is
// registered first (declaring name/size/mime), then its bytes are streamed in
// with PATCH requests at explicit offsets so an interrupted upload can resume
// from the server-reported `received` count. Caps are enforced server-side:
// per-file, per-share, and (optionally) total on-disk usage.

import { createHash } from 'node:crypto';
import { config } from '../config.js';
import { db, now } from '../db.js';
import { json, error, readJson, requireSameOrigin, METADATA_BODY_MAX } from '../lib/http.js';
import { verifySecretToken } from '../lib/crypto.js';
import { hasOwnerCookie } from '../lib/auth.js';
import { writeChunk, blobRangeStream, fileEnc } from '../lib/storage.js';
import { newFileId } from '../lib/ids.js';
import { newFileSalt } from '../lib/filecrypt.js';
import { CURRENT_AT_REST_KEY_ID } from '../lib/keys.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';
import { recordKeyUsage, apiKeyRow, effectiveCaps, keyValidForShare, scopeErrorForShare } from '../lib/apikeys.js';
import { enforceKey } from '../lib/ratelimit.js';
import { reserveInTx, commitInTx, touchInTx } from '../lib/quota.js';
import { acquireAll, overloaded, takeBytes } from '../lib/semaphore.js';
import { declareRoutePolicy } from '../lib/routePolicy.js';

const getShare = db.query('SELECT id, edit_token, expires_at, e2e, creator_ip, api_key_id, finalized FROM shares WHERE id = ? AND deleted_at IS NULL');
const shareTotal = db.query('SELECT COALESCE(SUM(size), 0) AS total, COUNT(*) AS count FROM files WHERE share_id = ?');
const insertFile = db.query(
	'INSERT INTO files (id, share_id, name, size, received, mime, complete, download_count, created_at, stored_name, iv, enc_version, key_id) VALUES (?, ?, ?, ?, 0, ?, 0, 0, ?, ?, ?, ?, ?)'
);
const getFile = db.query('SELECT id, size, received, complete, iv, enc_version, key_id FROM files WHERE id = ? AND share_id = ?');
const updateReceived = db.query('UPDATE files SET received = ?, complete = ? WHERE id = ?');
const updateSha256 = db.query('UPDATE files SET sha256 = ? WHERE id = ?');

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

// Resolve the share and verify ownership (X-Edit-Token header, or - M-05 - the
// per-share owner cookie). Returns { share, via: 'header'|'cookie' }, or a
// Response to short-circuit on failure (404 missing/deleted, 403 bad token).
// `via` lets the two write routes below require same-origin proof only for the
// ambient-cookie path, exactly like every other owner-gated route in this app
// (see shares.js's ownerVia + the F-10 convention) - the header path carries
// no ambient credential and needs none.
function authShare(req, id) {
	const share = getShare.get(id);
	// Reject missing, soft-deleted, and expired shares (mirrors the read-path
	// liveShare gate) so writes cannot land on a share that view/download already
	// treat as gone. A NON-finalized share is never treated as expired mid-upload:
	// its published-link expiry clock does not start until finalize, so a slow
	// multi-GB upload cannot be 404'd (and its partial blobs swept) while it is
	// still in progress.
	if (!share || (share.finalized && share.expires_at !== null && share.expires_at < now())) return { res: error(404, 'Share not found') };
	const token = req.headers.get('x-edit-token');
	if (token && verifySecretToken(token, share.edit_token)) return { share, via: 'header' };
	if (hasOwnerCookie(req, share)) return { share, via: 'cookie' };
	return { res: error(403, 'Forbidden') };
}

// A finalized share is checked at the top of both write routes (registration and
// chunk upload), right after authShare(): once finalized its file set is closed,
// so neither new registrations nor further chunk bytes may land.
function checkFinalized(share) {
	if (share.finalized) return error(409, 'Share is finalized and no longer accepts new files');
	return null;
}

// When the share was created via an API key, a key that has since been revoked
// or expired must lose write access through the edit-token path too - otherwise
// revoking/expiring a key only blocks its own bearer-token API calls while the
// share it already created keeps accepting uploads via the edit token forever.
// keyValidForShare (lib/apikeys.js) is shared with shares.js isOwner()/
// finalize/DELETE and download.js accessCheck(), so every owner-gated route
// treats a revoked key's edit token the same way, not just this file's.
function checkKeyValid(share) {
	return keyValidForShare(share) ? null : error(403, 'API key is no longer valid');
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
	declareRoutePolicy('POST', '/api/shares/:id/files', { auth: 'editTokenOrKey', csrf: true, rateLimit: 'file-reg', audit: null });
	router.post('/api/shares/:id/files', async ({ req, params }) => {
		const { share, res, via } = authShare(req, params.id);
		if (res) return res;
		if (via === 'cookie') {
			const csrf = requireSameOrigin(req);
			if (csrf) return csrf;
		}
		const finalizedErr = checkFinalized(share);
		if (finalizedErr) return finalizedErr;
		const keyErr = checkKeyValid(share);
		if (keyErr) return keyErr;
		const scopeErr = scopeErrorForShare(share, 'write');
		if (scopeErr) return scopeErr;

		// Bounds the 10000-file-flood metadata-bloat vector (each registration is
		// cheap on its own, but a flood of them still grows the files table). Keyed
		// by share id (not ip) so unrelated concurrent uploaders sharing a NAT or
		// host do not throttle each other, while a single share is still bounded.
		const limited = enforceKey('file-reg', share.id, 300, 60_000);
		if (limited) return limited;

		const { value, response: bodyErr } = await readJson(req, METADATA_BODY_MAX);
		if (bodyErr) return bodyErr;
		const body = value || {};

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

		const fileId = newFileId();
		// E2E shares arrive already encrypted by the client - store the bytes raw
		// (iv = null means storage does not apply its own encryption layer). A
		// non-E2E file only gets an iv (and thus server-side encryption) when
		// at-rest encryption is enabled; this is the only place ENCRYPT_AT_REST
		// affects new writes - existing files keep decrypting via their own iv
		// regardless of this setting (see storage.js). Every new row is stamped
		// enc_version=2/key_id=CURRENT_AT_REST_KEY_ID unconditionally - both
		// columns are inert whenever iv is null.
		const iv = share.e2e || !config.encryptAtRest ? null : newFileSalt();

		// Re-check the per-share aggregate, atomically reserve global quota, and
		// insert - all inside one synchronous transaction: the `agg` snapshot
		// above can go stale under concurrent registrations against the same
		// share (or against the server's global cap), each passing the same
		// stale check and together exceeding maxShareSize/maxTotalSize.
		// Re-reading fresh and reserving right before the insert (with no await
		// in between) closes both races - reserveInTx is what makes the global
		// cap atomic instead of the old cached-disk-walk check-then-act.
		const registered = db.transaction(() => {
			const fresh = shareTotal.get(share.id);
			if (fresh.total + size > caps.maxShareSize) return 'share';
			if (!reserveInTx(fileId, share.id, size)) return 'server';
			insertFile.run(fileId, share.id, name, size, mime, now(), fileId, iv, 2, CURRENT_AT_REST_KEY_ID);
			return true;
		})();
		if (registered === 'share') return error(413, 'Share exceeds the per-share size limit');
		if (registered === 'server') return error(413, 'Server storage limit reached');

		return json({ fileId, received: 0 });
	});

	// Report how many bytes are on disk so a client can resume.
	declareRoutePolicy('GET', '/api/shares/:id/files/:fileId/status', { auth: 'editTokenOrKey', csrf: false, rateLimit: null, audit: null });
	router.get('/api/shares/:id/files/:fileId/status', ({ req, params }) => {
		const { share, res } = authShare(req, params.id);
		if (res) return res;
		const keyErr = checkKeyValid(share);
		if (keyErr) return keyErr;
		const scopeErr = scopeErrorForShare(share, 'write');
		if (scopeErr) return scopeErr;
		const file = getFile.get(params.fileId, share.id);
		if (!file) return error(404, 'File not found');
		return json({ received: file.received, size: file.size, complete: !!file.complete });
	});

	// Append a chunk of raw bytes at the given offset.
	declareRoutePolicy('PATCH', '/api/shares/:id/files/:fileId', { auth: 'editTokenOrKey', csrf: true, rateLimit: 'chunk-patch', audit: null });
	router.patch('/api/shares/:id/files/:fileId', async ({ req, params, query }) => {
		const { share, res, via } = authShare(req, params.id);
		if (res) return res;
		if (via === 'cookie') {
			const csrf = requireSameOrigin(req);
			if (csrf) return csrf;
		}
		const finalizedErr = checkFinalized(share);
		if (finalizedErr) return finalizedErr;
		const keyErr = checkKeyValid(share);
		if (keyErr) return keyErr;
		const scopeErr = scopeErrorForShare(share, 'write');
		if (scopeErr) return scopeErr;

		// This is the highest-request-volume endpoint in the app (one PATCH per
		// chunk), so it gets a generous per-share ceiling rather than none.
		const limited = enforceKey('chunk-patch', share.id, 1200, 60_000);
		if (limited) return limited;

		// Admission control: bound the number of concurrent chunk bodies being
		// buffered into memory, both per-share (a client uploads a few chunks in
		// parallel) and globally (worst-case chunk-buffer memory). This is
		// separate from withFileLock below, which serializes writes for the SAME
		// file id - the semaphore instead limits how many DIFFERENT chunk
		// requests (any file, any share) may be in flight at once.
		const release = acquireAll([
			['chunk', share.id, 6],
			['chunk-global', null, 32],
		]);
		if (!release) return overloaded(2);

		try {
			// Everything below is serialized per file id: concurrent PATCHes for the
			// same file would otherwise all read the same `received` and race past the
			// offset check, each buffering a body before either one has written.
			return await withFileLock(params.fileId, async () => {
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

				// M-04: byte-rate budget, keyed the same as the 'chunk'/'chunk-global'
				// admission-control slots just above (per share). Charged BEFORE
				// buffering the body into memory, using the declared length when the
				// client sent one, or the worst-case chunkSize otherwise, so an
				// over-budget client is rejected without paying for the read first.
				if (config.uploadBytesPerSec > 0) {
					const rateCost = Number.isFinite(declaredLen) && declaredLen >= 0 ? declaredLen : config.chunkSize;
					const rateLimited = takeBytes('chunk-bytes', share.id, rateCost, config.uploadBytesPerSec * 4, config.uploadBytesPerSec);
					if (rateLimited) return rateLimited;
				}

				const buf = await req.arrayBuffer();
				const chunk = new Uint8Array(buf);
				// The Content-Length guard above is skipped entirely when the client
				// omits it (e.g. chunked transfer encoding, where Number(null) === 0
				// would otherwise pass as "0 <= 0"). Cap the actual bytes read too, so
				// that path cannot smuggle an oversized chunk past the header check.
				if (chunk.length > config.chunkSize + 64) return error(413, 'Chunk exceeds the maximum chunk size');
				if (file.received + chunk.length > file.size) return error(413, 'Chunk exceeds declared file size');

				const received = await writeChunk(share.id, file.id, offset, chunk, fileEnc(file));
				const complete = received === file.size ? 1 : 0;
				// Commit the file's bytes from "reserved" to "used" the moment it
				// finishes, or touch the reservation's TTL forward otherwise - a live
				// multi-day upload's quota hold must never be reaped out from under it
				// just because a single chunk PATCH took a while. Same transaction as
				// the received/complete write so a crash between them cannot desync
				// the ledger from what the row says.
				db.transaction(() => {
					updateReceived.run(received, complete, file.id);
					if (complete && !file.complete) commitInTx(file.id, file.size);
					else touchInTx(file.id);
				})();
				// Lifetime stats when a file first finishes (persist past deletion).
				if (complete && !file.complete) {
					bumpMetric('files_uploaded');
					bumpMetric('bytes_uploaded', file.size);
					bumpUploader(share.creator_ip, { bytes: file.size });
					// Attribute the bytes to the API key when this share was created via one.
					if (share.api_key_id) recordKeyUsage(share.api_key_id, { bytes: file.size });

					// Content digest, computed once here (not per chunk) over the plaintext -
					// the same decrypt path download.js uses - so it is correct for at-rest
					// encrypted files too.
					const hash = createHash('sha256');
					const plaintext = blobRangeStream(share.id, file.id, 0, file.size - 1, fileEnc(file));
					for await (const part of plaintext) hash.update(part);
					updateSha256.run(hash.digest('hex'), file.id);
				}
				return json({ received, complete: !!complete });
			});
		} finally {
			release();
		}
	});
}
