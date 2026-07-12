// Streaming endpoints for share visitors: inline preview, single-file download,
// and a whole-share zip. All three are Range-aware (preview/single download) and
// enforce the same access gate: the share must be live (exists, not soft-deleted,
// not expired) and, when password-protected, the caller must present a valid
// access token or the owner edit token. Only complete files are ever streamed.

import { db, now } from '../db.js';
import { config } from '../config.js';
import { error, parseRange, contentDisposition, FILE_SECURITY_HEADERS, SECURITY_HEADERS } from '../lib/http.js';
import { verifySecretToken } from '../lib/crypto.js';
import { readAccessToken, hasAccessToken, hasOwnerCookie } from '../lib/auth.js';
import { verifyApiKey, readApiKey, readApiKeySession, keyValidForShare, apiKeyRow, hasScope } from '../lib/apikeys.js';
import { blobPath, blobRangeStream, deleteShareFiles, fileEnc, plainSize } from '../lib/storage.js';
import { scheduleMigration, awaitFileMigration } from '../lib/migrate.js';
import { isRenamePending } from '../lib/renames.js';
import { createZipStream } from '../lib/zip.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';
import { enforce } from '../lib/ratelimit.js';
import { acquire, acquireAll, overloaded, takeBytes } from '../lib/semaphore.js';
import * as quota from '../lib/quota.js';
import { audit } from '../lib/audit.js';
import { declareRoutePolicy } from '../lib/routePolicy.js';

// Whether a resolved Range (or the absence of one) covers the ENTIRE file in
// one shot - i.e. letting the stream drain would deliver the file in full.
// Used to decide whether a request is a "full" delivery worth counting/
// claiming/burning, as opposed to a partial range probe or seek. A range that
// merely reaches the last byte (e.g. a tail probe like `bytes=-1`, or any
// start offset other than 0) is NOT full - only an unranged GET or an
// explicit `bytes=0-<size-1>` request transfers every byte of the file.
function reachesEnd(range, size) {
	return range === null || (!range.invalid && range.start === 0 && range.end === size - 1);
}

// Only these MIME types are ever served inline (rendered in the browser on our
// own origin). Everything else - HTML, SVG-with-doubt, scripts, office docs - is
// forced to a neutral octet-stream attachment so a malicious upload cannot run
// script in our origin and ride an admin's session. The view page reads text
// files via fetch(), which works regardless of disposition, so non-media text
// still previews without being navigable as an active document.
const SAFE_INLINE = new Set([
	'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp', 'image/x-icon', 'image/svg+xml',
	'video/mp4', 'video/webm', 'video/ogg',
	'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm', 'audio/aac', 'audio/flac', 'audio/mp4',
	'application/pdf',
	'text/plain',
]);

// Locked-down policy applied to every preview response: no scripts, no active
// content, only same-origin media/styles. Neutralizes any inline rendering of a
// document type (e.g. an SVG opened directly) on top of the attachment fallback.
const PREVIEW_CSP =
	"default-src 'none'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'unsafe-inline'; object-src 'self'; frame-src 'self'; script-src 'none'; base-uri 'none'; form-action 'none'";

function previewServing(mime) {
	const m = String(mime || '').toLowerCase().split(';')[0].trim();
	if (SAFE_INLINE.has(m)) return { inline: true, type: m };
	return { inline: false, type: 'application/octet-stream' };
}

const getShare = db.query('SELECT * FROM shares WHERE id = ?');
const getFile = db.query('SELECT * FROM files WHERE id = ? AND share_id = ?');
const getCompleteFiles = db.query('SELECT * FROM files WHERE share_id = ? AND complete = 1 ORDER BY created_at, id');
const incFileDownload = db.query('UPDATE files SET download_count = download_count + 1 WHERE id = ?');
const incShareDownload = db.query('UPDATE shares SET download_count = download_count + 1 WHERE id = ?');
const insertEvent = db.query('INSERT INTO download_events (share_id, file_id, ts, ip, ua) VALUES (?, ?, ?, ?, ?)');
// Atomically claim a one-time share for burning: only succeeds (changes > 0)
// if it is still live and still one-time, so two racing full deliveries can
// never both win the claim. restoreShare undoes a claim whose delivery was
// cancelled before completion, so the recipient can simply retry.
const claimOneTime = db.query('UPDATE shares SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL AND one_time = 1');
const restoreShare = db.query('UPDATE shares SET deleted_at = NULL WHERE id = ?');
// Atomically claim one slot of a download-capped share: only succeeds
// (changes > 0) while the cap has not yet been reached, so N concurrent full
// deliveries against a maxDownloads=1 share can never all win the claim - the
// same guarantee claimOneTime gives one-time shares. releaseDownload undoes a
// claim whose delivery was cancelled before completion, mirroring restoreShare.
const claimDownload = db.query('UPDATE shares SET download_count = download_count + 1 WHERE id = ? AND (max_downloads IS NULL OR download_count < max_downloads)');
const releaseDownload = db.query('UPDATE shares SET download_count = download_count - 1 WHERE id = ?');

// Resolve a file row for reading, first waiting out any in-flight v1->v2
// at-rest migration swap for it (lib/migrate.js, M-06). That swap window
// (two renames + one atomic UPDATE) is only ever held for a few filesystem
// syscalls, but a caller that already fetched a stale v1 row must not open
// the blob path - or decrypt it with the v1 IV - while, or right after, a
// migration promotes it to v2 underneath: that would either 404 on the
// momentarily-missing path or silently decrypt v2 ciphertext with the wrong
// (v1 CTR) algorithm. Re-fetches the row only when a wait actually
// happened, so the common (no migration in flight) case pays no extra query.
async function resolveFile(shareId, fileId) {
	let file = getFile.get(fileId, shareId);
	if (file && fileEnc(file)?.version === 1 && (await awaitFileMigration(file.id))) {
		// The wait means a migration swap for this exact file just finished (or a
		// concurrent delete won the race and it never got one to finish - see
		// lib/migrate.js's withFileLock recheck). Either way the row as fetched
		// above is stale: re-fetch it fresh, and if it's gone now, say so - never
		// silently fall back to the pre-migration object, which would let a
		// caller that only null-checks `file` proceed against a row (and blob)
		// that no longer exists.
		file = getFile.get(fileId, shareId) || null;
	}
	return file;
}

// A share whose rename (admin slug change) is mid-flight - see lib/renames.js's
// isRenamePending() - must never be read: storage.js would either 404 against
// a directory that hasn't moved yet (a fabricated empty response for a legacy
// v1/plaintext blob) or blow up mid-stream once the directory disappears out
// from under an open v2 read. Mirrors semaphore.js's overloaded() shape (503 +
// Retry-After) since this is the same "try again in a moment" signal, just
// for a different resource than a concurrency slot.
function renamePendingResponse() {
	return new Response(JSON.stringify({ error: 'Share temporarily unavailable, retry shortly' }), {
		status: 503,
		headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '1', ...SECURITY_HEADERS },
	});
}

// Resolve a share that is safe to serve: present, not soft-deleted, not expired.
function liveShare(id) {
	const share = getShare.get(id);
	if (!share || share.deleted_at !== null) return null;
	if (share.expires_at !== null && share.expires_at < now()) return null;
	return share;
}

// Returns whether the caller may read the share. The owner - identified by a
// matching X-Edit-Token, or by the API key that created the share (so a backup
// client can restore its own files with just the key) - always gets access;
// otherwise a password-gated share requires a valid per-share access token.
function accessCheck(share, req, url) {
	const editToken = req.headers.get('x-edit-token');
	// A matching edit token alone is not enough when the share was made via an
	// API key that has since been revoked or expired - keyValidForShare treats
	// that exactly like an invalid token, so "revoke" actually cuts off read/
	// download access too, not just new bearer-token calls. (The api_key_id
	// branch just below is already safe: verifyApiKey/readApiKeySession reject
	// a revoked/expired key on their own.)
	let owner = !!editToken && verifySecretToken(editToken, share.edit_token) && keyValidForShare(share);
	// M-05: the per-share owner cookie is a second way to prove the exact same
	// ownership the edit token proves (same keyValidForShare gate, same
	// downstream read-scope check just below) - read-only here, so no
	// same-origin proof is needed (unlike the mutating routes in shares.js/
	// uploads.js that also accept this cookie).
	if (!owner && hasOwnerCookie(req, share) && keyValidForShare(share)) owner = true;
	// A valid edit token (or owner cookie) only grants read-owner access when
	// the backing key still holds the shares:read scope - a write-only (e.g.
	// drop-box) key's edit token must not unlock reading/downloading what it
	// uploaded.
	if (owner && share.api_key_id && !hasScope(apiKeyRow(share.api_key_id), 'read')) owner = false;
	if (!owner && share.api_key_id) {
		const key = verifyApiKey(readApiKey(req)) || readApiKeySession(req);
		if (key && key.id === share.api_key_id && hasScope(key, 'read')) owner = true;
	}
	if (owner || !share.password_hash) return { ok: true, owner };
	const token = readAccessToken(req, url);
	if (token && hasAccessToken(token, share.id, share.password_hash)) return { ok: true, owner };
	return { ok: false, owner };
}

// countShare is false for a max_downloads-capped delivery, whose slot was
// already atomically claimed (via claimDownload) up front - incrementing
// shares.download_count here too would double-count it. Event logging and
// lifetime stats always run regardless.
function recordDownload(shareId, fileId, ip, ua, creatorIp, { countShare = true } = {}) {
	const ts = now();
	if (fileId) incFileDownload.run(fileId);
	if (countShare) incShareDownload.run(shareId);
	insertEvent.run(shareId, fileId, ts, ip ?? null, ua ?? null);
	// Lifetime stats, credited to the uploader (persist past deletion).
	bumpMetric('downloads');
	bumpUploader(creatorIp, { downloads: 1 });
}

function limitReached(share) {
	return share.max_downloads !== null && share.download_count >= share.max_downloads;
}

// M-03 GAP 2: whether a share is genuinely protected in a way that makes its
// request-count bucket worth surviving a restart - password-gated, or under
// a download cap (see ratelimit.js's PERSIST_PREFIXES comment). Used below to
// pick between the SQLite-persisted 'dl:' bucket and a plain in-memory-only
// 'dlv:' bucket, so an ordinary public/unlimited share's preview/download
// requests - the highest-volume, unauthenticated, publicly-reachable path in
// the app - never pay a synchronous SQLite UPSERT. The zip bucket does not
// use this split (see ratelimit.js's file-header comment).
function isRateLimitProtected(share) {
	return !!share.password_hash || share.max_downloads !== null;
}

// Disambiguate a zip entry name against ones already used in the same archive
// (two files can share a sanitized name), inserting " (2)", " (3)", ... before
// the extension - most zip extractors silently keep only one of two identically
// named entries, so a collision must never reach createZipStream.
function uniqueZipName(name, used) {
	if (!used.has(name)) {
		used.add(name);
		return name;
	}
	const dot = name.lastIndexOf('.');
	const base = dot > 0 ? name.slice(0, dot) : name;
	const ext = dot > 0 ? name.slice(dot) : '';
	let candidate;
	let i = 2;
	do {
		candidate = `${base} (${i})${ext}`;
		i++;
	} while (used.has(candidate));
	used.add(candidate);
	return candidate;
}

// Remove a one-time share's blobs once the in-flight response has finished. The
// share row is soft-deleted up front (via claimOneTime, at claim time) so it
// disappears immediately; the bytes are only dropped after the stream drains
// (or is cancelled) so we never yank the file out from under a download that
// is still being read. Quota is released HERE, not at claim time - burnBlobs
// is the single once-only burn point shared by the single-file and zip
// one-time paths (see the burnPending/readEnd bookkeeping below), whereas a
// claim can still be undone by restoreShare if the delivery is cancelled, so
// releasing quota at claim time could reclaim bytes for a share that is about
// to un-delete itself.
function burnBlobs(shareId) {
	quota.releaseShare(shareId);
	deleteShareFiles(shareId).catch(e => console.error('one-time cleanup failed for', shareId, e));
}

// Wrap a stream so onComplete fires ONCE only when it fully drains (done),
// and onEnd fires ONCE on any termination (done, cancel, or error). A cancel
// (client disconnect / paused download / closed tab) must NOT be treated as a
// completed delivery.
function trackedStream(source, { onComplete, onEnd } = {}) {
	let ended = false;
	const end = (completed) => { if (ended) return; ended = true; if (completed) onComplete?.(); onEnd?.(); };
	const reader = source.getReader();
	return new ReadableStream({
		async pull(controller) {
			try {
				const { value, done } = await reader.read();
				if (done) { controller.close(); end(true); return; }
				controller.enqueue(value);
			} catch (e) { controller.error(e); end(false); }
		},
		cancel(reason) { reader.cancel(reason); end(false); },
	});
}

// Tracks in-flight read streams per share so a one-time burn never races a
// still-draining delivery. A full delivery bumps the count on start and drops
// it on end (whether it completed, was cancelled, or errored); if a burn was
// requested while reads were still in flight, it runs as soon as the last one
// finishes instead of racing rm -rf against live reads.
const activeReads = new Map(); // shareId -> count of in-flight streams
const burnPending = new Set(); // shareIds whose blobs should be burned once no reads remain
function readStart(id) { activeReads.set(id, (activeReads.get(id) || 0) + 1); }
function readEnd(id) {
	const n = (activeReads.get(id) || 1) - 1;
	if (n <= 0) { activeReads.delete(id); if (burnPending.has(id)) { burnPending.delete(id); burnBlobs(id); } }
	else activeReads.set(id, n);
}

// When an offload mode is configured and the file needs no server-side
// decryption (E2E, or any file when at-rest encryption is off), return the
// headers that tell the reverse proxy to serve the raw blob itself via
// sendfile; otherwise null (stream through the app as usual). Range,
// Content-Length and 206 handling are done by the proxy.
function offloadHeaders(share, file) {
	if (file.iv != null) return null;
	if (config.xAccelRedirect) {
		return { 'X-Accel-Redirect': `${config.xAccelRedirect}/${encodeURIComponent(share.id)}/${encodeURIComponent(file.id)}` };
	}
	if (config.xSendfile) {
		return { 'X-Sendfile': blobPath(share.id, file.id) };
	}
	return null;
}

// Build a Range-aware response for a single blob. makeBody optionally wraps the
// chosen stream (used to schedule one-time cleanup). A caller that has already
// stat'd the file / parsed the Range passes `size` and `range` to avoid a
// second stat syscall and re-parse on the hot streaming path.
function rangeResponse(share, file, req, opts = {}) {
	const { inline = false, contentType, makeBody, extraHeaders, head = false } = opts;
	const size = opts.size !== undefined ? opts.size : plainSize(file, share.id);
	const range = opts.range !== undefined ? opts.range : parseRange(req.headers.get('range'), size);
	if (range?.invalid) {
		return new Response(null, {
			status: 416,
			headers: { 'Content-Range': `bytes */${size}`, 'Accept-Ranges': 'bytes', ...FILE_SECURITY_HEADERS },
		});
	}
	const start = range ? range.start : 0;
	const end = range ? range.end : size - 1;
	// HEAD gets the exact status/headers a GET would, but must never open the
	// blob stream: Bun drops an unread body without cancelling it, so the
	// createReadStream fd would leak on every probe.
	let body = null;
	if (!head) {
		const decrypted = blobRangeStream(share.id, file.id, start, end, fileEnc(file));
		body = makeBody ? makeBody(decrypted) : decrypted;
	}
	return new Response(body, {
		status: range ? 206 : 200,
		headers: {
			'Content-Type': contentType || file.mime || 'application/octet-stream',
			'Content-Length': String(range ? range.length : size),
			'Accept-Ranges': 'bytes',
			'Content-Disposition': contentDisposition(file.name.split('/').pop(), inline),
			'Cache-Control': 'no-store',
			...FILE_SECURITY_HEADERS,
			...(extraHeaders || {}),
			...(range ? { 'Content-Range': `bytes ${range.start}-${range.end}/${size}` } : {}),
		},
	});
}

export default function download(router) {
	// Inline preview: never counts as a download, so it cannot be metered against
	// a one-time burn. maxDownloads caps the Download action (a saved copy), not
	// inline viewing, so a download-limited share still previews fine; one-time
	// stays blocked because inline streaming would defeat burn-on-first-access.
	declareRoutePolicy('GET', '/api/shares/:id/files/:fileId/preview', { auth: 'shareAccess', csrf: false, rateLimit: 'dl:<shareId>|dlv:<shareId>', audit: null });
	router.get('/api/shares/:id/files/:fileId/preview', async ({ req, url, params, ip, server }) => {
		server?.timeout?.(req, 0);
		// Resolve the share BEFORE rate-limiting against its id: otherwise a flood
		// of nonexistent ids would each mint their own bucket in the process-wide
		// rate-limit map at zero cost to the attacker.
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		// F-19 follow-up: refuse before any storage.js call while this share's
		// admin rename is mid-flight (see lib/renames.js's isRenamePending()).
		if (isRenamePending(share.id)) return renamePendingResponse();
		// GAP 2 fix: only a genuinely protected share (password-gated or under a
		// download cap) uses the SQLite-persisted 'dl:' bucket; an ordinary share
		// uses the plain in-memory-only 'dlv:' bucket instead (see
		// isRateLimitProtected() and ratelimit.js's PERSIST_PREFIXES comment).
		const limited = enforce((isRateLimitProtected(share) ? 'dl:' : 'dlv:') + params.id, ip, 600, 60_000);
		if (limited) return limited;
		const { ok, owner } = accessCheck(share, req, url);
		if (!ok) return error(403, 'Password required');
		// The owner (edit token or the API key that created the share) manages and
		// restores their own share, so this gate does not apply to them. Preview
		// never counts as a download, so any share with retrieval control - burn
		// on first access, or a download cap - must refuse to preview entirely for
		// a non-owner; otherwise the full file is retrievable inline with the
		// counter never incremented, silently bypassing the control.
		if (!owner && (share.one_time || share.max_downloads !== null)) return error(403, 'Preview is disabled for this share');
		const file = await resolveFile(share.id, params.fileId);
		if (!file) return error(404, 'File not found');
		if (!file.complete) return error(409, 'File is not ready');

		// Admission control: shares the same per-IP 'dl' semaphore as the download
		// endpoint (both stream response bytes to the client). Acquired after the
		// access/limit checks, before any response is built.
		const release = acquire('dl', ip, 16);
		if (!release) return overloaded(3);

		try {
			// L-05: every preview response is revocable user content - even an
			// "uncontrolled" share (no password/one_time/max_downloads) can still be
			// deleted, expired, or have a password/cap added to it after the fact by
			// its owner or an admin, and its id is not a content digest, so a stale
			// cached copy would keep serving bytes the visitor is no longer meant to
			// have. A share's bytes are never a deliberately public, content-
			// addressed, credential-free object, so no branch here gets long-lived
			// caching - always no-store.
			const cacheControl = 'no-store';
			const offload = offloadHeaders(share, file);
			if (offload) {
				// Offload hands the bytes to the reverse proxy (or serves headers-only
				// for a HEAD probe) - no stream is ever opened by this process.
				release();
				const serving = previewServing(file.mime);
				return new Response(null, {
					headers: {
						...offload,
						'Content-Type': serving.type,
						'Content-Disposition': contentDisposition(file.name.split('/').pop(), serving.inline),
						'Content-Security-Policy': PREVIEW_CSP,
						'Cache-Control': cacheControl,
						ETag: '"' + file.id + '"',
						'Accept-Ranges': 'bytes',
						...FILE_SECURITY_HEADERS,
					},
				});
			}
			if (req.method === 'HEAD') {
				// HEAD never opens a stream (see rangeResponse's head handling).
				release();
				return rangeResponse(share, file, req, {
					inline: previewServing(file.mime).inline,
					contentType: previewServing(file.mime).type,
					head: true,
					extraHeaders: { 'Content-Security-Policy': PREVIEW_CSP, 'Cache-Control': cacheControl, ETag: '"' + file.id + '"' },
				});
			}
			// M-04: byte-rate budget, keyed by IP like the 'dl' admission-control
			// slot just above. Sized from the actual Range (or the whole file when
			// unranged) BEFORE the stream opens; an invalid range is left to
			// rangeResponse's 416 below without spending any budget - it transfers
			// zero bytes either way.
			const size = plainSize(file, share.id);
			const range = parseRange(req.headers.get('range'), size);
			if (config.downloadBytesPerSec > 0 && !range?.invalid) {
				const cost = range ? range.length : size;
				const rateLimited = takeBytes('dl-bytes', ip, cost, config.downloadBytesPerSec * 4, config.downloadBytesPerSec);
				if (rateLimited) { release(); return rateLimited; }
			}
			// M-06: lazy migration trigger - fire-and-forget, after the decision to
			// actually stream this v1 file is made, so it adds no latency here.
			if (fileEnc(file)?.version === 1) scheduleMigration(file.id);
			const serving = previewServing(file.mime);
			return rangeResponse(share, file, req, {
				inline: serving.inline,
				contentType: serving.type,
				size,
				range,
				makeBody: src => trackedStream(src, { onEnd: release }),
				extraHeaders: {
					'Content-Security-Policy': PREVIEW_CSP,
					// no-store (see cacheControl above, L-05) - revocable content is
					// never cached, even across a scrub-back seek in the player.
					'Cache-Control': cacheControl,
					ETag: '"' + file.id + '"',
				},
			});
		} catch (e) {
			release();
			throw e;
		}
	});

	// Attachment download: counts as one download - and, for a one-time share,
	// claims and eventually burns it - only once the delivery is a "full" one
	// (a GET that transfers the entire file: no Range header, or an explicit
	// `bytes=0-<size-1>`) and only after that stream has fully drained. A
	// dropped/paused/partial/tail-probe download never counts or burns, so a
	// multi-GB video survives an interrupted transfer and can be resumed - and
	// a Range request cannot be used to dodge a one-time burn or a download cap.
	declareRoutePolicy('GET', '/api/shares/:id/files/:fileId/download', { auth: 'shareAccess', csrf: false, rateLimit: 'dl:<shareId>|dlv:<shareId>', audit: 'share.burned' });
	router.get('/api/shares/:id/files/:fileId/download', async ({ req, url, params, ip, server }) => {
		// Long video downloads/pauses must not be killed by an idle timeout.
		server?.timeout?.(req, 0);
		// Generous per-IP-per-share cap: stops bandwidth/CPU exhaustion loops
		// without interfering with legitimate range/seek streaming (a video
		// scrubbing through a file makes many small Range requests), and keeps
		// one hot video from exhausting the budget for other shares behind the
		// same IP.
		// Resolve the share BEFORE rate-limiting against its id: otherwise a flood
		// of nonexistent ids would each mint their own bucket in the process-wide
		// rate-limit map at zero cost to the attacker.
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		// F-19 follow-up: refuse before any storage.js call while this share's
		// admin rename is mid-flight (see lib/renames.js's isRenamePending()).
		if (isRenamePending(share.id)) return renamePendingResponse();
		// GAP 2 fix: only a genuinely protected share (password-gated or under a
		// download cap) uses the SQLite-persisted 'dl:' bucket; an ordinary share
		// uses the plain in-memory-only 'dlv:' bucket instead (see
		// isRateLimitProtected() and ratelimit.js's PERSIST_PREFIXES comment).
		const limited = enforce((isRateLimitProtected(share) ? 'dl:' : 'dlv:') + params.id, ip, 600, 60_000);
		if (limited) return limited;
		const { ok, owner } = accessCheck(share, req, url);
		if (!ok) return error(403, 'Password required');
		const file = await resolveFile(share.id, params.fileId);
		if (!file) return error(404, 'File not found');
		if (!file.complete) return error(409, 'File is not ready');
		// The owner's own reads (edit token or owning API key) never hit the cap.
		if (!owner && limitReached(share)) return error(410, 'Download limit reached');

		// Admission control: bound concurrent streaming download/preview responses
		// per client IP (bandwidth/fd exhaustion). Acquired after the access/limit
		// checks and before any response (including HEAD) is built; released
		// exactly once on every path below - either immediately (HEAD, or an
		// early error before a stream exists) or via trackedStream's onEnd once
		// the response body actually finishes draining/cancelling/erroring.
		const release = acquire('dl', ip, 16);
		if (!release) return overloaded(3);

		try {
			const size = plainSize(file, share.id);
			const range = parseRange(req.headers.get('range'), size);
			// A controlled share (one-time, or under a download cap) can only ever
			// be delivered whole to a non-owner: an ordinary pair of non-overlapping
			// Range requests could otherwise reconstruct the entire file across two
			// requests without either one individually looking like a "full"
			// delivery below, defeating the claim/burn/cap machinery entirely. Force
			// such a Range to be ignored (served as a normal full 200) instead of
			// honored as a 206 partial, so "stream drained" and "visitor got the
			// whole file" stay the same event. An exact bytes=0-(size-1) range is
			// left alone since it is already a full delivery per reachesEnd, and a
			// genuinely malformed range still falls through to rangeResponse's 416.
			const effRange =
				!owner &&
				(share.one_time || share.max_downloads !== null) &&
				range && !range.invalid && !(range.start === 0 && range.end === size - 1)
					? null
					: range;
			// HEAD is a pure probe (the E2E view page pre-flights one before
			// committing a navigation download): answer from metadata alone, before
			// the one-time read tracking below. Reaching that machinery with a body
			// Bun never drains would bump activeReads without a matching readEnd,
			// stalling a later burn forever. No stream is ever opened, so the slot
			// is released immediately rather than handed to a trackedStream.
			if (req.method === 'HEAD') {
				release();
				return rangeResponse(share, file, req, { inline: false, size, range: effRange, head: true });
			}
			// M-06: lazy migration trigger - fire-and-forget, GET only (a HEAD
			// probe never opens a stream, so it returns above without this).
			if (fileEnc(file)?.version === 1) scheduleMigration(file.id);
			// A "full" delivery is a non-owner GET whose range (or the absence of
			// one) covers the entire file in one shot - i.e. draining the stream
			// delivers every byte. Anything else (a partial range probe, a tail
			// probe, a HEAD, or the owner's own restore) never counts, claims, or
			// burns.
			const full = req.method === 'GET' && !owner && reachesEnd(effRange, size);
			const ua = req.headers.get('user-agent');

			// M-04: byte-rate budget, keyed by IP like the 'dl' admission-control
			// slot just above. Sized from the actual (possibly range-forced-to-full)
			// delivery BEFORE the stream opens.
			if (config.downloadBytesPerSec > 0) {
				const cost = effRange ? effRange.length : size;
				const rateLimited = takeBytes('dl-bytes', ip, cost, config.downloadBytesPerSec * 4, config.downloadBytesPerSec);
				if (rateLimited) { release(); return rateLimited; }
			}

			// One-time shares carry the full claim/burn machinery: track every read so
			// a burn waits for in-flight reads, claim the share on a full delivery,
			// count and burn only once that delivery drains, and restore it if the
			// delivery is cancelled so the recipient can retry.
			if (share.one_time) {
				if (full) {
					const claimed = claimOneTime.run(now(), share.id).changes > 0;
					if (!claimed) { release(); return error(410, 'This one-time share has already been taken'); }
					audit('share.burned', { ip, target: share.id });
				}
				readStart(share.id);
				let completed = false;
				const makeBody = src =>
					trackedStream(src, {
						onComplete: full
							? () => {
									completed = true;
									recordDownload(share.id, file.id, ip, ua, share.creator_ip);
									burnPending.add(share.id);
								}
							: undefined,
						onEnd: () => {
							if (full && !completed) restoreShare.run(share.id);
							readEnd(share.id);
							release();
						},
					});
				return rangeResponse(share, file, req, { inline: false, makeBody, size, range: effRange });
			}

			// A download-capped share must count only a COMPLETED full delivery, so a
			// cancelled/paused transfer never consumes the cap - wrap just that stream.
			// The slot is claimed atomically up front (not check-then-increment) so N
			// concurrent requests against a maxDownloads=1 share cannot all pass; a lost
			// claim race means the cap was reached by a racing request.
			if (full && share.max_downloads !== null) {
				const claimed = claimDownload.run(share.id).changes > 0;
				if (!claimed) { release(); return error(410, 'Download limit reached'); }
				let completed = false;
				const makeBody = src =>
					trackedStream(src, {
						onComplete: () => {
							completed = true;
							recordDownload(share.id, file.id, ip, ua, share.creator_ip, { countShare: false });
						},
						onEnd: () => { if (!completed) releaseDownload.run(share.id); release(); },
					});
				return rangeResponse(share, file, req, { inline: false, makeBody, size, range: effRange });
			}

			// Uncontrolled share (the common, hot path): tally a full delivery up front
			// and stream with the semaphore slot released once the body ends.
			if (full) recordDownload(share.id, file.id, ip, ua, share.creator_ip);
			const makeBody = src => trackedStream(src, { onEnd: release });
			return rangeResponse(share, file, req, { inline: false, makeBody, size, range: effRange });
		} catch (e) {
			release();
			throw e;
		}
	});

	// Whole-share zip: one chunked archive of every complete file. A zip is
	// always a "full" delivery (there is no partial-range zip), so it gets the
	// same one-time claim/burn-on-completion treatment as a full single-file
	// download: only the request whose stream actually drains to the end gets
	// to count the download and burn the share.
	declareRoutePolicy('GET', '/api/shares/:id/download-all', { auth: 'shareAccess', csrf: false, rateLimit: 'zip', audit: 'share.burned' });
	router.get('/api/shares/:id/download-all', async ({ req, url, params, ip, server }) => {
		// A long archive stream must not be killed by an idle timeout.
		server?.timeout?.(req, 0);
		// A zip build is heavier per-request than a single-file stream, so it gets
		// its own (lower) generous per-IP cap - still well above legitimate use,
		// just enough to stop a bandwidth/CPU exhaustion loop. One unconditional
		// per-IP key for every request (protected or not): a live share lookup
		// before enforce() would spend a SQLite SELECT on every request in the
		// exact flood scenario this limiter exists to reject at zero cost, and
		// splitting the bucket by share protection would hand an attacker a
		// second, independent 30/60s allowance by flooding a share they made
		// password-protected themselves before moving on to an unprotected one.
		const limited = enforce('zip', ip, 30, 60_000);
		if (limited) return limited;
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		// F-19 follow-up: refuse before any storage.js call while this share's
		// admin rename is mid-flight (see lib/renames.js's isRenamePending()).
		if (isRenamePending(share.id)) return renamePendingResponse();
		const { ok, owner } = accessCheck(share, req, url);
		if (!ok) return error(403, 'Password required');
		// Zip is built server-side, which is impossible for E2E shares (the server
		// has neither the key nor the real filenames). The client downloads each
		// encrypted file and decrypts it instead.
		if (share.e2e) return error(409, 'Zip download is not available for end-to-end encrypted shares');
		if (!owner && limitReached(share)) return error(410, 'Download limit reached');

		let files = getCompleteFiles.all(share.id);
		// Nothing to deliver: do not count a download or burn a one-time share on
		// an empty archive.
		if (!files.length) return error(404, 'No files to download');

		// The zip writer emits classic (non-zip64) local/central-directory
		// records, whose 32-bit size fields cannot address a file or archive at
		// or above 4GiB. Refuse up front rather than silently emit a corrupt
		// archive that only fails once the client tries to open it.
		const ZIP_LIMIT = 0xFFFFFFFF;
		const totalSize = files.reduce((sum, f) => sum + f.size, 0);
		if (totalSize >= ZIP_LIMIT || files.some(f => f.size >= ZIP_LIMIT)) {
			return error(413, 'Share is too large for a single zip; download the files individually');
		}

		// Same probe rule as the single-file download: HEAD answers headers-only
		// and never constructs the archive stream - so it stays exempt from the
		// admission-control acquire below entirely.
		if (req.method === 'HEAD') {
			return new Response(null, {
				headers: {
					'Content-Type': 'application/zip',
					'Content-Disposition': contentDisposition((share.title || share.id) + '.zip', false),
					'Cache-Control': 'no-store',
					...FILE_SECURITY_HEADERS,
				},
			});
		}

		// Admission control: a zip build is the heaviest stream type (reads every
		// blob, CRC32s every byte), so it gets its own tighter per-IP and global
		// caps on top of the shared 'dl' semaphore used by single-file
		// download/preview.
		const release = acquireAll([
			['zip', ip, 2],
			['zip-global', null, 6],
		]);
		if (!release) return overloaded(5);

		try {
			// M-06: wait out any in-flight migration swap for each v1 file before
			// opening its blob stream (same reasoning as resolveFile() above). A
			// file that disappears mid-await (same TOCTOU a concurrent delete can
			// cause - see resolveFile()) is dropped from the archive entirely,
			// never left in as the stale pre-migration object, which would have
			// gone on to open a blob that no longer exists and broken the zip
			// stream mid-build. Then fire-and-forget a lazy migration trigger for
			// any that are still v1.
			for (let i = 0; i < files.length; i++) {
				if (fileEnc(files[i])?.version === 1 && (await awaitFileMigration(files[i].id))) {
					files[i] = getFile.get(files[i].id, share.id) || null;
				}
			}
			files = files.filter(Boolean);
			if (!files.length) { release(); return error(404, 'No files to download'); }
			for (const f of files) {
				if (fileEnc(f)?.version === 1) scheduleMigration(f.id);
			}

			// M-5: the batch snapshot above (and the loop's own per-file
			// awaitFileMigration check) only guarantees THAT file's row is fresh at
			// the moment it was checked - it says nothing about a DIFFERENT file's
			// migration completing its swap while this loop was awaiting on some
			// other entry. Trusting `f` here would risk opening a blob that has
			// since been promoted to v2 on disk with the stale v1 iv/version still
			// in hand (silent CTR "decryption" of authenticated GCM ciphertext -
			// garbage, and it would never fail loudly). Re-resolve each file fresh
			// right when the zip writer actually asks for its bytes (createZipStream
			// streams entries strictly one at a time, so this happens immediately
			// before that entry is read) - mirroring resolveFile()'s single-file
			// safety above, but evaluated at the true point of use instead of from
			// this batch snapshot.
			const usedZipNames = new Set();
			const entries = files.map(f => ({
				name: uniqueZipName(f.name, usedZipNames),
				file: {
					stream: () => new ReadableStream({
						async start(controller) {
							const fresh = await resolveFile(share.id, f.id);
							// Deleted concurrently, or this share's admin rename (F-19 follow-up:
							// isRenamePending()) started/is still mid-flight since the batch
							// snapshot above - either way, emit an empty entry rather than
							// stale/wrong/momentarily-missing bytes.
							if (!fresh || isRenamePending(share.id)) { controller.close(); return; }
							const reader = blobRangeStream(share.id, fresh.id, 0, fresh.size - 1, fileEnc(fresh)).getReader();
							while (true) {
								const { done, value } = await reader.read();
								if (done) break;
								controller.enqueue(value);
							}
							controller.close();
						},
					}),
				},
				size: f.size,
			}));

			// HEAD probes (auto-routed to this GET handler) must not count, claim, or
			// burn, and the owner is exempt entirely (their own restore never counts
			// or burns).
			const full = !owner && req.method === 'GET';

			// M-04 GAP 1 fix: byte-rate budget, keyed by IP with the exact same
			// 'dl-bytes' bucket already used by single-file preview/download (see
			// the M-04 comments on those routes) - previously this route had no
			// byte-rate cap at all, letting a client bypass the configured
			// download-bytes-per-sec budget entirely by using the archive endpoint.
			// Sized from the archive's total content bytes (the sum of every
			// entry's plain size) before the stream opens, same as the single-file
			// download's whole-file cost.
			if (config.downloadBytesPerSec > 0) {
				const zipCost = entries.reduce((sum, e) => sum + e.size, 0);
				const rateLimited = takeBytes('dl-bytes', ip, zipCost, config.downloadBytesPerSec * 4, config.downloadBytesPerSec);
				if (rateLimited) { release(); return rateLimited; }
			}

			if (full && share.one_time) {
				const claimed = claimOneTime.run(now(), share.id).changes > 0;
				if (!claimed) { release(); return error(410, 'This one-time share has already been taken'); }
				audit('share.burned', { ip, target: share.id });
			}
			// A download-capped (non-one-time) share must count only a COMPLETED full
			// zip delivery, so a cancelled/failed archive never consumes the cap. The
			// slot is claimed atomically up front here (not via the plain
			// check-then-act limitReached() check above, which only short-circuits the
			// common case) so N concurrent zip requests against a maxDownloads=1 share
			// cannot all pass - the same guarantee the single-file download path
			// already gets from claimDownload/releaseDownload.
			const capped = full && !share.one_time && share.max_downloads !== null;
			if (capped) {
				const claimed = claimDownload.run(share.id).changes > 0;
				if (!claimed) { release(); return error(410, 'Download limit reached'); }
			}

			let body = createZipStream(entries);
			if (full) {
				readStart(share.id);
				let completed = false;
				body = trackedStream(body, {
					onComplete: () => {
						completed = true;
						recordDownload(share.id, null, ip, req.headers.get('user-agent'), share.creator_ip, { countShare: !capped });
						if (share.one_time) burnPending.add(share.id);
					},
					onEnd: () => {
						if (share.one_time && !completed) restoreShare.run(share.id);
						if (capped && !completed) releaseDownload.run(share.id);
						readEnd(share.id);
						release();
					},
				});
			} else {
				// Non-full (the owner's own restore): still wrap so the semaphore
				// slot is released once the archive stream finishes draining/
				// cancelling/erroring, rather than only on the tracked full path.
				body = trackedStream(body, { onEnd: release });
			}

			const zipName = (share.title || share.id) + '.zip';
			return new Response(body, {
				headers: {
					'Content-Type': 'application/zip',
					'Content-Disposition': contentDisposition(zipName, false),
					'Cache-Control': 'no-store',
					...FILE_SECURITY_HEADERS,
				},
			});
		} catch (e) {
			release();
			throw e;
		}
	});
}
