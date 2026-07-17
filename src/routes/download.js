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
		headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '1', 'Cache-Control': 'no-store', ...SECURITY_HEADERS },
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
	const token = readAccessToken(req, url, share.id);
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

// Security-audit finding (2026-07, "cancelled downloads still burn shares"):
// a reverse proxy/CDN in front of this process (production sits behind
// Cloudflare - see DEPLOY.md) can itself fully absorb a streamed response -
// so trackedStream's onComplete fires exactly as though the delivery fully
// drained - even when the real visitor's connection was dropped after only a
// few bytes: the proxy, not this process, is the party that actually
// observed the failure, and Bun's own socket-close/cancel signal only ever
// fires for ITS immediate peer (the proxy), never the browser two hops away.
// Since burning a one-time share's blobs, or permanently spending a
// maxDownloads slot, is irreversible, a "full" delivery's apparent
// completion is held PENDING for a short grace window (config.downloadGraceMs)
// instead of being finalized the instant onComplete fires. While pending, a
// fresh "full" request against the exact same (already-claimed) share can be
// treated as a retry of that SAME delivery, not a new grant - the only
// authorization boundary a one-time/capped link ever had was "whoever holds
// the link", so redelivering it once more before finalizing hands out
// nothing the holder was not already entitled to.
//
// Follow-up finding (2026-07, "grace window itself defeats maxDownloads"):
// the first cut of this mechanism keyed pending state by shareId alone (a
// single boolean-ish slot per share, set the instant ANY claim completed).
// That let ANY full request landing while ANY grace window was open take the
// redelivery branch - which skips limitReached()/claimDownload() entirely -
// regardless of whether it was really a retry of the claim that just
// completed, or a brand new full request against an already-fully-spent
// link. Since each redelivery also re-armed the SAME window, plain,
// non-malicious-looking sequential GETs could ride it to an effectively
// unbounded number of full 200 deliveries - a complete defeat of
// maxDownloads/one-time. Fixed with two independent bounds, both keyed to
// the COMPLETED CLAIM rather than the share:
//
//   1. pendingDelivery holds an ARRAY of claim entries per share, not a
//      single slot - one entry per real, atomically-successful
//      claimOneTime()/claimDownload() call that has completed but not yet
//      finalized. A maxDownloads=N share can have up to N of these pending
//      at once, each with its own independent grace window, so redelivering
//      one claim's retry can never be confused with, or steal the window
//      from, a different claim.
//   2. Every request against a controlled share tries the REAL atomic claim
//      FIRST, exactly as if no grace mechanism existed. Only when that
//      fails - i.e. only when the request would otherwise be rejected right
//      now by limitReached()/"already taken", meaning the cap is genuinely
//      exhausted - does tryClaimRetry() below look for a pending claim to
//      redeliver against, and even then only if THAT claim has not already
//      used up its own small, fixed retry budget
//      (config.downloadGraceMaxRetries, default 1: one legitimate
//      completion's worth of retries, not an open-ended allowance). So a
//      share can never accumulate more genuinely-claimed slots than
//      maxDownloads allows - claimDownload/claimOneTime's own atomic
//      counters are the single source of truth for that - and each of those
//      slots can only ever be redelivered a small, bounded number of extra
//      times, never indefinitely, no matter how many requests arrive or how
//      long the window stays open.
//
// Each entry's own grace deadline still extends on every retry granted
// against it (bounded overall at config.downloadGraceMaxMs from THAT
// claim's own first completion, same as before), so a claim can never be
// held pending forever - but now "pending" additionally requires spare
// retry budget on some real, already-completed claim, not merely "some
// timer somewhere for this share hasn't fired yet".
//
// Known, accepted trade-off: two genuinely concurrent retries against the
// SAME pending claim, landing in the same JS turn, could both pass the
// retriesUsed check before either one's increment is observed by the other
// (this process is otherwise single-threaded JS, so this requires two
// connections whose synchronous claim-decision code happens to interleave
// around the same microtask boundary). This is a narrow, low-probability
// race whose worst case is one extra duplicate delivery, not an unbounded
// one - far lower severity than the bug being fixed, and consistent with
// the existing trust model (the link itself, not a per-recipient identity,
// is the only credential a one-time/capped share ever had).
const pendingDelivery = new Map(); // shareId -> Array<{ firstAt, retriesUsed, timer, finalize }>

// shareIds whose one-time blobs have already been (or are being) burned -
// guards finalizeOneTimeShare() against ever running twice for the same
// share (quota.releaseShare()'s documented contract requires exactly ONE
// call per share - see lib/quota.js's IDEMPOTENCY RULE comment). Self-
// cleaning: an entry is only ever needed to guard against a LATE retry
// racing the original grace expiry, a window already bounded by
// config.downloadGraceMaxMs, so it is dropped after the same interval
// rather than retained forever.
const finalizedOneTime = new Set();

function finalizeOneTimeShare(shareId) {
	if (finalizedOneTime.has(shareId)) return;
	finalizedOneTime.add(shareId);
	const t = setTimeout(() => finalizedOneTime.delete(shareId), config.downloadGraceMaxMs);
	t.unref?.();
	// Reuses the existing in-flight-read-safe burn path: if some OTHER read (a
	// fresh retry that started just as this timer fired) is still active for
	// this share, defer the actual burn to readEnd() above instead of racing
	// rm -rf against it.
	burnPending.add(shareId);
	if ((activeReads.get(shareId) || 0) === 0) { burnPending.delete(shareId); burnBlobs(shareId); }
}

function pendingEntries(shareId) {
	return pendingDelivery.get(shareId) || [];
}

// Whether this share has ANY claim still inside its post-completion grace
// window - regardless of whether that claim has spare retry budget left.
// Used to decide whether a share is still resolvable at all (liveOrPendingShare
// below) and whether the top-level limitReached() gate should let a request
// through to the real per-claim retry check instead of refusing it outright.
function hasPendingDelivery(shareId) {
	return pendingDelivery.has(shareId);
}

function removePendingEntry(shareId, entry) {
	const list = pendingDelivery.get(shareId);
	if (!list) return;
	const i = list.indexOf(entry);
	if (i !== -1) list.splice(i, 1);
	if (list.length === 0) pendingDelivery.delete(shareId);
}

// (Re)schedules `entry`'s own finalize timer, extending its deadline without
// ever pushing it past config.downloadGraceMaxMs from ITS OWN firstAt.
function scheduleFinalize(shareId, entry) {
	if (entry.timer) clearTimeout(entry.timer);
	const delay = Math.max(0, Math.min(config.downloadGraceMs, config.downloadGraceMaxMs - (Date.now() - entry.firstAt)));
	const timer = setTimeout(() => { removePendingEntry(shareId, entry); entry.finalize(); }, delay);
	timer.unref?.();
	entry.timer = timer;
}

// Opens a FRESH, independently-tracked grace window for a genuinely NEW
// claim (a real claimOneTime()/claimDownload() success) whose delivery has
// just finished draining. `finalize` runs once THIS claim's own window
// elapses with no further redelivery of it.
function armDeliveryGrace(shareId, finalize) {
	const entry = { firstAt: Date.now(), retriesUsed: 0, timer: null, finalize };
	const list = pendingDelivery.get(shareId);
	if (list) list.push(entry);
	else pendingDelivery.set(shareId, [entry]);
	scheduleFinalize(shareId, entry);
	return entry;
}

// Extends the grace deadline of an EXISTING pending claim (one that
// tryClaimRetry() below already granted a redelivery against) once that
// retry's own stream finishes draining. Does NOT touch retriesUsed again -
// that budget was already spent synchronously at grant time, in
// tryClaimRetry, so a retry that itself stalls or gets cancelled cannot be
// used to accumulate extra budget by never completing.
function extendDeliveryGrace(shareId, entry) {
	if (pendingDelivery.get(shareId)?.includes(entry)) scheduleFinalize(shareId, entry);
}

// Grants a redelivery retry against whichever still-pending claim for this
// share has spare retry budget, consuming one unit of THAT claim's budget
// (synchronously, before any await - see the header comment's race
// trade-off) and returning the entry so the caller can extend precisely
// that claim's own window once the retry completes - or null if every
// pending claim for this share has already used its full budget, meaning
// the request must be refused exactly as if no grace mechanism existed.
function tryClaimRetry(shareId) {
	for (const entry of pendingEntries(shareId)) {
		if (entry.retriesUsed < config.downloadGraceMaxRetries) {
			entry.retriesUsed++;
			return entry;
		}
	}
	return null;
}

// A share that is either genuinely live, or a one-time share that is
// soft-deleted but still has at least one claim within its post-completion
// grace window above - i.e. still eligible for a same-link redelivery retry.
// Only this file's single-file and zip GET handlers use this (the ones with
// claim/burn machinery); every other read path (preview, shares.js's
// metadata endpoint) intentionally keeps using the plain liveShare() and
// sees a pending one-time share as gone, exactly like before this fix.
function liveOrPendingShare(id) {
	const live = liveShare(id);
	if (live) return live;
	if (!hasPendingDelivery(id)) return null;
	const raw = getShare.get(id);
	if (!raw || !raw.one_time || raw.deleted_at === null) return null;
	return raw;
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
			headers: { 'Content-Range': `bytes */${size}`, 'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store', ...FILE_SECURITY_HEADERS },
		});
	}
	const start = range ? range.start : 0;
	const end = range ? range.end : size - 1;
	// HEAD gets the exact status/headers a GET would, but must never open the
	// blob stream: Bun drops an unread body without cancelling it, so the
	// createReadStream fd would leak on every probe.
	let body = null;
	if (!head) {
		if (opts.body !== undefined) {
			// Pre-buffered body (see servePreview's PREVIEW_BUFFER_CAP branch below):
			// the caller already read the decrypted stream into a Uint8Array itself,
			// so no stream is opened here at all.
			body = opts.body;
		} else {
			const decrypted = blobRangeStream(share.id, file.id, start, end, fileEnc(file));
			body = makeBody ? makeBody(decrypted) : decrypted;
		}
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

// Bun (1.3.14, this repo's pinned Dockerfile version) silently drops an
// explicitly-set Content-Length and forces chunked framing for any streamed
// Response body over ~255 bytes - but keeps the header for a Blob/TypedArray
// body. A chat-app crawler (Discord's media pipeline in particular) needs a
// correct Content-Length/Range contract to render an inline player, so
// servePreview's GET branch below fully buffers any response bounded by this
// cap instead of streaming it. Every embeddable image/gif and most mp4s fall
// under it; anything larger keeps streaming unbuffered, as before, to avoid
// holding a large file fully in memory.
const PREVIEW_BUFFER_CAP = 32 * 1024 * 1024; // 32MiB

// Inline preview handler - exported so the embed path (routes/pages.js) can
// call it directly for a bot-UA fetch of a share URL, reusing this exact gate
// chain (liveShare -> rename-pending -> rate limit -> accessCheck -> the F-01
// one-time/capped 403) instead of re-implementing any of it against storage.js
// directly. Registered on the router below like any other handler.
export async function servePreview({ req, url, params, ip, server }) {
	// The unbounded per-request timeout below is only granted to the actual
	// streaming branch further down (a file above PREVIEW_BUFFER_CAP). The
	// buffered branch fully materializes the response body up front and
	// releases its 'dl' admission-control slot before the bytes are flushed to
	// the client, so a client that stalls or never reads must still be bounded
	// by Bun's default idleTimeout (255s, server.js) - otherwise a stalled
	// direct-to-origin client could hold an unbounded number of up-to-32MiB
	// buffers in memory indefinitely.
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
		const extraHeaders = {
			'Content-Security-Policy': PREVIEW_CSP,
			// no-store (see cacheControl above, L-05) - revocable content is
			// never cached, even across a scrub-back seek in the player.
			'Cache-Control': cacheControl,
			ETag: '"' + file.id + '"',
		};
		// See PREVIEW_BUFFER_CAP above: read the decrypted range fully into memory
		// and release the semaphore slot immediately, rather than handing off a
		// stream whose Content-Length Bun would otherwise drop.
		const bytesToSend = range ? range.length : size;
		if (bytesToSend <= PREVIEW_BUFFER_CAP) {
			const start = range ? range.start : 0;
			const end = range ? range.end : size - 1;
			const decrypted = blobRangeStream(share.id, file.id, start, end, fileEnc(file));
			const body = new Uint8Array(await new Response(decrypted).arrayBuffer());
			release();
			return rangeResponse(share, file, req, { inline: serving.inline, contentType: serving.type, size, range, body, extraHeaders });
		}
		// Only the true streaming branch (file above PREVIEW_BUFFER_CAP) gets the
		// unbounded per-request timeout - see the comment at the top of this
		// function. This path holds no materialized buffer; its memory footprint
		// is bounded by stream backpressure, same as the /download handlers below.
		server?.timeout?.(req, 0);
		return rangeResponse(share, file, req, {
			inline: serving.inline,
			contentType: serving.type,
			size,
			range,
			makeBody: src => trackedStream(src, { onEnd: release }),
			extraHeaders,
		});
	} catch (e) {
		release();
		throw e;
	}
}

export default function download(router) {
	// Inline preview: never counts as a download, so it cannot be metered against
	// a one-time burn. maxDownloads caps the Download action (a saved copy), not
	// inline viewing, so a download-limited share still previews fine; one-time
	// stays blocked because inline streaming would defeat burn-on-first-access.
	declareRoutePolicy('GET', '/api/shares/:id/files/:fileId/preview', { auth: 'shareAccess', csrf: false, rateLimit: 'dl:<shareId>|dlv:<shareId>', audit: null });
	router.get('/api/shares/:id/files/:fileId/preview', servePreview);

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
		// rate-limit map at zero cost to the attacker. liveOrPendingShare (not
		// plain liveShare) also accepts a one-time share that is soft-deleted but
		// still inside its post-completion grace window - see the PENDING
		// comment above pendingDelivery.
		const share = liveOrPendingShare(params.id);
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
		// A share with an outstanding pending-grace redelivery (see above) is
		// exempted here too - its slot was already claimed by the original
		// request; the retry paths below decide whether to actually redeliver.
		if (!owner && limitReached(share) && !hasPendingDelivery(share.id)) return error(410, 'Download limit reached');

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
			// count and hold (not burn - see the PENDING comment above
			// pendingDelivery) only once that delivery drains, and restore it if the
			// delivery is cancelled so the recipient can retry.
			if (share.one_time) {
				// Always try the REAL atomic claim first, exactly as if no grace
				// mechanism existed. Only when that fails - the share is already
				// taken - do we look for a pending claim with spare retry budget to
				// redeliver against, instead of an outright refusal. See the
				// FOLLOW-UP FINDING comment above pendingDelivery for why this
				// ordering (and the per-claim retry budget) both matter.
				let isRetry = false;
				let retryClaim = null;
				if (full) {
					const claimed = claimOneTime.run(now(), share.id).changes > 0;
					if (claimed) {
						audit('share.burned', { ip, target: share.id });
					} else {
						retryClaim = tryClaimRetry(share.id);
						if (!retryClaim) { release(); return error(410, 'This one-time share has already been taken'); }
						isRetry = true;
					}
				}
				readStart(share.id);
				let completed = false;
				const makeBody = src =>
					trackedStream(src, {
						onComplete: full
							? () => {
									completed = true;
									// Only tally the public counters once per share - a
									// grace-window retry redelivers the SAME entitlement,
									// not a second one.
									if (!isRetry) {
										recordDownload(share.id, file.id, ip, ua, share.creator_ip);
										armDeliveryGrace(share.id, () => finalizeOneTimeShare(share.id));
									} else {
										extendDeliveryGrace(share.id, retryClaim);
									}
								}
							: undefined,
						onEnd: () => {
							// A retry's own failure to complete does nothing extra here -
							// the underlying claim stays exactly as claimed as it was; only
							// the ORIGINAL (non-retry) claim's own cancel restores it.
							if (full && !completed && !isRetry) restoreShare.run(share.id);
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
			// claim race means the cap was reached by a racing request. As with the
			// one-time branch above, a request landing while an earlier delivery is
			// still pending-grace redelivers against that SAME claim instead of
			// re-claiming or 410ing.
			if (full && share.max_downloads !== null) {
				// Always try the REAL atomic claim first (see the one-time branch
				// above and the FOLLOW-UP FINDING comment for why) - only a request
				// that would otherwise be rejected right now falls back to a
				// bounded grace retry against an already-pending claim.
				let isRetry = false;
				let retryClaim = null;
				const claimed = claimDownload.run(share.id).changes > 0;
				if (!claimed) {
					retryClaim = tryClaimRetry(share.id);
					if (!retryClaim) { release(); return error(410, 'Download limit reached'); }
					isRetry = true;
				}
				let completed = false;
				const makeBody = src =>
					trackedStream(src, {
						onComplete: () => {
							completed = true;
							if (!isRetry) {
								recordDownload(share.id, file.id, ip, ua, share.creator_ip, { countShare: false });
								armDeliveryGrace(share.id, () => {});
							} else {
								extendDeliveryGrace(share.id, retryClaim);
							}
						},
						onEnd: () => { if (!completed && !isRetry) releaseDownload.run(share.id); release(); },
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
		// liveOrPendingShare (not plain liveShare) also accepts a one-time share
		// that is soft-deleted but still inside its post-completion grace window
		// - see the PENDING comment above pendingDelivery.
		const share = liveOrPendingShare(params.id);
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
		// A share with an outstanding pending-grace redelivery (see above) is
		// exempted here too - its slot was already claimed by the original
		// request; the claim blocks below decide whether to actually redeliver.
		if (!owner && limitReached(share) && !hasPendingDelivery(share.id)) return error(410, 'Download limit reached');

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
			// Always try the REAL atomic claim first for a controlled share (see the
			// single-file download handler's FOLLOW-UP FINDING comment for why) -
			// only a request that would otherwise be rejected right now falls back
			// to a bounded grace retry against an already-pending claim.
			let isRetry = false;
			let retryClaim = null;

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
				if (claimed) {
					audit('share.burned', { ip, target: share.id });
				} else {
					retryClaim = tryClaimRetry(share.id);
					if (!retryClaim) { release(); return error(410, 'This one-time share has already been taken'); }
					isRetry = true;
				}
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
				if (!claimed) {
					retryClaim = tryClaimRetry(share.id);
					if (!retryClaim) { release(); return error(410, 'Download limit reached'); }
					isRetry = true;
				}
			}

			let body = createZipStream(entries);
			if (full) {
				readStart(share.id);
				let completed = false;
				body = trackedStream(body, {
					onComplete: () => {
						completed = true;
						// Only tally the public counters once per share - a
						// grace-window retry redelivers the SAME entitlement, not a
						// second one.
						if (!isRetry) {
							recordDownload(share.id, null, ip, req.headers.get('user-agent'), share.creator_ip, { countShare: !capped });
							if (share.one_time) armDeliveryGrace(share.id, () => finalizeOneTimeShare(share.id));
							else if (capped) armDeliveryGrace(share.id, () => {});
						} else {
							extendDeliveryGrace(share.id, retryClaim);
						}
					},
					onEnd: () => {
						// A retry's own failure to complete does nothing extra here -
						// the underlying claim stays exactly as claimed as it was; only
						// the ORIGINAL (non-retry) claim's own cancel restores it.
						if (!completed && !isRetry) {
							if (share.one_time) restoreShare.run(share.id);
							if (capped) releaseDownload.run(share.id);
						}
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
