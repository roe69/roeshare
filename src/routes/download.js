// Streaming endpoints for share visitors: inline preview, single-file download,
// and a whole-share zip. All three are Range-aware (preview/single download) and
// enforce the same access gate: the share must be live (exists, not soft-deleted,
// not expired) and, when password-protected, the caller must present a valid
// access token or the owner edit token. Only complete files are ever streamed.

import { db, now } from '../db.js';
import { config } from '../config.js';
import { error, parseRange, contentDisposition, SECURITY_HEADERS } from '../lib/http.js';
import { verifySecretToken } from '../lib/crypto.js';
import { readAccessToken, hasAccessToken } from '../lib/auth.js';
import { verifyApiKey, readApiKey, readApiKeySession, keyValidForShare } from '../lib/apikeys.js';
import { blobFile, blobPath, blobRangeStream, deleteShareFiles } from '../lib/storage.js';
import { createZipStream } from '../lib/zip.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';
import { enforce } from '../lib/ratelimit.js';

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
	if (!owner && share.api_key_id) {
		const key = verifyApiKey(readApiKey(req)) || readApiKeySession(req);
		if (key && key.id === share.api_key_id) owner = true;
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
// share row is soft-deleted up front so it disappears immediately; the bytes are
// only dropped after the stream drains (or is cancelled) so we never yank the
// file out from under a download that is still being read.
function burnBlobs(shareId) {
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
	const size = opts.size !== undefined ? opts.size : blobFile(share.id, file.id).size;
	const range = opts.range !== undefined ? opts.range : parseRange(req.headers.get('range'), size);
	if (range?.invalid) {
		return new Response(null, {
			status: 416,
			headers: { 'Content-Range': `bytes */${size}`, 'Accept-Ranges': 'bytes', ...SECURITY_HEADERS },
		});
	}
	const start = range ? range.start : 0;
	const end = range ? range.end : size - 1;
	// HEAD gets the exact status/headers a GET would, but must never open the
	// blob stream: Bun drops an unread body without cancelling it, so the
	// createReadStream fd would leak on every probe.
	let body = null;
	if (!head) {
		const decrypted = blobRangeStream(share.id, file.id, start, end, file.iv);
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
			...SECURITY_HEADERS,
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
	router.get('/api/shares/:id/files/:fileId/preview', async ({ req, url, params, ip, server }) => {
		server?.timeout?.(req, 0);
		// Resolve the share BEFORE rate-limiting against its id: otherwise a flood
		// of nonexistent ids would each mint their own bucket in the process-wide
		// rate-limit map at zero cost to the attacker.
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		const limited = enforce('dl:' + params.id, ip, 600, 60_000);
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
		const file = getFile.get(params.fileId, share.id);
		if (!file) return error(404, 'File not found');
		if (!file.complete) return error(409, 'File is not ready');
		// A password-protected share's bytes must never linger in a shared/browser
		// cache keyed only by URL - a subsequent visitor (or the same browser after
		// the password changes) could read cached content past the point where they
		// should still be authorized. one_time/max_downloads-capped shares are
		// already blocked above for non-owners, but the owner's own preview of such
		// a share should not be cached long-term either. Only a fully public,
		// uncontrolled share gets the long immutable cache.
		const cacheControl = share.password_hash || share.one_time || share.max_downloads !== null
			? 'no-store'
			: 'private, max-age=31536000, immutable';
		const offload = offloadHeaders(share, file);
		if (offload) {
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
					...SECURITY_HEADERS,
				},
			});
		}
		const serving = previewServing(file.mime);
		return rangeResponse(share, file, req, {
			inline: serving.inline,
			contentType: serving.type,
			head: req.method === 'HEAD',
			extraHeaders: {
				'Content-Security-Policy': PREVIEW_CSP,
				// Previewed bytes are immutable content addressed by file id, so a
				// scrub-back in the player can be served from the browser cache
				// instead of re-requesting already-fetched ranges - but only for a
				// fully public, uncontrolled share (see cacheControl above).
				'Cache-Control': cacheControl,
				ETag: '"' + file.id + '"',
			},
		});
	});

	// Attachment download: counts as one download - and, for a one-time share,
	// claims and eventually burns it - only once the delivery is a "full" one
	// (a GET that transfers the entire file: no Range header, or an explicit
	// `bytes=0-<size-1>`) and only after that stream has fully drained. A
	// dropped/paused/partial/tail-probe download never counts or burns, so a
	// multi-GB video survives an interrupted transfer and can be resumed - and
	// a Range request cannot be used to dodge a one-time burn or a download cap.
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
		const limited = enforce('dl:' + params.id, ip, 600, 60_000);
		if (limited) return limited;
		const { ok, owner } = accessCheck(share, req, url);
		if (!ok) return error(403, 'Password required');
		const file = getFile.get(params.fileId, share.id);
		if (!file) return error(404, 'File not found');
		if (!file.complete) return error(409, 'File is not ready');
		// The owner's own reads (edit token or owning API key) never hit the cap.
		if (!owner && limitReached(share)) return error(410, 'Download limit reached');

		const size = blobFile(share.id, file.id).size;
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
		// stalling a later burn forever.
		if (req.method === 'HEAD') {
			return rangeResponse(share, file, req, { inline: false, size, range: effRange, head: true });
		}
		// A "full" delivery is a non-owner GET whose range (or the absence of
		// one) covers the entire file in one shot - i.e. draining the stream
		// delivers every byte. Anything else (a partial range probe, a tail
		// probe, a HEAD, or the owner's own restore) never counts, claims, or
		// burns.
		const full = req.method === 'GET' && !owner && reachesEnd(effRange, size);
		const ua = req.headers.get('user-agent');

		// One-time shares carry the full claim/burn machinery: track every read so
		// a burn waits for in-flight reads, claim the share on a full delivery,
		// count and burn only once that delivery drains, and restore it if the
		// delivery is cancelled so the recipient can retry.
		if (share.one_time) {
			if (full) {
				const claimed = claimOneTime.run(now(), share.id).changes > 0;
				if (!claimed) return error(410, 'This one-time share has already been taken');
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
			if (!claimed) return error(410, 'Download limit reached');
			let completed = false;
			const makeBody = src =>
				trackedStream(src, {
					onComplete: () => {
						completed = true;
						recordDownload(share.id, file.id, ip, ua, share.creator_ip, { countShare: false });
					},
					onEnd: () => { if (!completed) releaseDownload.run(share.id); },
				});
			return rangeResponse(share, file, req, { inline: false, makeBody, size, range: effRange });
		}

		// Uncontrolled share (the common, hot path): tally a full delivery up front
		// and stream with no wrapper and no per-share read tracking.
		if (full) recordDownload(share.id, file.id, ip, ua, share.creator_ip);
		return rangeResponse(share, file, req, { inline: false, size, range: effRange });
	});

	// Whole-share zip: one chunked archive of every complete file. A zip is
	// always a "full" delivery (there is no partial-range zip), so it gets the
	// same one-time claim/burn-on-completion treatment as a full single-file
	// download: only the request whose stream actually drains to the end gets
	// to count the download and burn the share.
	router.get('/api/shares/:id/download-all', async ({ req, url, params, ip, server }) => {
		// A long archive stream must not be killed by an idle timeout.
		server?.timeout?.(req, 0);
		// A zip build is heavier per-request than a single-file stream, so it gets
		// its own (lower) generous per-IP cap - still well above legitimate use,
		// just enough to stop a bandwidth/CPU exhaustion loop.
		const limited = enforce('zip', ip, 30, 60_000);
		if (limited) return limited;
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		const { ok, owner } = accessCheck(share, req, url);
		if (!ok) return error(403, 'Password required');
		// Zip is built server-side, which is impossible for E2E shares (the server
		// has neither the key nor the real filenames). The client downloads each
		// encrypted file and decrypts it instead.
		if (share.e2e) return error(409, 'Zip download is not available for end-to-end encrypted shares');
		if (!owner && limitReached(share)) return error(410, 'Download limit reached');

		const files = getCompleteFiles.all(share.id);
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
		// and never constructs the archive stream.
		if (req.method === 'HEAD') {
			return new Response(null, {
				headers: {
					'Content-Type': 'application/zip',
					'Content-Disposition': contentDisposition((share.title || share.id) + '.zip', false),
					'Cache-Control': 'no-store',
					...SECURITY_HEADERS,
				},
			});
		}

		const usedZipNames = new Set();
		const entries = files.map(f => ({
			name: uniqueZipName(f.name, usedZipNames),
			file: { stream: () => blobRangeStream(share.id, f.id, 0, f.size - 1, f.iv) },
			size: f.size,
		}));

		// HEAD probes (auto-routed to this GET handler) must not count, claim, or
		// burn, and the owner is exempt entirely (their own restore never counts
		// or burns).
		const full = !owner && req.method === 'GET';
		if (full && share.one_time) {
			const claimed = claimOneTime.run(now(), share.id).changes > 0;
			if (!claimed) return error(410, 'This one-time share has already been taken');
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
			if (!claimed) return error(410, 'Download limit reached');
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
				},
			});
		}

		const zipName = (share.title || share.id) + '.zip';
		return new Response(body, {
			headers: {
				'Content-Type': 'application/zip',
				'Content-Disposition': contentDisposition(zipName, false),
				'Cache-Control': 'no-store',
				...SECURITY_HEADERS,
			},
		});
	});
}
