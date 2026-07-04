// Streaming endpoints for share visitors: inline preview, single-file download,
// and a whole-share zip. All three are Range-aware (preview/single download) and
// enforce the same access gate: the share must be live (exists, not soft-deleted,
// not expired) and, when password-protected, the caller must present a valid
// access token or the owner edit token. Only complete files are ever streamed.

import { db, now } from '../db.js';
import { error, parseRange, contentDisposition, SECURITY_HEADERS } from '../lib/http.js';
import { safeEqual } from '../lib/crypto.js';
import { readAccessToken, hasAccessToken } from '../lib/auth.js';
import { verifyApiKey, readApiKey, readApiKeySession } from '../lib/apikeys.js';
import { blobFile, blobRangeStream, deleteShareFiles } from '../lib/storage.js';
import { createZipStream } from '../lib/zip.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';
import { enforce } from '../lib/ratelimit.js';

// Whether a resolved Range (or the absence of one) reaches the last byte of
// the file - i.e. letting the stream drain would deliver the file in full.
// Used to decide whether a request is a "full" delivery worth counting/
// claiming/burning, as opposed to a partial range probe or seek.
function reachesEnd(range, size) {
	return range === null || (!range.invalid && range.end === size - 1);
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
	let owner = !!editToken && safeEqual(editToken, share.edit_token);
	if (!owner && share.api_key_id) {
		const key = verifyApiKey(readApiKey(req)) || readApiKeySession(req);
		if (key && key.id === share.api_key_id) owner = true;
	}
	if (owner || !share.password_hash) return { ok: true, owner };
	const token = readAccessToken(req, url);
	if (token && hasAccessToken(token, share.id)) return { ok: true, owner };
	return { ok: false, owner };
}

function recordDownload(shareId, fileId, ip, ua, creatorIp) {
	const ts = now();
	if (fileId) incFileDownload.run(fileId);
	incShareDownload.run(shareId);
	insertEvent.run(shareId, fileId, ts, ip ?? null, ua ?? null);
	// Lifetime stats, credited to the uploader (persist past deletion).
	bumpMetric('downloads');
	bumpUploader(creatorIp, { downloads: 1 });
}

function limitReached(share) {
	return share.max_downloads !== null && share.download_count >= share.max_downloads;
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

// Build a Range-aware response for a single blob. makeBody optionally wraps the
// chosen stream (used to schedule one-time cleanup).
function rangeResponse(share, file, req, opts = {}) {
	const { inline = false, contentType, makeBody, extraHeaders } = opts;
	const f = blobFile(share.id, file.id);
	const size = f.size;
	const range = parseRange(req.headers.get('range'), size);
	if (range?.invalid) {
		return new Response(null, {
			status: 416,
			headers: { 'Content-Range': `bytes */${size}`, 'Accept-Ranges': 'bytes', ...SECURITY_HEADERS },
		});
	}
	const start = range ? range.start : 0;
	const end = range ? range.end : size - 1;
	const decrypted = blobRangeStream(share.id, file.id, start, end, file.iv);
	const body = makeBody ? makeBody(decrypted) : decrypted;
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
		const limited = enforce('dl:' + params.id, ip, 600, 60_000);
		if (limited) return limited;
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		const { ok, owner } = accessCheck(share, req, url);
		if (!ok) return error(403, 'Password required');
		// The owner (edit token or the API key that created the share) manages and
		// restores their own share, so this gate does not apply to them.
		if (!owner && share.one_time) return error(403, 'Preview is disabled for one-time shares');
		const file = getFile.get(params.fileId, share.id);
		if (!file) return error(404, 'File not found');
		if (!file.complete) return error(409, 'File is not ready');
		const serving = previewServing(file.mime);
		return rangeResponse(share, file, req, {
			inline: serving.inline,
			contentType: serving.type,
			extraHeaders: {
				'Content-Security-Policy': PREVIEW_CSP,
				// Previewed bytes are immutable content addressed by file id, so a
				// scrub-back in the player can be served from the browser cache
				// instead of re-requesting already-fetched ranges.
				'Cache-Control': 'private, max-age=31536000, immutable',
				ETag: '"' + file.id + '"',
			},
		});
	});

	// Attachment download: counts as one download - and, for a one-time share,
	// claims and eventually burns it - only once the delivery is a "full" one
	// (a GET whose range reaches the last byte) and only after that stream has
	// fully drained. A dropped/paused/partial download never counts or burns,
	// so a multi-GB video survives an interrupted transfer and can be resumed.
	router.get('/api/shares/:id/files/:fileId/download', async ({ req, url, params, ip, server }) => {
		// Long video downloads/pauses must not be killed by an idle timeout.
		server?.timeout?.(req, 0);
		// Generous per-IP-per-share cap: stops bandwidth/CPU exhaustion loops
		// without interfering with legitimate range/seek streaming (a video
		// scrubbing through a file makes many small Range requests), and keeps
		// one hot video from exhausting the budget for other shares behind the
		// same IP.
		const limited = enforce('dl:' + params.id, ip, 600, 60_000);
		if (limited) return limited;
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		const { ok, owner } = accessCheck(share, req, url);
		if (!ok) return error(403, 'Password required');
		const file = getFile.get(params.fileId, share.id);
		if (!file) return error(404, 'File not found');
		if (!file.complete) return error(409, 'File is not ready');
		// The owner's own reads (edit token or owning API key) never hit the cap.
		if (!owner && limitReached(share)) return error(410, 'Download limit reached');

		const size = blobFile(share.id, file.id).size;
		const range = parseRange(req.headers.get('range'), size);
		// A "full" delivery is a non-owner GET whose range (or the absence of
		// one) reaches the last byte - i.e. draining the stream delivers the
		// whole file. Anything else (a partial range probe, a HEAD, or the
		// owner's own restore) never counts, claims, or burns.
		const full = req.method === 'GET' && !owner && reachesEnd(range, size);

		if (full && share.one_time) {
			// Atomically claim the share so only the request that will actually
			// deliver the whole file gets to burn it; a losing racer (a second
			// full-range request arriving after the claim) is turned away instead
			// of also streaming and burning.
			const claimed = claimOneTime.run(now(), share.id).changes > 0;
			if (!claimed) return error(410, 'This one-time share has already been taken');
		}

		// Track every read against the share, not just full deliveries, so a
		// one-time burn (triggered by a concurrent full delivery elsewhere)
		// always waits for partial/owner reads that are still in flight.
		readStart(share.id);
		let completed = false;
		const makeBody = src =>
			trackedStream(src, {
				onComplete: full
					? () => {
							completed = true;
							recordDownload(share.id, file.id, ip, req.headers.get('user-agent'), share.creator_ip);
							if (share.one_time) burnPending.add(share.id);
						}
					: undefined,
				onEnd: () => {
					// A cancelled/errored full delivery of a one-time share must not
					// leave it burned/soft-deleted - restore it so the recipient can
					// simply retry the download.
					if (full && share.one_time && !completed) restoreShare.run(share.id);
					readEnd(share.id);
				},
			});
		return rangeResponse(share, file, req, { inline: false, makeBody });
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

		const entries = files.map(f => ({
			name: f.name,
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

		let body = createZipStream(entries);
		if (full) {
			readStart(share.id);
			let completed = false;
			body = trackedStream(body, {
				onComplete: () => {
					completed = true;
					recordDownload(share.id, null, ip, req.headers.get('user-agent'), share.creator_ip);
					if (share.one_time) burnPending.add(share.id);
				},
				onEnd: () => {
					if (share.one_time && !completed) restoreShare.run(share.id);
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
