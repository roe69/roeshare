// Streaming endpoints for share visitors: inline preview, single-file download,
// and a whole-share zip. All three are Range-aware (preview/single download) and
// enforce the same access gate: the share must be live (exists, not soft-deleted,
// not expired) and, when password-protected, the caller must present a valid
// access token or the owner edit token. Only complete files are ever streamed.

import { db, now } from '../db.js';
import { error, parseRange, contentDisposition, SECURITY_HEADERS } from '../lib/http.js';
import { safeEqual } from '../lib/crypto.js';
import { readAccessToken, hasAccessToken } from '../lib/auth.js';
import { verifyApiKey, readApiKey } from '../lib/apikeys.js';
import { blobFile, blobRangeStream, deleteShareFiles } from '../lib/storage.js';
import { createZipStream } from '../lib/zip.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';

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
const softDeleteShare = db.query('UPDATE shares SET deleted_at = ? WHERE id = ?');

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
		const key = verifyApiKey(readApiKey(req));
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

// Wrap a ReadableStream so onDone fires exactly once when it ends, errors, or is
// cancelled. Used to defer one-time blob deletion until the body is fully sent.
function cleanupStream(source, onDone) {
	let finished = false;
	const finish = () => {
		if (finished) return;
		finished = true;
		onDone();
	};
	const reader = source.getReader();
	return new ReadableStream({
		async pull(controller) {
			try {
				const { value, done } = await reader.read();
				if (done) {
					controller.close();
					finish();
					return;
				}
				controller.enqueue(value);
			} catch (e) {
				controller.error(e);
				finish();
			}
		},
		cancel(reason) {
			reader.cancel(reason);
			finish();
		},
	});
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
	// Inline preview: never counts as a download, but must respect the same
	// limit/one-time gates as /download so it cannot be used to exfiltrate the
	// full bytes after the cap is reached, or to read a one-time share without
	// ever burning it.
	router.get('/api/shares/:id/files/:fileId/preview', async ({ req, url, params }) => {
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		if (!accessCheck(share, req, url).ok) return error(403, 'Password required');
		// A one-time share is "burn after first retrieval"; serving its full bytes
		// inline (repeatedly, without counting) would defeat that, so preview is
		// disabled for one-time shares - the recipient downloads to retrieve.
		if (share.one_time) return error(403, 'Preview is disabled for one-time shares');
		if (limitReached(share)) return error(410, 'Download limit reached');
		const file = getFile.get(params.fileId, share.id);
		if (!file) return error(404, 'File not found');
		if (!file.complete) return error(409, 'File is not ready');
		const serving = previewServing(file.mime);
		return rangeResponse(share, file, req, { inline: serving.inline, contentType: serving.type, extraHeaders: { 'Content-Security-Policy': PREVIEW_CSP } });
	});

	// Attachment download: counts as one download when serving without a Range
	// header (a full delivery), so seeks/resumes do not double-count.
	router.get('/api/shares/:id/files/:fileId/download', async ({ req, url, params, ip }) => {
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		if (!accessCheck(share, req, url).ok) return error(403, 'Password required');
		const file = getFile.get(params.fileId, share.id);
		if (!file) return error(404, 'File not found');
		if (!file.complete) return error(409, 'File is not ready');
		if (limitReached(share)) return error(410, 'Download limit reached');

		// Count exactly one download per delivery. For an uncontrolled share we
		// only count deliveries that include the start of the file (no Range, or a
		// Range beginning at byte 0) so mid-stream seeks/resumes do not
		// double-count. For a controlled share (one-time or a download cap) we
		// count EVERY GET delivery, including partial ranges, because otherwise a
		// "Range: bytes=1-" request would fetch (almost) the whole file without
		// counting or burning - bypassing the cap / one-time guarantee.
		// HEAD probes (auto-routed to this GET handler) never count or burn.
		const range = parseRange(req.headers.get('range'), blobFile(share.id, file.id).size);
		const controlled = share.one_time || share.max_downloads !== null;
		const counted =
			req.method === 'GET' &&
			(controlled ? !(range && range.invalid) : range === null || (!range.invalid && range.start === 0));
		let makeBody;
		if (counted) {
			recordDownload(share.id, file.id, ip, req.headers.get('user-agent'), share.creator_ip);
			if (share.one_time) {
				softDeleteShare.run(now(), share.id);
				makeBody = src => cleanupStream(src, () => burnBlobs(share.id));
			}
		}
		return rangeResponse(share, file, req, { inline: false, makeBody });
	});

	// Whole-share zip: one chunked archive of every complete file. Counts as one
	// download; honors the same limit and one-time burn rules.
	router.get('/api/shares/:id/download-all', async ({ req, url, params, ip }) => {
		const share = liveShare(params.id);
		if (!share) return error(404, 'Share not found');
		if (!accessCheck(share, req, url).ok) return error(403, 'Password required');
		// Zip is built server-side, which is impossible for E2E shares (the server
		// has neither the key nor the real filenames). The client downloads each
		// encrypted file and decrypts it instead.
		if (share.e2e) return error(409, 'Zip download is not available for end-to-end encrypted shares');
		if (limitReached(share)) return error(410, 'Download limit reached');

		const files = getCompleteFiles.all(share.id);
		// Nothing to deliver: do not count a download or burn a one-time share on
		// an empty archive.
		if (!files.length) return error(404, 'No files to download');
		const entries = files.map(f => ({
			name: f.name,
			file: { stream: () => blobRangeStream(share.id, f.id, 0, f.size - 1, f.iv) },
			size: f.size,
		}));

		// HEAD probes (auto-routed to this GET handler) must not count or burn.
		const counted = req.method === 'GET';
		if (counted) recordDownload(share.id, null, ip, req.headers.get('user-agent'), share.creator_ip);

		let body = createZipStream(entries);
		if (counted && share.one_time) {
			softDeleteShare.run(now(), share.id);
			body = cleanupStream(body, () => burnBlobs(share.id));
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
