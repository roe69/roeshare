// Programmatic API (v1). Other servers and scripts authenticate with an API key
// (a bearer token, see lib/apikeys.js) instead of the browser upload-password
// cookie, and create/upload shares without a session. Two flows are offered:
//
//   - One-shot:  POST /api/v1/upload  - send a file body in a single request and
//                get back a finished share URL. Simplest; bounded by the server's
//                max request body size, so it suits files up to ~tens of MiB.
//   - Resumable: POST /api/v1/shares  - create a share and receive an editToken,
//                then drive the standard resumable endpoints
//                (POST /api/shares/:id/files, PATCH chunks, POST .../finalize)
//                with `X-Edit-Token`. Use this for large files.
//
// Everything is validated server-side and the same per-file/per-share/total
// storage caps apply as the web portal.

import { config } from '../config.js';
import { db, now } from '../db.js';
import { json, error, requestOrigin, cookie, clearCookie, requestScheme } from '../lib/http.js';
import { hashPassword } from '../lib/crypto.js';
import { newShareId, newFileId, newToken } from '../lib/ids.js';
import { writeChunk, totalUsage, deleteShareFiles } from '../lib/storage.js';
import { newIv } from '../lib/filecrypt.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';
import { enforce } from '../lib/ratelimit.js';
import { slugError } from '../lib/slug.js';
import { authenticate, verifyApiKey, recordKeyUsage, effectiveCaps, clampExpiry, issueApiKeySession, readApiKeySession, APIKEY_COOKIE } from '../lib/apikeys.js';

const getShareById = db.query('SELECT id FROM shares WHERE id = ?');
const insertShare = db.query(
	`INSERT INTO shares (id, title, created_at, expires_at, password_hash, max_downloads, one_time, edit_token, creator_ip, creator_ua, e2e, api_key_id)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
);
const insertFile = db.query(
	'INSERT INTO files (id, share_id, name, size, received, mime, complete, download_count, created_at, stored_name, iv) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)',
);
const setFinalized = db.query('UPDATE shares SET finalized = 1 WHERE id = ?');
const softDeleteShare = db.query('UPDATE shares SET deleted_at = ? WHERE id = ?');

// A live share owned by `keyId` (created with that key, not soft-deleted). The
// expiry is NOT applied here so a key can still inspect/delete an expired-but-not-
// yet-swept share it created.
const getOwnedShare = db.query('SELECT * FROM shares WHERE id = ? AND api_key_id = ? AND deleted_at IS NULL');
const getShareFiles = db.query('SELECT id, name, size, received, mime, complete, download_count, created_at FROM files WHERE share_id = ? ORDER BY created_at ASC, id ASC');

// Map a share row to the API shape, with a built download/share URL.
function shareView(s, origin, files) {
	const totalSize = files ? files.reduce((n, f) => n + f.size, 0) : undefined;
	return {
		id: s.id,
		title: s.title,
		url: `${origin}/${s.id}`,
		createdAt: s.created_at,
		expiresAt: s.expires_at,
		oneTime: !!s.one_time,
		e2e: !!s.e2e,
		password: !!s.password_hash,
		maxDownloads: s.max_downloads,
		downloadCount: s.download_count,
		viewCount: s.view_count || 0,
		finalized: !!s.finalized,
		...(totalSize !== undefined ? { totalSize } : {}),
		...(files
			? {
					files: files.map(f => ({
						id: f.id,
						name: f.name,
						size: f.size,
						received: f.received,
						mime: f.mime,
						complete: !!f.complete,
						downloadCount: f.download_count,
						// Ready-to-use retrieval URL (authorize with this same API key).
						download: `${origin}/api/shares/${s.id}/files/${f.id}/download`,
					})),
			  }
			: {}),
	};
}

// Keep a SAFE relative path (mirrors uploads.js): drop "."/".."/empty/drive
// segments and control chars. Never used as an on-disk path (blobs use the file
// id), only as the display name and zip entry path.
function sanitizeName(name) {
	const parts = String(name ?? '')
		.split(/[/\\]+/)
		.map(s => s.replace(/[\x00-\x1f\x7f]/g, '').replace(/^[A-Za-z]:$/, '').trim())
		.filter(s => s && s !== '.' && s !== '..');
	return parts.join('/').slice(0, 1024) || 'file';
}

async function readJson(req) {
	try {
		return await req.json();
	} catch {
		return null;
	}
}

// Normalize share options from either a JSON body or query params (values may be
// strings). Returns { values } on success or { error } with a message.
function parseOptions(src) {
	const out = {};

	out.title = typeof src.title === 'string' && src.title.trim() ? src.title.trim().slice(0, 200) : null;

	// expiresIn: omitted/empty -> default; 0 -> never; else seconds from now.
	if (src.expiresIn === undefined || src.expiresIn === null || src.expiresIn === '') {
		out.expiresAt = config.defaultExpiry > 0 ? now() + config.defaultExpiry : null;
	} else {
		const n = Number(src.expiresIn);
		if (!Number.isFinite(n) || n < 0) return { error: 'Invalid expiresIn' };
		out.expiresAt = n > 0 ? now() + Math.trunc(n) : null;
	}

	// maxDownloads: 0/null/omitted -> unlimited.
	out.maxDownloads = null;
	if (src.maxDownloads !== undefined && src.maxDownloads !== null && src.maxDownloads !== '') {
		const n = Number(src.maxDownloads);
		if (!Number.isFinite(n) || n < 0) return { error: 'Invalid maxDownloads' };
		out.maxDownloads = n > 0 ? Math.trunc(n) : null;
	}

	out.oneTime = src.oneTime === true || src.oneTime === 1 || src.oneTime === '1' || src.oneTime === 'true' ? 1 : 0;

	out.passwordPlain = typeof src.password === 'string' && src.password.length > 0 ? src.password : null;
	if (out.passwordPlain && out.passwordPlain.length > config.maxPasswordLength) return { error: 'Password is too long' };

	out.slug = null;
	if (src.slug !== undefined && src.slug !== null && src.slug !== '') {
		const slug = String(src.slug).trim();
		const err = slugError(slug);
		if (err) return { error: err };
		out.slug = slug;
	}

	return { values: out };
}

// Check a key's scopes/limits against the requested options. Returns an error
// message when the request is not permitted, else null. (Byte caps are enforced
// separately against the actual upload size.)
function scopeError(key, opts) {
	if (key.max_shares != null && key.upload_count >= key.max_shares) return 'This key has reached its share limit';
	if (opts.slug && key.allow_slug === 0) return 'This key may not set custom links';
	if (opts.passwordPlain && key.allow_password === 0) return 'This key may not set passwords';
	return null;
}

// Insert a share row attributed to `key`. Returns { id, editToken } or
// { conflict } when a requested slug is already taken. Applies the key's max
// share lifetime to the expiry.
async function createShare(ctx, key, opts) {
	let id;
	if (opts.slug) {
		if (getShareById.get(opts.slug)) return { conflict: 'That custom link is already taken' };
		id = opts.slug;
	} else {
		id = newShareId();
	}

	const expiresAt = clampExpiry(key, opts.expiresAt);
	const passwordHash = opts.passwordPlain ? await hashPassword(opts.passwordPlain) : null;
	const editToken = newToken();
	const ua = (ctx.req.headers.get('user-agent') || `API key: ${key.name}`).slice(0, 512);

	insertShare.run(id, opts.title, now(), expiresAt, passwordHash, opts.maxDownloads, opts.oneTime, editToken, ctx.ip ?? null, ua, key.id);
	// Lifetime stats (persist past deletion), plus the per-key tally.
	bumpMetric('shares_created');
	bumpUploader(ctx.ip, { shares: 1 });
	recordKeyUsage(key.id, { shares: 1 });

	return { id, editToken };
}

export default function apiV1(router) {
	// ---- Browser portal session (name + token login) -----------------------
	// Lets a key holder sign in to the web portal and manage the key's shares.
	router.post('/api/v1/login', async ctx => {
		const limited = enforce('apikey-login', ctx.ip, 10, 5 * 60 * 1000);
		if (limited) return limited;
		const body = (await readJson(ctx.req)) || {};
		const token = typeof body.token === 'string' ? body.token.trim() : '';
		const name = typeof body.name === 'string' ? body.name.trim() : '';
		const key = verifyApiKey(token);
		// Both fields must check out: the token must be valid (and not revoked/
		// expired) AND match the given name, so it reads like a name + secret login.
		if (!key || name.toLowerCase() !== String(key.name).toLowerCase()) {
			return error(403, 'That name and token do not match an active key');
		}
		const setCookie = cookie(APIKEY_COOKIE, issueApiKeySession(key.id), {
			maxAge: config.adminSessionTtl, httpOnly: true, sameSite: 'Lax', secure: requestScheme(ctx.req, ctx.url) === 'https',
		});
		return json({ id: key.id, name: key.name }, { headers: { 'Set-Cookie': setCookie } });
	});

	router.get('/api/v1/session', ctx => {
		const key = readApiKeySession(ctx.req);
		return json({ session: key ? { id: key.id, name: key.name } : null });
	});

	router.post('/api/v1/logout', () => json({ ok: true }, { headers: { 'Set-Cookie': clearCookie(APIKEY_COOKIE) } }));

	// ---- Key check ---------------------------------------------------------
	// A cheap endpoint a client can hit to confirm its key works.
	router.get('/api/v1/me', ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');
		return json({
			id: key.id,
			name: key.name,
			createdAt: key.created_at,
			lastUsedAt: key.last_used_at,
			expiresAt: key.expires_at,
			uploadCount: key.upload_count,
			bytesUploaded: key.bytes_uploaded,
		});
	});

	// ---- Create a share (resumable flow) -----------------------------------
	router.post('/api/v1/shares', async ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');
		const limited = enforce(`api-create:${key.id}`, ctx.ip, 120, 10 * 60 * 1000);
		if (limited) return limited;

		const body = (await readJson(ctx.req)) || {};
		const parsed = parseOptions(body);
		if (parsed.error) return error(400, parsed.error);

		const denied = scopeError(key, parsed.values);
		if (denied) return error(403, denied);

		const made = await createShare(ctx, key, parsed.values);
		if (made.conflict) return error(409, made.conflict);

		// Advertise the caps this key actually operates under, so the client sizes
		// its chunks/files correctly.
		const caps = effectiveCaps(key);
		return json(
			{
				id: made.id,
				editToken: made.editToken,
				url: `${requestOrigin(ctx.req, ctx.url)}/${made.id}`,
				chunkSize: config.chunkSize,
				maxFileSize: caps.maxFileSize,
				maxShareSize: caps.maxShareSize,
			},
			201,
		);
	});

	// ---- One-shot upload ---------------------------------------------------
	// The request body IS the file. Share options arrive as query params and the
	// filename as the `X-Filename` header (or `?filename=`). On success a finished,
	// finalized single-file share is returned. Larger or resumable uploads should
	// use POST /api/v1/shares + the standard chunked endpoints instead.
	router.post('/api/v1/upload', async ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');
		const limited = enforce(`api-upload:${key.id}`, ctx.ip, 120, 10 * 60 * 1000);
		if (limited) return limited;

		const q = ctx.query;
		const rawName = ctx.req.headers.get('x-filename') || q.get('filename');
		if (!rawName) return error(400, 'Missing filename (set the X-Filename header or ?filename=)');
		const name = sanitizeName(rawName);
		const mime = q.get('mime') || 'application/octet-stream';

		const parsed = parseOptions({
			title: q.get('title'),
			slug: q.get('slug'),
			password: q.get('password'),
			expiresIn: q.get('expiresIn'),
			maxDownloads: q.get('maxDownloads'),
			oneTime: q.get('oneTime'),
		});
		if (parsed.error) return error(400, parsed.error);

		const denied = scopeError(key, parsed.values);
		if (denied) return error(403, denied);

		// Buffer the body (bounded by the server's maxRequestBodySize) and enforce
		// caps BEFORE creating any rows, so a rejected upload leaves nothing behind.
		// The key's own per-file/per-share caps apply on top of the server limits.
		const caps = effectiveCaps(key);
		const buf = new Uint8Array(await ctx.req.arrayBuffer());
		const size = buf.length;
		if (size === 0) return error(400, 'Empty request body');
		if (size > caps.maxFileSize) return error(413, 'File exceeds this key\'s per-file size limit');
		if (size > caps.maxShareSize) return error(413, 'File exceeds this key\'s per-share size limit');
		if (config.maxTotalSize > 0 && (await totalUsage()) + size > config.maxTotalSize) {
			return error(413, 'Server storage limit reached');
		}

		const made = await createShare(ctx, key, parsed.values);
		if (made.conflict) return error(409, made.conflict);

		const fileId = newFileId();
		const iv = newIv();
		// Write the bytes BEFORE recording the file as complete, so a write failure
		// never leaves a phantom "complete" row pointing at a missing/partial blob.
		try {
			await writeChunk(made.id, fileId, 0, buf, iv);
		} catch (e) {
			console.error('one-shot upload write failed for', made.id, e);
			softDeleteShare.run(now(), made.id);
			await deleteShareFiles(made.id).catch(() => {});
			return error(500, 'Could not store the file');
		}
		insertFile.run(fileId, made.id, name, size, size, mime, 1, now(), fileId, iv);
		setFinalized.run(made.id);

		// File-completion stats (the chunked flow records these in uploads.js; the
		// one-shot path writes the bytes directly, so it records them here).
		bumpMetric('files_uploaded');
		bumpMetric('bytes_uploaded', size);
		bumpUploader(ctx.ip, { bytes: size });
		recordKeyUsage(key.id, { bytes: size });

		return json(
			{
				id: made.id,
				url: `${requestOrigin(ctx.req, ctx.url)}/${made.id}`,
				fileId,
				name,
				size,
			},
			201,
		);
	});

	// ---- List this key's shares (enumerate a backup) -----------------------
	router.get('/api/v1/shares', ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');

		const search = (ctx.query.get('search') || '').trim();
		let limit = Number(ctx.query.get('limit'));
		if (!Number.isFinite(limit) || limit <= 0) limit = 50;
		limit = Math.min(Math.trunc(limit), 500);
		let offset = Number(ctx.query.get('offset'));
		if (!Number.isFinite(offset) || offset < 0) offset = 0;
		offset = Math.trunc(offset);

		const like = `%${search}%`;
		const where = 'WHERE api_key_id = ? AND deleted_at IS NULL' + (search ? ' AND (id LIKE ? OR title LIKE ?)' : '');
		const filterArgs = search ? [key.id, like, like] : [key.id];

		const total = db.query(`SELECT COUNT(*) AS n FROM shares ${where}`).get(...filterArgs).n;
		// File count/size come from correlated subqueries in the one query (no N+1).
		// Uses the unaliased `shares` table so the same `where` string and the count
		// query above both apply unchanged.
		const rows = db
			.query(
				`SELECT shares.*,
					(SELECT COUNT(*) FROM files f WHERE f.share_id = shares.id) AS fileCount,
					(SELECT COALESCE(SUM(f.size), 0) FROM files f WHERE f.share_id = shares.id) AS totalSize
				FROM shares ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
			)
			.all(...filterArgs, limit, offset);
		const origin = requestOrigin(ctx.req, ctx.url);
		const shares = rows.map(s => ({ ...shareView(s, origin), fileCount: s.fileCount, totalSize: s.totalSize }));
		return json({ shares, total, limit, offset });
	});

	// ---- Inspect one of this key's shares ----------------------------------
	router.get('/api/v1/shares/:id', ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');
		const share = getOwnedShare.get(ctx.params.id, key.id);
		if (!share) return error(404, 'Not found');
		const files = getShareFiles.all(share.id);
		return json(shareView(share, requestOrigin(ctx.req, ctx.url), files));
	});

	// ---- Delete one of this key's shares (backup rotation) -----------------
	router.delete('/api/v1/shares/:id', async ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');
		const share = getOwnedShare.get(ctx.params.id, key.id);
		if (!share) return error(404, 'Not found');
		softDeleteShare.run(now(), share.id);
		await deleteShareFiles(share.id);
		return json({ ok: true });
	});
}
