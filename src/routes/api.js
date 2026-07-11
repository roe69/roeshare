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

import { createHash } from 'node:crypto';
import { config } from '../config.js';
import { db, now } from '../db.js';
import { json, error, requestOrigin, cookie, clearCookie, requestScheme, requireSameOrigin } from '../lib/http.js';
import { hashPassword, hashSecretToken } from '../lib/crypto.js';
import { newShareId, newFileId, newToken } from '../lib/ids.js';
import { writeChunk, deleteShareFiles, isCleanupPending } from '../lib/storage.js';
import * as quota from '../lib/quota.js';
import { newFileSalt } from '../lib/filecrypt.js';
import { CURRENT_AT_REST_KEY_ID } from '../lib/keys.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';
import { enforce, enforceKey } from '../lib/ratelimit.js';
import { acquire, acquireAll, overloaded } from '../lib/semaphore.js';
import { slugError } from '../lib/slug.js';
import { authenticate, authenticateSource, verifyApiKey, recordKeyUsage, effectiveCaps, clampExpiry, issueApiKeySession, readApiKeySession, APIKEY_COOKIE, apiKeyRow, requireScope } from '../lib/apikeys.js';
import { audit } from '../lib/audit.js';
import { declareRoutePolicy } from '../lib/routePolicy.js';

// lower(id) so a slug can never collide-by-case with an existing one (the
// on-disk share directory is effectively case-insensitive on some
// filesystems). Includes soft-deleted rows too - a key can reuse a slug it
// just deleted (the delete-then-recreate backup rotation flow), but the old
// row still holds the id's PRIMARY KEY slot, so createShare below must clear
// it before inserting rather than just checking deleted_at IS NULL here.
// api_key_id is selected too so createShare can confirm the CALLER owns a
// soft-deleted row before it is allowed to hard-delete it.
const getShareById = db.query('SELECT id, deleted_at, api_key_id FROM shares WHERE lower(id) = lower(?)');
const hardDeleteShare = db.query('DELETE FROM shares WHERE id = ?');
const insertShare = db.query(
	`INSERT INTO shares (id, title, created_at, expires_at, password_hash, max_downloads, one_time, edit_token, creator_ip, creator_ua, e2e, api_key_id)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
);
const insertFile = db.query(
	'INSERT INTO files (id, share_id, name, size, received, mime, complete, download_count, created_at, stored_name, iv, sha256, enc_version, key_id) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)',
);
const setFinalized = db.query('UPDATE shares SET finalized = 1 WHERE id = ?');
const softDeleteShare = db.query('UPDATE shares SET deleted_at = ? WHERE id = ?');

// A live share owned by `keyId` (created with that key, not soft-deleted). The
// expiry is NOT applied here so a key can still inspect/delete an expired-but-not-
// yet-swept share it created.
const getOwnedShare = db.query('SELECT * FROM shares WHERE id = ? AND api_key_id = ? AND deleted_at IS NULL');
const getShareFiles = db.query('SELECT id, name, size, received, mime, complete, download_count, created_at, sha256 FROM files WHERE share_id = ? ORDER BY created_at ASC, id ASC');

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
						sha256: f.sha256,
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

// Insert a share row attributed to `key`. Returns { id, editToken }, { conflict }
// when a requested slug is already taken, { limited } when the key has hit its
// share cap, or { overloaded } when the argon2 semaphore is full (password
// shares only). Applies the key's max share lifetime to the expiry.
//
// All async work (password hashing) happens BEFORE the transaction below.
// The slug-conflict recheck, the fresh max_shares check, the share insert, and
// the key's usage-tally bump then run inside one synchronous db.transaction():
// since nothing in that block awaits, no other request's continuation can
// interleave with it, which is what closes the race where concurrent requests
// on the same key all pass a stale upload_count snapshot and all succeed past
// max_shares. CONFLICT/LIMITED are thrown as sentinels so the transaction rolls
// back automatically (bun:sqlite semantics) instead of leaving a partial row.
async function createShare(ctx, key, opts) {
	const expiresAt = clampExpiry(key, opts.expiresAt);
	let passwordHash = null;
	if (opts.passwordPlain) {
		const release = acquire('argon2', null, 4);
		if (!release) return { overloaded: true };
		try {
			passwordHash = await hashPassword(opts.passwordPlain);
		} finally {
			release();
		}
	}
	const editToken = newToken();
	const ua = (ctx.req.headers.get('user-agent') || `API key: ${key.name}`).slice(0, 512);

	const CONFLICT = { conflict: 'That custom link is already taken' };
	const LIMITED = { limited: 'This key has reached its share limit' };
	// Distinct from CONFLICT so callers can tell "taken for good" apart from
	// "taken right now, try again shortly" - but shaped the same (a `conflict`
	// message) so it flows through the existing 409 handling below unchanged.
	const CLEANUP_PENDING = { conflict: 'That link was just deleted and is still being cleaned up; try again shortly' };

	const attempt = db.transaction(() => {
		let id;
		if (opts.slug) {
			const existing = getShareById.get(opts.slug);
			if (existing) {
				if (existing.deleted_at == null) throw CONFLICT;
				// Soft-deleted row squatting on this id: only the key that owns it
				// may reclaim the slug by hard-deleting it - otherwise any caller
				// requesting the same slug could permanently destroy another
				// tenant's soft-deleted share (edit_token hash, IPs, counters,
				// audit trail). Fall back to the ordinary CONFLICT when it is not
				// ours; from the caller's perspective the slug is simply taken.
				if (existing.api_key_id !== key.id) throw CONFLICT;
				// The previous occupant's directory may still be mid-removal
				// (deleteShareFiles runs as an unguarded background await after
				// the soft-delete - possibly triggered by shares.js's own DELETE
				// route rather than this file's; isCleanupPending is shared across
				// every caller via storage.js). Hard-deleting and reinserting now
				// would race that rm(), so make the caller retry until it has
				// finished instead of risking corrupting/losing the new tenant's
				// blobs.
				if (isCleanupPending(existing.id)) throw CLEANUP_PENDING;
				hardDeleteShare.run(existing.id);
			}
			id = opts.slug;
		} else {
			id = newShareId();
		}

		const fresh = apiKeyRow(key.id);
		if (fresh && fresh.max_shares != null && fresh.upload_count >= fresh.max_shares) throw LIMITED;

		insertShare.run(id, opts.title, now(), expiresAt, passwordHash, opts.maxDownloads, opts.oneTime, hashSecretToken(editToken), ctx.ip ?? null, ua, key.id);
		recordKeyUsage(key.id, { shares: 1 });
		return id;
	});

	let id;
	try {
		id = attempt();
	} catch (e) {
		if (e === CONFLICT || e === LIMITED || e === CLEANUP_PENDING) return e;
		throw e;
	}

	// Lifetime stats (persist past deletion); not part of the atomic check.
	bumpMetric('shares_created');
	bumpUploader(ctx.ip, { shares: 1 });
	// Shared by both the resumable (/api/v1/shares) and one-shot (/api/v1/upload)
	// creation paths - this is the single site both funnel through.
	audit('share.created', { ip: ctx.ip, actor: `apikey:${key.id}`, target: id });

	return { id, editToken };
}

export default function apiV1(router) {
	// ---- Browser portal session (name + token login) -----------------------
	// Lets a key holder sign in to the web portal and manage the key's shares.
	declareRoutePolicy('POST', '/api/v1/login', { auth: 'public', csrf: true, rateLimit: 'apikey-login', audit: 'apikey.login.failure|apikey.login.success' });
	router.post('/api/v1/login', async ctx => {
		const csrf = requireSameOrigin(ctx.req);
		if (csrf) return csrf;
		const limited = enforce('apikey-login', ctx.ip, 10, 5 * 60 * 1000);
		if (limited) return limited;
		const body = (await readJson(ctx.req)) || {};
		const token = typeof body.token === 'string' ? body.token.trim() : '';
		const name = typeof body.name === 'string' ? body.name.trim() : '';
		const key = verifyApiKey(token);
		// Both fields must check out: the token must be valid (and not revoked/
		// expired) AND match the given name, so it reads like a name + secret login.
		if (!key || name.toLowerCase() !== String(key.name).toLowerCase()) {
			// No key id in the record when the token itself didn't resolve to one.
			audit('apikey.login.failure', { ip: ctx.ip, target: key ? key.id : null });
			return error(403, 'That name and token do not match an active key');
		}
		audit('apikey.login.success', { ip: ctx.ip, actor: `apikey:${key.id}` });
		const setCookie = cookie(APIKEY_COOKIE, issueApiKeySession(key), {
			maxAge: config.adminSessionTtl, httpOnly: true, sameSite: 'Lax', secure: requestScheme(ctx.req, ctx.url, ctx.server) === 'https',
		});
		return json({ id: key.id, name: key.name }, { headers: { 'Set-Cookie': setCookie } });
	});

	declareRoutePolicy('GET', '/api/v1/session', { auth: 'public', csrf: false, rateLimit: null, audit: null });
	router.get('/api/v1/session', ctx => {
		const key = readApiKeySession(ctx.req);
		return json({ session: key ? { id: key.id, name: key.name } : null });
	});

	declareRoutePolicy('POST', '/api/v1/logout', { auth: 'public', csrf: true, rateLimit: null, audit: null });
	router.post('/api/v1/logout', ctx => {
		const csrf = requireSameOrigin(ctx.req);
		if (csrf) return csrf;
		return json({ ok: true }, { headers: { 'Set-Cookie': clearCookie(APIKEY_COOKIE) } });
	});

	// ---- Key check ---------------------------------------------------------
	// A cheap endpoint a client can hit to confirm its key works.
	declareRoutePolicy('GET', '/api/v1/me', { auth: 'apiKeyOrSession', csrf: false, rateLimit: 'api-me', audit: null });
	router.get('/api/v1/me', ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');
		const limited = enforceKey('api-me', key.id, 60, 60000);
		if (limited) return limited;
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
	declareRoutePolicy('POST', '/api/v1/shares', { auth: 'apiKeyOrSession', csrf: true, rateLimit: 'api-create', audit: 'share.created' });
	router.post('/api/v1/shares', async ctx => {
		const auth = authenticateSource(ctx.req);
		if (!auth) return error(401, 'Invalid or missing API key');
		if (auth.viaCookie) {
			const csrf = requireSameOrigin(ctx.req);
			if (csrf) return csrf;
		}
		const key = auth.key;
		const scopeDenied = requireScope(key, 'create');
		if (scopeDenied) return scopeDenied;
		const limited = enforceKey('api-create', key.id, 120, 10 * 60 * 1000);
		if (limited) return limited;

		const body = (await readJson(ctx.req)) || {};
		const parsed = parseOptions(body);
		if (parsed.error) return error(400, parsed.error);

		const denied = scopeError(key, parsed.values);
		if (denied) return error(403, denied);

		const made = await createShare(ctx, key, parsed.values);
		if (made.overloaded) return overloaded(2);
		if (made.conflict) return error(409, made.conflict);
		if (made.limited) return error(403, made.limited);

		// Advertise the caps this key actually operates under, so the client sizes
		// its chunks/files correctly.
		const caps = effectiveCaps(key);
		return json(
			{
				id: made.id,
				editToken: made.editToken,
				url: `${requestOrigin(ctx.req, ctx.url, ctx.server)}/${made.id}`,
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
	//
	// `password` is the one option that should NOT be passed as a query param
	// (URLs end up in proxy logs, browser history, Referer headers): send it via
	// the `X-Upload-Password` header instead. `?password=` still works for
	// backwards compatibility for one release but is deprecated - remove it in a
	// future release once clients have migrated.
	declareRoutePolicy('POST', '/api/v1/upload', { auth: 'apiKeyOrSession', csrf: true, rateLimit: 'api-upload', audit: 'share.created' });
	router.post('/api/v1/upload', async ctx => {
		const auth = authenticateSource(ctx.req);
		if (!auth) return error(401, 'Invalid or missing API key');
		if (auth.viaCookie) {
			const csrf = requireSameOrigin(ctx.req);
			if (csrf) return csrf;
		}
		const key = auth.key;
		let scopeDenied = requireScope(key, 'create');
		if (scopeDenied) return scopeDenied;
		scopeDenied = requireScope(key, 'write');
		if (scopeDenied) return scopeDenied;
		const limited = enforceKey('api-upload', key.id, 120, 10 * 60 * 1000);
		if (limited) return limited;

		const q = ctx.query;
		const rawName = ctx.req.headers.get('x-filename') || q.get('filename');
		if (!rawName) return error(400, 'Missing filename (set the X-Filename header or ?filename=)');
		const name = sanitizeName(rawName);
		const mime = q.get('mime') || 'application/octet-stream';

		// Prefer the password from the X-Upload-Password header: URLs (and thus
		// query params) end up in proxy access logs, browser history, and the
		// Referer header, none of which apply to headers. The `?password=` query
		// form is kept for one release for backwards compatibility and should be
		// removed once callers have migrated to the header.
		const parsed = parseOptions({
			title: q.get('title'),
			slug: q.get('slug'),
			password: ctx.req.headers.get('x-upload-password') || q.get('password'),
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

		// Reject an oversized body from the declared Content-Length BEFORE
		// buffering it into memory, so a key scoped to a tiny size cap cannot
		// still force the server to read up to the server-wide request-body
		// limit on every call (same idiom as the PATCH chunk-upload precheck in
		// uploads.js). Clients that omit/misreport Content-Length still get
		// caught by the actual-size checks below.
		const declaredLen = Number(ctx.req.headers.get('content-length'));
		if (Number.isFinite(declaredLen)) {
			if (declaredLen > caps.maxFileSize) return error(413, 'File exceeds this key\'s per-file size limit');
			if (declaredLen > caps.maxShareSize) return error(413, 'File exceeds this key\'s per-share size limit');
		}

		// Admission control: bound the number of one-shot bodies being buffered
		// whole into memory, both per-key (a backup script uploads sequentially)
		// and globally (worst-case in-flight buffer memory = 4 x maxFileSize).
		// Acquired BEFORE the body is read into memory.
		const release = acquireAll([
			['oneshot', key.id, 2],
			['oneshot-global', null, 4],
		]);
		if (!release) return overloaded(3);

		try {
			const buf = new Uint8Array(await ctx.req.arrayBuffer());
			const size = buf.length;
			if (size === 0) return error(400, 'Empty request body');
			if (size > caps.maxFileSize) return error(413, 'File exceeds this key\'s per-file size limit');
			if (size > caps.maxShareSize) return error(413, 'File exceeds this key\'s per-share size limit');

			// Reserve the global quota atomically (replacing the old cached-disk-walk
			// check-then-act) BEFORE any row exists - shareId is null here since no
			// share has been created yet for a one-shot upload.
			const fileId = newFileId();
			if (!quota.reserve(fileId, null, size)) {
				return error(413, 'Server storage limit reached');
			}
			const sha256 = createHash('sha256').update(buf).digest('hex');

			const made = await createShare(ctx, key, parsed.values);
			if (made.overloaded) {
				quota.releaseFile(fileId);
				return overloaded(2);
			}
			if (made.conflict) {
				quota.releaseFile(fileId);
				return error(409, made.conflict);
			}
			if (made.limited) {
				quota.releaseFile(fileId);
				return error(403, made.limited);
			}

			const iv = newFileSalt();
			// Write the bytes BEFORE recording the file as complete, so a write failure
			// never leaves a phantom "complete" row pointing at a missing/partial blob.
			try {
				await writeChunk(made.id, fileId, 0, buf, { version: 2, keyId: CURRENT_AT_REST_KEY_ID, fileSalt: iv, fileId });
			} catch (e) {
				console.error('one-shot upload write failed for', made.id, e);
				quota.releaseFile(fileId);
				softDeleteShare.run(now(), made.id);
				await deleteShareFiles(made.id).catch(() => {});
				return error(500, 'Could not store the file');
			}
			insertFile.run(fileId, made.id, name, size, size, mime, 1, now(), fileId, iv, sha256, 2, CURRENT_AT_REST_KEY_ID);
			setFinalized.run(made.id);
			quota.commit(fileId, size);

			// File-completion stats (the chunked flow records these in uploads.js; the
			// one-shot path writes the bytes directly, so it records them here).
			bumpMetric('files_uploaded');
			bumpMetric('bytes_uploaded', size);
			bumpUploader(ctx.ip, { bytes: size });
			recordKeyUsage(key.id, { bytes: size });

			return json(
				{
					id: made.id,
					url: `${requestOrigin(ctx.req, ctx.url, ctx.server)}/${made.id}`,
					fileId,
					name,
					size,
				},
				201,
			);
		} finally {
			release();
		}
	});

	// ---- List this key's shares (enumerate a backup) -----------------------
	declareRoutePolicy('GET', '/api/v1/shares', { auth: 'apiKeyOrSession', csrf: false, rateLimit: 'api-list', audit: null });
	router.get('/api/v1/shares', ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');
		const scopeDenied = requireScope(key, 'read');
		if (scopeDenied) return scopeDenied;
		const limited = enforceKey('api-list', key.id, 300, 60000);
		if (limited) return limited;

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
		const origin = requestOrigin(ctx.req, ctx.url, ctx.server);
		const shares = rows.map(s => ({ ...shareView(s, origin), fileCount: s.fileCount, totalSize: s.totalSize }));
		return json({ shares, total, limit, offset });
	});

	// ---- Inspect one of this key's shares ----------------------------------
	declareRoutePolicy('GET', '/api/v1/shares/:id', { auth: 'apiKeyOrSession', csrf: false, rateLimit: 'api-get', audit: null });
	router.get('/api/v1/shares/:id', ctx => {
		const key = authenticate(ctx.req);
		if (!key) return error(401, 'Invalid or missing API key');
		const scopeDenied = requireScope(key, 'read');
		if (scopeDenied) return scopeDenied;
		const limited = enforceKey('api-get', key.id, 300, 60000);
		if (limited) return limited;
		const share = getOwnedShare.get(ctx.params.id, key.id);
		if (!share) return error(404, 'Not found');
		const files = getShareFiles.all(share.id);
		return json(shareView(share, requestOrigin(ctx.req, ctx.url, ctx.server), files));
	});

	// ---- Delete one of this key's shares (backup rotation) -----------------
	declareRoutePolicy('DELETE', '/api/v1/shares/:id', { auth: 'apiKeyOrSession', csrf: true, rateLimit: 'api-delete', audit: 'share.deleted' });
	router.delete('/api/v1/shares/:id', async ctx => {
		const auth = authenticateSource(ctx.req);
		if (!auth) return error(401, 'Invalid or missing API key');
		if (auth.viaCookie) {
			const csrf = requireSameOrigin(ctx.req);
			if (csrf) return csrf;
		}
		const key = auth.key;
		const scopeDenied = requireScope(key, 'delete');
		if (scopeDenied) return scopeDenied;
		const limited = enforceKey('api-delete', key.id, 60, 60000);
		if (limited) return limited;
		const share = getOwnedShare.get(ctx.params.id, key.id);
		if (!share) return error(404, 'Not found');
		softDeleteShare.run(now(), share.id);
		quota.releaseShare(share.id);
		await deleteShareFiles(share.id);
		audit('share.deleted', { ip: ctx.ip, actor: `apikey:${key.id}`, target: share.id });
		return json({ ok: true });
	});
}
