// Share lifecycle + metadata routes: public config, draft creation, password
// unlock, visitor metadata, finalize, and owner/admin delete. Upload (chunking)
// and download/preview live in their own modules.

import { config } from '../config.js';
import { db, now } from '../db.js';
import { json, error, cookie, requestOrigin, requestScheme, requireSameOrigin } from '../lib/http.js';
import { hashPassword, verifyPassword, hashSecretToken, verifySecretToken } from '../lib/crypto.js';
import { uploadAllowed, isAdmin, issueAccessToken, hasAccessToken, readAccessToken, hasUploadAccess, issueUploadToken, uploadLinkToken, UPLOAD_COOKIE } from '../lib/auth.js';
import { bumpMetric, bumpUploader } from '../lib/stats.js';
import { newShareId, newToken } from '../lib/ids.js';
import { deleteShareFiles } from '../lib/storage.js';
import { enforce } from '../lib/ratelimit.js';
import { acquire, overloaded } from '../lib/semaphore.js';
import { slugError } from '../lib/slug.js';
import { keyValidForShare, scopeErrorForShare, apiKeyRow, hasScope } from '../lib/apikeys.js';
import * as quota from '../lib/quota.js';

const getShare = db.query('SELECT * FROM shares WHERE id = ?');
// Case-insensitive slug-conflict check: a soft-deleted share no longer holds
// its slug, so it is excluded here (unlike getShare/liveShare, which still
// resolve deleted rows by exact id for existing links).
const getShareBySlugCI = db.query('SELECT id FROM shares WHERE lower(id) = lower(?) AND deleted_at IS NULL');
const insertShare = db.query(
	`INSERT INTO shares (id, title, created_at, expires_at, password_hash, max_downloads, one_time, edit_token, creator_ip, creator_ua, e2e)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
);
const getFiles = db.query('SELECT id, name, size, received, mime, complete, download_count, sha256 FROM files WHERE share_id = ? ORDER BY created_at ASC');
const setFinalized = db.query('UPDATE shares SET finalized = 1 WHERE id = ?');
// Shifts a share's expiry forward by the time spent uploading, so the
// published-link expiry clock effectively starts at finalize rather than at
// share creation (see the finalize handler below).
const shiftExpiry = db.query('UPDATE shares SET expires_at = expires_at + (? - created_at) WHERE id = ?');
const softDelete = db.query('UPDATE shares SET deleted_at = ? WHERE id = ?');
const incShareView = db.query('UPDATE shares SET view_count = view_count + 1 WHERE id = ?');

// A share is "live" when it exists, is not soft-deleted, and has not expired.
// A non-finalized share's expiry clock has not started yet (see finalize,
// below), so it is never treated as expired while still being uploaded.
function liveShare(id) {
	const share = getShare.get(id);
	if (!share || share.deleted_at != null) return null;
	if (share.finalized && share.expires_at != null && share.expires_at < now()) return null;
	return share;
}

// A matching edit token is not enough on its own: if the share was created via
// an API key that has since been revoked or expired, treat it exactly like an
// invalid token - otherwise "revoke" would only stop that key's own
// bearer-token calls while the shares it already made keep accepting owner
// actions via the edit token forever.
function isOwner(req, share) {
	const token = req.headers.get('x-edit-token');
	return !!token && verifySecretToken(token, share.edit_token) && keyValidForShare(share);
}

async function readJson(req) {
	try {
		return await req.json();
	} catch {
		return null;
	}
}

export default function shares(router) {
	// ---- Public config -----------------------------------------------------

	router.get('/api/config', ctx =>
		json({
			chunkSize: config.chunkSize,
			maxFileSize: config.maxFileSize,
			maxShareSize: config.maxShareSize,
			defaultExpiry: config.defaultExpiry,
			defaultE2e: config.defaultE2e,
			uploadPasswordRequired: !!config.uploadPassword,
			// Resolved from the visitor's host so links match the domain in use.
			baseUrl: requestOrigin(ctx.req, ctx.url, ctx.server),
		})
	);

	// ---- Upload-password gate ----------------------------------------------
	// Lets the upload page verify the upload password and reveal the portal
	// before any file is chosen. The real enforcement is still on share create.

	router.post('/api/upload/verify', async ctx => {
		const limited = enforce('upload-verify', ctx.ip, 20, 5 * 60 * 1000);
		if (limited) return limited;
		if (!config.uploadPassword) return json({ ok: true });
		const body = (await readJson(ctx.req)) || {};
		if (!uploadAllowed(body.password)) return error(403, 'Incorrect upload password');
		const setCookie = cookie(UPLOAD_COOKIE, issueUploadToken(), { maxAge: config.adminSessionTtl, httpOnly: true, sameSite: 'Lax', secure: requestScheme(ctx.req, ctx.url, ctx.server) === 'https' });
		return json({ ok: true }, { headers: { 'Set-Cookie': setCookie } });
	});

	// ---- Quick-access link --------------------------------------------------
	// Returns a shareable instant-login link for an already-authorized uploader.
	// The token is derived from SECRET (not the password), so handing out the link
	// never exposes the real upload password. Only available to a caller that
	// already holds upload access, and only when an upload password is configured.

	router.get('/api/upload/link', ctx => {
		if (!config.uploadPassword) return json({ enabled: false });
		if (!hasUploadAccess(ctx.req)) return error(403, 'Forbidden');
		return json({ enabled: true, url: `${requestOrigin(ctx.req, ctx.url, ctx.server)}/?token=${encodeURIComponent(uploadLinkToken())}` });
	});

	// ---- Create draft ------------------------------------------------------

	router.post('/api/shares', async ctx => {
		// Spam guard: cap new shares per IP (30 per 10 minutes).
		const limited = enforce('share-create', ctx.ip, 30, 10 * 60 * 1000);
		if (limited) return limited;

		const body = (await readJson(ctx.req)) || {};

		// Authorized by the upload cookie (the gate) or an explicit password in the body.
		if (config.uploadPassword && !uploadAllowed(body.uploadPassword)) {
			if (!hasUploadAccess(ctx.req)) return error(403, 'Upload password required');
			// Ambient-cookie authorization (no explicit password in this request) -
			// require same-origin proof (F-10 CSRF defense-in-depth). A request that
			// supplied a real body password needs no such proof: it is not riding an
			// ambient credential.
			const csrf = requireSameOrigin(ctx.req);
			if (csrf) return csrf;
		}

		let title = null;
		if (typeof body.title === 'string') {
			title = body.title.trim().slice(0, 200) || null;
		}

		// expiresIn: omitted -> default; 0 -> never; otherwise seconds from now.
		let expiresAt;
		if (body.expiresIn === undefined || body.expiresIn === null) {
			expiresAt = config.defaultExpiry > 0 ? now() + config.defaultExpiry : null;
		} else {
			const n = Number(body.expiresIn);
			if (!Number.isFinite(n) || n < 0) return error(400, 'Invalid expiresIn');
			expiresAt = n > 0 ? now() + Math.trunc(n) : null;
		}

		// maxDownloads: 0/null/omitted -> unlimited.
		let maxDownloads = null;
		if (body.maxDownloads !== undefined && body.maxDownloads !== null) {
			const n = Number(body.maxDownloads);
			if (!Number.isFinite(n) || n < 0) return error(400, 'Invalid maxDownloads');
			maxDownloads = n > 0 ? Math.trunc(n) : null;
		}

		let passwordHash = null;
		if (typeof body.password === 'string' && body.password.length > 0) {
			if (body.password.length > config.maxPasswordLength) return error(400, 'Password is too long');
			const release = acquire('argon2', null, 4);
			if (!release) return overloaded(2);
			try {
				passwordHash = await hashPassword(body.password);
			} finally {
				release();
			}
		}

		const oneTime = body.oneTime ? 1 : 0;
		// End-to-end encrypted shares: the client encrypts before upload and the
		// server never sees the key. Server-side at-rest encryption is skipped for
		// these (the bytes are already ciphertext) and server-side preview/zip are
		// disabled - the browser does all decryption.
		const e2e = body.e2e ? 1 : 0;

		// Optional custom URL slug. Charset excludes dots/slashes (traversal-safe)
		// and the slug is namespaced under /s/ so it cannot collide with a route.
		// Matched case-insensitively against any other live (non-soft-deleted)
		// share id; a soft-deleted share frees its slug for reuse.
		let id;
		if (body.slug !== undefined && body.slug !== null && body.slug !== '') {
			const slug = String(body.slug).trim();
			const err = slugError(slug);
			if (err) return error(400, err);
			if (getShareBySlugCI.get(slug)) return error(409, 'That custom link is already taken');
			id = slug;
		} else {
			id = newShareId();
		}

		const editToken = newToken();
		const ua = (ctx.req.headers.get('user-agent') || '').slice(0, 512) || null;

		try {
			insertShare.run(id, title, now(), expiresAt, passwordHash, maxDownloads, oneTime, hashSecretToken(editToken), ctx.ip ?? null, ua, e2e);
		} catch (e) {
			// A soft-deleted share keeps its row (and its id, the primary key) around,
			// so getShareBySlugCI's "taken" check above cannot see it and reusing that
			// slug hits a PK collision here. Report it the same way as an upfront
			// conflict rather than letting it surface as a 500.
			if (String(e?.message).includes('UNIQUE constraint failed')) return error(409, 'That custom link is already taken');
			throw e;
		}
		// Lifetime stats (persist past deletion).
		bumpMetric('shares_created');
		bumpUploader(ctx.ip, { shares: 1 });

		return json(
			{
				id,
				editToken,
				chunkSize: config.chunkSize,
				maxFileSize: config.maxFileSize,
				maxShareSize: config.maxShareSize,
			},
			201
		);
	});

	// ---- Unlock (password -> access token) ---------------------------------

	router.post('/api/shares/:id/unlock', async ctx => {
		// Resolve the share first so attempts against random/nonexistent ids cannot
		// mint a long-lived rate-limit bucket each (a memory-growth vector).
		const share = liveShare(ctx.params.id);
		if (!share) return error(404, 'Not found');

		// Brute-force guard on share passwords: 15 attempts per 5 minutes per
		// IP+share. Keyed by share so one share's attempts cannot lock out others.
		const limited = enforce(`unlock:${ctx.params.id}`, ctx.ip, 15, 5 * 60 * 1000);
		if (limited) return limited;

		const body = (await readJson(ctx.req)) || {};
		const password = body.password ?? '';
		if (typeof password === 'string' && password.length > config.maxPasswordLength) return error(400, 'Password is too long');
		const release = acquire('argon2', null, 4);
		if (!release) return overloaded(2);
		let ok;
		try {
			ok = await verifyPassword(password, share.password_hash);
		} finally {
			release();
		}
		if (!ok) return error(403, 'Incorrect password');

		return json({ accessToken: issueAccessToken(share.id, share.password_hash) });
	});

	// ---- Visitor metadata --------------------------------------------------

	router.get('/api/shares/:id', ctx => {
		const limited = enforce('meta', ctx.ip, 240, 60_000);
		if (limited) return limited;
		const share = liveShare(ctx.params.id);
		if (!share) return error(404, 'Not found');

		// A write/create-only key's edit token still authenticates as owner
		// (isOwner), but read-elevation here degrades rather than errors: without
		// the shares:read scope on the backing key, treat the caller as an
		// ordinary visitor instead of a 403 - so a write-only drop-box key never
		// breaks public visitors of its own shares (the password gate still
		// applies normally below).
		const owner = isOwner(ctx.req, share) && (share.api_key_id == null || hasScope(apiKeyRow(share.api_key_id), 'read'));

		if (share.password_hash && !owner) {
			const token = readAccessToken(ctx.req, ctx.url);
			if (!token || !hasAccessToken(token, share.id, share.password_hash)) {
				// No share metadata (title in particular, which for backup jobs may
				// contain hostnames/customer names) before the visitor has proven
				// they know the password.
				return json({ protected: true }, 401);
			}
		}

		// Count a view when a non-owner opens the share (the page loads its
		// metadata once). Owners checking their own share never inflate the count.
		const counted = !owner;
		if (counted) {
			incShareView.run(share.id);
			bumpMetric('views');
		}

		const files = getFiles.all(share.id);
		const totalSize = files.reduce((sum, f) => sum + f.size, 0);

		return json({
			id: share.id,
			title: share.title,
			createdAt: share.created_at,
			expiresAt: share.expires_at,
			oneTime: !!share.one_time,
			e2e: !!share.e2e,
			maxDownloads: share.max_downloads,
			downloadCount: share.download_count,
			viewCount: (share.view_count || 0) + (counted ? 1 : 0),
			finalized: !!share.finalized,
			totalSize,
			owner,
			// Owners (validated via X-Edit-Token) get a read access token so their
			// element-src previews and download links work without unlocking - the
			// edit token itself is too sensitive to place in URLs.
			...(owner ? { accessToken: issueAccessToken(share.id, share.password_hash) } : {}),
			files: files.map(f => ({
				id: f.id,
				name: f.name,
				size: f.size,
				mime: f.mime,
				complete: !!f.complete,
				downloadCount: f.download_count,
				sha256: f.sha256,
				// Owners get the resume offset (bytes received so far) so a refreshed
				// upload page can continue an in-flight file. Not exposed to visitors.
				...(owner ? { received: f.received } : {}),
			})),
		});
	});

	// ---- Finalize ----------------------------------------------------------

	router.post('/api/shares/:id/finalize', ctx => {
		// Resolve the share first so attempts against random/nonexistent ids cannot
		// mint a long-lived rate-limit bucket each (a memory-growth vector).
		const share = liveShare(ctx.params.id);
		if (!share) return error(404, 'Not found');
		const limited = enforce(`finalize:${ctx.params.id}`, ctx.ip, 60, 60_000);
		if (limited) return limited;
		if (!isOwner(ctx.req, share)) return error(403, 'Forbidden');
		const scopeErr = scopeErrorForShare(share, 'write');
		if (scopeErr) return scopeErr;

		// Start the published-link expiry clock at finalize, not at creation: shift
		// expires_at forward by however long the upload took, so the link lives for
		// its intended duration from the moment it is actually published. Only on
		// the first finalize, so a re-finalize cannot keep pushing the clock out.
		const firstFinalize = !share.finalized;
		setFinalized.run(share.id);
		if (firstFinalize && share.expires_at != null) shiftExpiry.run(now(), share.id);
		return json({ id: share.id, url: `${requestOrigin(ctx.req, ctx.url, ctx.server)}/${share.id}` });
	});

	// ---- Delete (owner or admin) -------------------------------------------

	router.delete('/api/shares/:id', async ctx => {
		// Resolve the share first so attempts against random/nonexistent ids cannot
		// mint a long-lived rate-limit bucket each (a memory-growth vector).
		const share = liveShare(ctx.params.id);
		if (!share) return error(404, 'Not found');
		const limited = enforce(`delete:${ctx.params.id}`, ctx.ip, 60, 60_000);
		if (limited) return limited;
		const owner = isOwner(ctx.req, share);
		if (!owner) {
			if (!isAdmin(ctx.req)) return error(403, 'Forbidden');
			// Admin authorization here is the ambient isAdmin() cookie, not the
			// X-Edit-Token header - require same-origin proof (F-10 CSRF
			// defense-in-depth). The edit-token path below is a header, not an
			// ambient credential, so it needs no such proof.
			const csrf = requireSameOrigin(ctx.req);
			if (csrf) return csrf;
		}
		// Only the edit-token (key-owner) path is scope-gated; an admin deleting
		// through the admin session bypasses per-key scopes entirely, same as
		// every other admin route.
		if (owner) {
			const scopeErr = scopeErrorForShare(share, 'delete');
			if (scopeErr) return scopeErr;
		}

		softDelete.run(now(), share.id);
		quota.releaseShare(share.id);
		await deleteShareFiles(share.id);
		return json({ ok: true });
	});
}
