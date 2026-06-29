// Share lifecycle + metadata routes: public config, draft creation, password
// unlock, visitor metadata, finalize, and owner/admin delete. Upload (chunking)
// and download/preview live in their own modules.

import { config } from '../config.js';
import { db, now } from '../db.js';
import { json, error, cookie } from '../lib/http.js';
import { hashPassword, verifyPassword, safeEqual } from '../lib/crypto.js';
import { uploadAllowed, isAdmin, issueAccessToken, hasAccessToken, readAccessToken, hasUploadAccess, issueUploadToken, UPLOAD_COOKIE } from '../lib/auth.js';
import { newShareId, newToken } from '../lib/ids.js';
import { deleteShareFiles } from '../lib/storage.js';
import { enforce } from '../lib/ratelimit.js';
import { slugError } from '../lib/slug.js';

const getShare = db.query('SELECT * FROM shares WHERE id = ?');
const insertShare = db.query(
	`INSERT INTO shares (id, title, created_at, expires_at, password_hash, max_downloads, one_time, edit_token, creator_ip, creator_ua, e2e)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
);
const getFiles = db.query('SELECT id, name, size, mime, complete, download_count FROM files WHERE share_id = ? ORDER BY created_at ASC');
const setFinalized = db.query('UPDATE shares SET finalized = 1 WHERE id = ?');
const softDelete = db.query('UPDATE shares SET deleted_at = ? WHERE id = ?');

// A share is "live" when it exists, is not soft-deleted, and has not expired.
function liveShare(id) {
	const share = getShare.get(id);
	if (!share || share.deleted_at != null) return null;
	if (share.expires_at != null && share.expires_at < now()) return null;
	return share;
}

function isOwner(req, share) {
	const token = req.headers.get('x-edit-token');
	return !!token && safeEqual(token, share.edit_token);
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

	router.get('/api/config', () =>
		json({
			chunkSize: config.chunkSize,
			maxFileSize: config.maxFileSize,
			maxShareSize: config.maxShareSize,
			defaultExpiry: config.defaultExpiry,
			uploadPasswordRequired: !!config.uploadPassword,
			baseUrl: config.baseUrl,
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
		const setCookie = cookie(UPLOAD_COOKIE, issueUploadToken(), { maxAge: config.adminSessionTtl, httpOnly: true, sameSite: 'Lax', secure: config.baseUrl.startsWith('https') });
		return json({ ok: true }, { headers: { 'Set-Cookie': setCookie } });
	});

	// ---- Create draft ------------------------------------------------------

	router.post('/api/shares', async ctx => {
		// Spam guard: cap new shares per IP (30 per 10 minutes).
		const limited = enforce('share-create', ctx.ip, 30, 10 * 60 * 1000);
		if (limited) return limited;

		const body = (await readJson(ctx.req)) || {};

		// Authorized by the upload cookie (the gate) or an explicit password in the body.
		if (config.uploadPassword && !hasUploadAccess(ctx.req) && !uploadAllowed(body.uploadPassword)) {
			return error(403, 'Upload password required');
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
			passwordHash = await hashPassword(body.password);
		}

		const oneTime = body.oneTime ? 1 : 0;
		// End-to-end encrypted shares: the client encrypts before upload and the
		// server never sees the key. Server-side at-rest encryption is skipped for
		// these (the bytes are already ciphertext) and server-side preview/zip are
		// disabled - the browser does all decryption.
		const e2e = body.e2e ? 1 : 0;

		// Optional custom URL slug. Charset excludes dots/slashes (traversal-safe)
		// and the slug is namespaced under /s/ so it cannot collide with a route.
		// Any existing row with that id - including soft-deleted ones, which keep
		// the primary key - counts as taken.
		let id;
		if (body.slug !== undefined && body.slug !== null && body.slug !== '') {
			const slug = String(body.slug).trim();
			const err = slugError(slug);
			if (err) return error(400, err);
			if (getShare.get(slug)) return error(409, 'That custom link is already taken');
			id = slug;
		} else {
			id = newShareId();
		}

		const editToken = newToken();
		const ua = (ctx.req.headers.get('user-agent') || '').slice(0, 512) || null;

		insertShare.run(id, title, now(), expiresAt, passwordHash, maxDownloads, oneTime, editToken, ctx.ip ?? null, ua, e2e);

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
		const ok = await verifyPassword(password, share.password_hash);
		if (!ok) return error(403, 'Incorrect password');

		return json({ accessToken: issueAccessToken(share.id) });
	});

	// ---- Visitor metadata --------------------------------------------------

	router.get('/api/shares/:id', ctx => {
		const share = liveShare(ctx.params.id);
		if (!share) return error(404, 'Not found');

		const owner = isOwner(ctx.req, share);

		if (share.password_hash && !owner) {
			const token = readAccessToken(ctx.req, ctx.url);
			if (!token || !hasAccessToken(token, share.id)) {
				return json({ protected: true, title: share.title }, 401);
			}
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
			finalized: !!share.finalized,
			totalSize,
			owner,
			// Owners (validated via X-Edit-Token) get a read access token so their
			// element-src previews and download links work without unlocking - the
			// edit token itself is too sensitive to place in URLs.
			...(owner ? { accessToken: issueAccessToken(share.id) } : {}),
			files: files.map(f => ({
				id: f.id,
				name: f.name,
				size: f.size,
				mime: f.mime,
				complete: !!f.complete,
				downloadCount: f.download_count,
			})),
		});
	});

	// ---- Finalize ----------------------------------------------------------

	router.post('/api/shares/:id/finalize', ctx => {
		const share = liveShare(ctx.params.id);
		if (!share) return error(404, 'Not found');
		if (!isOwner(ctx.req, share)) return error(403, 'Forbidden');

		setFinalized.run(share.id);
		return json({ id: share.id, url: `${config.baseUrl}/${share.id}` });
	});

	// ---- Delete (owner or admin) -------------------------------------------

	router.delete('/api/shares/:id', async ctx => {
		const share = liveShare(ctx.params.id);
		if (!share) return error(404, 'Not found');
		if (!isOwner(ctx.req, share) && !isAdmin(ctx.req)) return error(403, 'Forbidden');

		softDelete.run(now(), share.id);
		await deleteShareFiles(share.id);
		return json({ ok: true });
	});
}
