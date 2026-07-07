// Auth helpers built on signed tokens (see crypto.js). There is no session
// store: an admin cookie and per-share access grants are self-contained signed
// payloads. Passwords (admin/upload) come from config; per-share passwords are
// argon2 hashes stored on the share row.
//
// Each admin/upload session token also carries a `k` fingerprint of the password
// it was issued under (credentialTag). Every request re-derives the current
// fingerprint and rejects a token whose `k` no longer matches, so rotating
// ADMIN_PASSWORD / UPLOAD_PASSWORD (which takes effect on the next restart)
// invalidates all outstanding sessions - a leaked or stale cookie stops working
// without needing a full SECRET rotation.

import { config } from '../config.js';
import { signToken, verifyToken, safeEqual, credentialTag } from './crypto.js';
import { parseCookies } from './http.js';

export const ADMIN_COOKIE = 'roeshare_admin';
export const UPLOAD_COOKIE = 'roeshare_upload';

// ---- Admin -----------------------------------------------------------------

const adminTag = () => credentialTag('admin', config.adminPassword);

export function checkAdminPassword(password) {
	if (!config.adminPassword) return false; // admin disabled when unset
	return safeEqual(password, config.adminPassword);
}

export function issueAdminToken() {
	return signToken({ role: 'admin', k: adminTag() }, config.adminSessionTtl);
}

export function isAdmin(req) {
	if (!config.adminPassword) return false; // admin disabled: no session is valid
	const token = parseCookies(req)[ADMIN_COOKIE];
	if (!token) return false;
	const payload = verifyToken(token);
	return !!payload && payload.role === 'admin' && payload.k === adminTag();
}

// ---- Upload gate -----------------------------------------------------------

const uploadTag = () => credentialTag('upload', config.uploadPassword);

export function uploadAllowed(password) {
	if (!config.uploadPassword) return true; // open uploads
	return safeEqual(password ?? '', config.uploadPassword);
}

// A signed cookie issued after the upload password is verified. It gates BOTH
// the upload portal's markup/code (served only with this cookie) and share
// creation, so an unauthorized visitor never receives the upload code at all.
export function issueUploadToken() {
	return signToken({ scope: 'upload', k: uploadTag() }, config.adminSessionTtl);
}

export function hasUploadAccess(req) {
	if (!config.uploadPassword) return true; // open uploads: no gate
	const token = parseCookies(req)[UPLOAD_COOKIE];
	if (!token) return false;
	const payload = verifyToken(token);
	return !!payload && payload.scope === 'upload' && payload.k === uploadTag();
}

// A stable, shareable "quick access" token for instant upload login via a link
// (?token=...). It is derived from SECRET (so it cannot be forged) but is NOT
// the upload password itself, so the link can be handed to a trusted person
// without revealing the real password. It expires after 90 days so a
// forgotten/leaked link eventually ages out. It also carries the upload-password
// fingerprint, so changing (or clearing) the upload password invalidates every
// outstanding quick-access link on the next restart - rotate the upload password
// (or SECRET) to revoke handed-out links without waiting for them to age out.
export function uploadLinkToken() {
	return signToken({ scope: 'upload-link', k: uploadTag() }, 90 * 24 * 3600);
}

// True if `token` authorizes upload login via the quick-access link above. The
// raw upload password is no longer accepted here - only through the POST
// /api/upload/verify body - so it can never land in a URL/access log via the
// query string. Only meaningful when an upload password is configured.
export function checkUploadLink(token) {
	if (!config.uploadPassword || !token) return false;
	const payload = verifyToken(token);
	return !!payload && payload.scope === 'upload-link' && payload.k === uploadTag();
}

// ---- Per-share access ------------------------------------------------------
// After a visitor unlocks a password-protected share, we hand them a short-lived
// signed token scoped to that share id. The edit token (returned to the
// uploader at creation) also grants access for management.

export function issueAccessToken(shareId) {
	return signToken({ scope: 'access', sid: shareId }, config.accessTokenTtl);
}

export function hasAccessToken(token, shareId) {
	const p = verifyToken(token);
	return !!p && p.scope === 'access' && p.sid === shareId;
}

// The access token may arrive via the Authorization: Bearer header or an
// `access` query param (handy for direct <video>/<img> element src URLs).
export function readAccessToken(req, url) {
	const auth = req.headers.get('authorization');
	if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
	return url?.searchParams?.get('access') || null;
}
