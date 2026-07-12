// Auth helpers built on signed tokens (see crypto.js). There is no session
// store for admin/upload/owner sessions: they are self-contained signed
// payloads (see the "__Host-" cookie-naming pair in lib/http.js used to set/
// read every one of them - L-08). Passwords (admin/upload) come from config;
// per-share passwords are argon2 hashes stored on the share row. The one
// piece of server-side state below is the single-use upload magic-link token
// table (M-01 Part B), because single-use redemption is not expressible as a
// stateless signed token.
//
// Each admin/upload/owner session token also carries a `k` fingerprint of the
// credential it was issued under (credentialTag). Every request re-derives
// the current fingerprint and rejects a token whose `k` no longer matches, so
// rotating ADMIN_PASSWORD / UPLOAD_PASSWORD / a share's edit token (which
// takes effect immediately, or on the next restart for the env-config cases)
// invalidates all outstanding sessions - a leaked or stale cookie stops
// working without needing a full SECRET rotation.
//
// F-13: the admin fingerprint also folds in mfa.js's mfaEnabledAt(), so
// enabling or disabling TOTP MFA changes the fingerprint too - every
// outstanding admin cookie (and any intermediate MFA cookie, which carries the
// same fingerprint) is invalidated the moment MFA is toggled, with no new
// invalidation machinery needed.

import { config } from '../config.js';
import { db, now } from '../db.js';
import { signToken, verifyToken, safeEqual, credentialTag, hashSecretToken } from './crypto.js';
import { readSessionCookie } from './http.js';
import { mfaEnabledAt } from './mfa.js';
import { newToken } from './ids.js';

export const ADMIN_COOKIE = 'roeshare_admin';
export const ADMIN_MFA_COOKIE = 'roeshare_admin_mfa';
export const UPLOAD_COOKIE = 'roeshare_upload';
// M-05/L-08: the owner-session cookie is named PER SHARE (see ownerCookieBase
// below), not this base alone - a fixed base with a shared cookie Path would
// have worked too (the finding's original sketch), but "__Host-" (L-08)
// mandates Path=/, which rules path-scoping out. Encoding the share id into
// the cookie NAME instead gives the same "shares never collide" guarantee
// while still qualifying for "__Host-".
export const OWNER_COOKIE_BASE = 'roeshare_owner';

// ---- Admin -----------------------------------------------------------------

const adminTag = () => credentialTag('admin', `${config.adminPassword}\0mfa:${mfaEnabledAt() ?? 0}`);

export function checkAdminPassword(password) {
	if (!config.adminPassword) return false; // admin disabled when unset
	return safeEqual(password, config.adminPassword);
}

export function issueAdminToken() {
	return signToken({ role: 'admin', k: adminTag() }, config.adminSessionTtl);
}

export function isAdmin(req) {
	if (!config.adminPassword) return false; // admin disabled: no session is valid
	const token = readSessionCookie(req, ADMIN_COOKIE);
	if (!token) return false;
	const payload = verifyToken(token);
	return !!payload && payload.role === 'admin' && safeEqual(payload.k, adminTag());
}

// ---- Admin MFA step-up (intermediate cookie) --------------------------------
// Issued after the password check passes when MFA is enabled, in place of the
// real admin cookie, so a correct password alone never grants a session. Short
// (5 minute) TTL; carries the same adminTag() fingerprint as the real admin
// cookie, so it is invalidated the instant MFA is toggled too.

const ADMIN_MFA_TTL = 5 * 60;

export function issueAdminMfaToken() {
	return signToken({ role: 'admin-mfa', k: adminTag() }, ADMIN_MFA_TTL);
}

export function checkAdminMfaToken(req) {
	const token = readSessionCookie(req, ADMIN_MFA_COOKIE);
	if (!token) return false;
	const payload = verifyToken(token);
	return !!payload && payload.role === 'admin-mfa' && safeEqual(payload.k, adminTag());
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
	const token = readSessionCookie(req, UPLOAD_COOKIE);
	if (!token) return false;
	const payload = verifyToken(token);
	return !!payload && payload.scope === 'upload' && safeEqual(payload.k, uploadTag());
}

// ---- Upload magic link (M-01 Part B) ---------------------------------------
// A shareable "quick access" link for instant upload login (?token=...). The
// old design (uploadLinkToken/checkUploadLink) was a stateless HMAC-signed
// token with a 90-day expiry, reusable any number of times until it aged out -
// a single leaked link (chat log, proxy log, browser history) stayed valid for
// up to three months. This replaces it with server-side, single-use, 15-minute
// tokens: the raw token is handed back exactly once at mint time and only its
// SHA-256 hash is stored (hashSecretToken - same discipline as a share's
// edit_token), so a leaked link is worthless minutes later, and worthless
// immediately after its one redemption.
const UPLOAD_LINK_TTL = 15 * 60;

const insertUploadLink = db.query('INSERT INTO upload_link_tokens (token_hash, k, expires_at) VALUES (?, ?, ?)');
const deleteExpiredUploadLinks = db.query('DELETE FROM upload_link_tokens WHERE expires_at < ?');
const getUploadLink = db.query('SELECT token_hash, k, expires_at FROM upload_link_tokens WHERE token_hash = ?');
const deleteUploadLink = db.query('DELETE FROM upload_link_tokens WHERE token_hash = ?');

// Mint a fresh single-use link token. Only meaningful when an upload password
// is configured (mirrors the old function's gate, enforced by callers via
// config.uploadPassword). Opportunistically sweeps expired rows first, so the
// table never grows unbounded from abandoned links. Returns the raw token -
// the only time it is ever available in plaintext.
export function mintUploadLink() {
	const token = newToken();
	deleteExpiredUploadLinks.run(now());
	insertUploadLink.run(hashSecretToken(token), uploadTag(), now() + UPLOAD_LINK_TTL);
	return token;
}

// Redeem a magic-link token: valid only once, only within its 15-minute TTL,
// and only while it still carries the CURRENT upload-password fingerprint
// (rotating/clearing UPLOAD_PASSWORD kills every unredeemed link, same
// semantics the old signed token had). Runs as one synchronous transaction so
// two racing requests for the same token can never both succeed - the row is
// deleted up front (first redemption wins) regardless of whether the
// remaining checks then pass, so a token can never be redeemed twice even if
// it turns out to be expired or fingerprint-stale. A second visit with the
// same token falls through to the lock page exactly like an invalid one.
export function redeemUploadLink(token) {
	if (!config.uploadPassword || typeof token !== 'string' || !token) return false;
	const hash = hashSecretToken(token);
	return db.transaction(() => {
		const row = getUploadLink.get(hash);
		if (!row) return false;
		deleteUploadLink.run(hash);
		if (row.expires_at <= now()) return false;
		return safeEqual(row.k, uploadTag());
	})();
}

// ---- Per-share access ------------------------------------------------------
// After a visitor unlocks a password-protected share, we hand them a short-lived
// signed token scoped to that share id. The edit token (returned to the
// uploader at creation) also grants access for management.

export function issueAccessToken(shareId, passwordHash) {
	const k = credentialTag(`access:${shareId}`, passwordHash || '');
	return signToken({ scope: 'access', sid: shareId, k }, config.accessTokenTtl);
}

export function hasAccessToken(token, shareId, passwordHash) {
	const p = verifyToken(token);
	if (!p || p.scope !== 'access' || p.sid !== shareId) return false;
	return safeEqual(p.k, credentialTag(`access:${shareId}`, passwordHash || ''));
}

// The access token may arrive via the Authorization: Bearer header or an
// `access` query param (handy for direct <video>/<img> element src URLs).
export function readAccessToken(req, url) {
	const auth = req.headers.get('authorization');
	if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
	return url?.searchParams?.get('access') || null;
}

// ---- Per-share owner session (M-05) ----------------------------------------
// A cookie alternative to the X-Edit-Token header, obtained by exchanging the
// edit token once (see routes/shares.js's POST /api/shares/:id/owner-session).
// Lets the browser stop keeping the edit token itself in localStorage - the
// cookie is HttpOnly, so it is unreadable to page script (and thus to an XSS
// payload) in a way a localStorage value never can be. The header path is
// completely unaffected: every route below still accepts X-Edit-Token exactly
// as before, byte for byte, for API-key/script callers.
//
// Named PER SHARE (see ownerCookieBase), never a single fixed cookie, so a
// browser that owns several shares carries one cookie per share and each only
// ever matches requests for its own share's API surface.
export const ownerCookieBase = shareId => `${OWNER_COOKIE_BASE}_${shareId}`;

// share.edit_token is already the stored SHA-256 hash (see db.js), never the
// raw token - folding it into the fingerprint means a future edit-token
// rotation would invalidate outstanding owner cookies automatically, the same
// way adminTag()/uploadTag() invalidate on a password change.
const ownerTag = share => credentialTag(`owner:${share.id}`, share.edit_token);

export function issueOwnerToken(share) {
	return signToken({ scope: 'owner', sid: share.id, k: ownerTag(share) }, config.adminSessionTtl);
}

export function hasOwnerCookie(req, share) {
	const token = readSessionCookie(req, ownerCookieBase(share.id));
	if (!token) return false;
	const payload = verifyToken(token);
	return !!payload && payload.scope === 'owner' && payload.sid === share.id && safeEqual(payload.k, ownerTag(share));
}
