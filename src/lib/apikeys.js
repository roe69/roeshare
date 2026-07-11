// API-key authentication for programmatic uploads. A key is a single opaque
// bearer token of the form `rsk_<id>_<secret>`:
//   - `id` is public: it is the database primary key (so lookup is O(1)) and the
//     recognizable prefix shown in the admin UI.
//   - `secret` is high-entropy and shown to the operator exactly once at creation.
// Only SHA-256(secret) is stored, so the database row can never recover a usable
// key. The secret has ~230 bits of entropy, so a fast hash (not argon2) is the
// right tradeoff: it is verified on every API request and is not brute-forceable.
//
// Each key carries optional per-key limits/scopes (byte caps, a lifetime share
// cap, a max share expiry, and whether it may set custom slugs / passwords),
// enforced at share creation and file registration.

import { createHash, timingSafeEqual } from 'node:crypto';
import { config } from '../config.js';
import { db, now } from '../db.js';
import { randomId } from './ids.js';
import { signToken, verifyToken, credentialTag, safeEqual } from './crypto.js';
import { parseCookies, error } from './http.js';

const KEY_PREFIX = 'rsk';
// Cookie holding a signed API-key web session, set after a name + token login so
// a key holder can browse their own shares in the browser (see routes/api.js).
export const APIKEY_COOKIE = 'roeshare_apikey';

const insertKey = db.query(
	`INSERT INTO api_keys (id, name, key_hash, created_at, expires_at, max_file_size, max_share_size, max_shares, max_expiry, allow_slug, allow_password, scope_create, scope_write, scope_read, scope_delete)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
);
const getKey = db.query('SELECT * FROM api_keys WHERE id = ?');
const touchKey = db.query('UPDATE api_keys SET last_used_at = ? WHERE id = ?');
const bumpKey = db.query('UPDATE api_keys SET upload_count = upload_count + ?, bytes_uploaded = bytes_uploaded + ? WHERE id = ?');
const revokeQ = db.query('UPDATE api_keys SET revoked_at = ? WHERE id = ?');
const rotateQ = db.query('UPDATE api_keys SET key_hash = ? WHERE id = ?');
const deleteQ = db.query('DELETE FROM api_keys WHERE id = ?');
const updateQ = db.query(
	`UPDATE api_keys SET name = ?, max_file_size = ?, max_share_size = ?, max_shares = ?, max_expiry = ?, allow_slug = ?, allow_password = ?, scope_create = ?, scope_write = ?, scope_read = ?, scope_delete = ? WHERE id = ?`,
);
const listQ = db.query(
	`SELECT k.*, (SELECT COUNT(*) FROM shares s WHERE s.api_key_id = k.id AND s.deleted_at IS NULL) AS live_shares
	 FROM api_keys k ORDER BY k.created_at DESC`,
);

function sha256(s) {
	return createHash('sha256').update(String(s)).digest();
}

// The ten limit/scope column values, in the order both insert and update expect.
function limitColumns(limits = {}) {
	return [
		limits.max_file_size ?? null,
		limits.max_share_size ?? null,
		limits.max_shares ?? null,
		limits.max_expiry ?? null,
		limits.allow_slug ?? 1,
		limits.allow_password ?? 1,
		limits.scope_create ?? 1,
		limits.scope_write ?? 1,
		limits.scope_read ?? 1,
		limits.scope_delete ?? 1,
	];
}

// The scopes/limits of a key row, in the camelCase shape the API/UI use.
// Exported so routes/admin.js can diff a PATCH's changed fields for the
// apikey.updated audit event without duplicating this mapping.
export function limitsOf(k) {
	return {
		maxFileSize: k.max_file_size ?? null,
		maxShareSize: k.max_share_size ?? null,
		maxShares: k.max_shares ?? null,
		maxExpiry: k.max_expiry ?? null,
		allowSlug: k.allow_slug !== 0,
		allowPassword: k.allow_password !== 0,
		scopes: {
			create: k.scope_create !== 0,
			write: k.scope_write !== 0,
			read: k.scope_read !== 0,
			delete: k.scope_delete !== 0,
		},
	};
}

// Public, secret-free view of a key row for the admin UI.
function mapKey(k) {
	return {
		id: k.id,
		name: k.name,
		prefix: `${KEY_PREFIX}_${k.id}`,
		createdAt: k.created_at,
		lastUsedAt: k.last_used_at,
		expiresAt: k.expires_at,
		revokedAt: k.revoked_at,
		uploadCount: k.upload_count,
		bytesUploaded: k.bytes_uploaded,
		liveShares: k.live_shares ?? 0,
		limits: limitsOf(k),
	};
}

// Validate + normalize an admin-supplied limits/scopes object into the ten DB
// column values. Byte caps are clamped to the server maxima (a key can only ever
// be MORE restrictive than the instance). Returns { values } or { error }.
export function sanitizeLimits(src = {}) {
	const out = {};

	const byteCap = (val, serverMax, label) => {
		if (val === undefined || val === null || val === '') return null;
		const n = Number(val);
		if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) return { error: `Invalid ${label}` };
		if (n === 0) return null; // 0 = "no override", inherit the server default
		return Math.min(n, serverMax);
	};

	let v = byteCap(src.maxFileSize, config.maxFileSize, 'max file size');
	if (v && v.error) return v;
	out.max_file_size = v;

	v = byteCap(src.maxShareSize, config.maxShareSize, 'max share size');
	if (v && v.error) return v;
	out.max_share_size = v;

	out.max_shares = config.defaultKeyMaxShares;
	if (src.maxShares !== undefined && src.maxShares !== null && src.maxShares !== '') {
		const n = Number(src.maxShares);
		if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) return { error: 'Invalid max shares' };
		out.max_shares = n > 0 ? n : null;
	}

	out.max_expiry = null;
	if (src.maxExpiry !== undefined && src.maxExpiry !== null && src.maxExpiry !== '') {
		const n = Number(src.maxExpiry);
		if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) return { error: 'Invalid max expiry' };
		out.max_expiry = n > 0 ? n : null;
	}

	// Scopes default to allowed when omitted.
	out.allow_slug = src.allowSlug === false || src.allowSlug === 0 || src.allowSlug === '0' ? 0 : 1;
	out.allow_password = src.allowPassword === false || src.allowPassword === 0 || src.allowPassword === '0' ? 0 : 1;

	// Operation-level scopes (F-06). Like allowSlug/allowPassword above, each
	// defaults to allowed (1) when omitted - the admin key-creation UI has no
	// scope picker in every caller yet, so a key minted without an explicit
	// `scopes` object must behave exactly as a full-access key.
	const scopes = src.scopes && typeof src.scopes === 'object' ? src.scopes : {};
	out.scope_create = scopes.create === false || scopes.create === 0 || scopes.create === '0' ? 0 : 1;
	out.scope_write = scopes.write === false || scopes.write === 0 || scopes.write === '0' ? 0 : 1;
	out.scope_read = scopes.read === false || scopes.read === 0 || scopes.read === '0' ? 0 : 1;
	out.scope_delete = scopes.delete === false || scopes.delete === 0 || scopes.delete === '0' ? 0 : 1;

	return { values: out };
}

// Create a key. `limits` is a sanitized column object (see sanitizeLimits). Returns
// the public id/prefix plus the full token, which the caller must surface to the
// operator ONCE - it is not recoverable afterwards.
export function createApiKey(name, expiresAt = null, limits = {}) {
	const id = randomId(12);
	const secret = randomId(40);
	const token = `${KEY_PREFIX}_${id}_${secret}`;
	insertKey.run(id, name, sha256(secret).toString('hex'), now(), expiresAt, ...limitColumns(limits));
	return { id, name, token, prefix: `${KEY_PREFIX}_${id}`, expiresAt };
}

// Parse and verify a presented token. Returns the raw key row (including limit
// columns), or null when the token is malformed, unknown, revoked, expired, or
// the secret does not match.
export function verifyApiKey(token) {
	if (typeof token !== 'string') return null;
	const parts = token.split('_');
	// rsk_<id>_<secret>: the id/secret alphabets never contain '_', so exactly
	// three parts is the only valid shape.
	if (parts.length !== 3 || parts[0] !== KEY_PREFIX) return null;
	const [, id, secret] = parts;
	if (!id || !secret) return null;
	const row = getKey.get(id);
	if (!row) return null;
	if (row.revoked_at != null) return null;
	if (row.expires_at != null && row.expires_at < now()) return null;
	const a = sha256(secret);
	const b = Buffer.from(row.key_hash, 'hex');
	if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
	return row;
}

// Pull the bearer token from `Authorization: Bearer ...` or the `X-Api-Key`
// header (either is accepted, Authorization wins).
export function readApiKey(req) {
	const auth = req.headers.get('authorization');
	if (auth && auth.slice(0, 7).toLowerCase() === 'bearer ') return auth.slice(7).trim();
	const x = req.headers.get('x-api-key');
	return x ? x.trim() : null;
}

// Fingerprint of a key's current secret (via its stored hash), keyed by SECRET.
// Baked into the portal session token so rotating the key's secret invalidates
// every outstanding browser session for it - the same credential-binding the
// admin/upload cookies use for password rotation.
const keyTag = keyHash => credentialTag('apikey', keyHash);

// A signed cookie for the browser portal. It names the key id and a fingerprint
// of its current secret; the row is re-fetched and re-checked (revoke / expiry /
// fingerprint) on every use, so revoking OR rotating a key kills its browser
// sessions immediately.
export function issueApiKeySession(key) {
	return signToken({ scope: 'apikey', kid: key.id, k: keyTag(key.key_hash) }, config.adminSessionTtl);
}

export function readApiKeySession(req) {
	const token = parseCookies(req)[APIKEY_COOKIE];
	if (!token) return null;
	const p = verifyToken(token);
	if (!p || p.scope !== 'apikey' || !p.kid) return null;
	const row = getKey.get(p.kid);
	if (!row || row.revoked_at != null) return null;
	if (row.expires_at != null && row.expires_at < now()) return null;
	if (!safeEqual(p.k, keyTag(row.key_hash))) return null; // secret rotated -> session invalidated
	return row;
}

// Authenticate a request in one step - by bearer/X-Api-Key token, or by the
// portal session cookie. On success the key's last_used_at is stamped and the row
// is returned; otherwise null.
export function authenticate(req) {
	const key = verifyApiKey(readApiKey(req)) || readApiKeySession(req);
	if (key) touchKey.run(now(), key.id);
	return key;
}

// Like authenticate(), but also reports HOW the caller authenticated, so
// call sites can require same-origin proof (F-10 CSRF defense) only for the
// ambient-cookie path - a bearer/X-Api-Key request carries no cookie an
// attacker's cross-site page could ride, so it is never asked for it.
// Returns { key, viaCookie } or null.
export function authenticateSource(req) {
	const bearer = verifyApiKey(readApiKey(req));
	const key = bearer || readApiKeySession(req);
	if (key) touchKey.run(now(), key.id);
	return key ? { key, viaCookie: !bearer } : null;
}

// Add to a key's lifetime usage tallies (shares created, bytes stored).
export function recordKeyUsage(id, { shares = 0, bytes = 0 } = {}) {
	if (!id) return;
	if (shares || bytes) bumpKey.run(shares, bytes, id);
}

// ---- Enforcement helpers (used by routes/api.js and routes/uploads.js) -----

// The raw key row by id (with limit columns), or null. Used by the resumable
// upload path to enforce a key's caps on file registration.
export function apiKeyRow(id) {
	return id ? getKey.get(id) : null;
}

// Effective per-file and per-share byte caps for a key row: the key's override
// when set, else the server default; never above the server default.
export function effectiveCaps(row) {
	const ff = row?.max_file_size;
	const fs = row?.max_share_size;
	return {
		maxFileSize: ff ? Math.min(ff, config.maxFileSize) : config.maxFileSize,
		maxShareSize: fs ? Math.min(fs, config.maxShareSize) : config.maxShareSize,
	};
}

// Clamp a requested expiry (epoch seconds, or null=never) to the key's max
// lifetime. A key with a max_expiry forces even "never" shares to expire.
export function clampExpiry(row, expiresAt) {
	const cap = row?.max_expiry;
	if (!cap) return expiresAt;
	const limit = now() + cap;
	if (expiresAt == null) return limit;
	return Math.min(expiresAt, limit);
}

// Whether the API key backing `share` (if any) is still usable. A share with
// no api_key_id was made via the web portal and is unaffected. Used by every
// owner-gated action (uploads.js write routes, shares.js isOwner/finalize/
// delete, download.js accessCheck) so that revoking or expiring a key cuts
// off the shares it created too - otherwise an edit token handed back at
// share-creation time would keep granting full owner access forever, even
// after the key that created it is revoked.
export function keyValidForShare(share) {
	if (!share.api_key_id) return true;
	const row = apiKeyRow(share.api_key_id);
	return !!row && row.revoked_at == null && (row.expires_at == null || row.expires_at >= now());
}

// ---- Operation-level scopes (F-06) -----------------------------------------
// Vocabulary: shares:create, shares:write, shares:read, shares:delete. Every
// /api/v1 route (and the edit-token routes a scoped key's shares flow
// through) requires one or more of these. See routes/api.js, routes/uploads.js,
// routes/shares.js, routes/download.js for the call sites.

// Whether a key row holds the given scope ('create' | 'write' | 'read' | 'delete').
export function hasScope(row, scope) {
	return row[`scope_${scope}`] !== 0;
}

// A ready-to-return 403 Response when `row` lacks `scope`, else null.
export function requireScope(row, scope) {
	return hasScope(row, scope) ? null : error(403, `This key does not have the shares:${scope} scope`);
}

// Enforce a scope on the API KEY THAT CREATED `share`, for the edit-token
// (resumable upload / finalize / delete) routes - so a share created by a
// scope-restricted key keeps enforcing that key's scopes on every subsequent
// edit-token call, not just on the key's own bearer-token requests. A share
// made via the web portal (no api_key_id) is unscoped. Mirrors
// keyValidForShare's revoked/expired handling.
export function scopeErrorForShare(share, scope) {
	if (!share.api_key_id) return null;
	const row = apiKeyRow(share.api_key_id);
	if (!row || row.revoked_at != null || (row.expires_at != null && row.expires_at < now())) return error(403, 'API key is no longer valid');
	return requireScope(row, scope);
}

// ---- Admin management ------------------------------------------------------

export function listApiKeys() {
	return listQ.all().map(mapKey);
}

export function getApiKey(id) {
	const k = getKey.get(id);
	return k ? mapKey(k) : null;
}

// Update a key's name and limits/scopes (the full set is always written).
// Returns false if the key does not exist.
export function updateApiKey(id, name, limits) {
	const k = getKey.get(id);
	if (!k) return false;
	updateQ.run(name, ...limitColumns(limits), id);
	return true;
}

// Revoke (disable) a key without deleting it, preserving its usage history.
// Returns false if the key does not exist.
export function revokeApiKey(id) {
	const k = getKey.get(id);
	if (!k) return false;
	if (k.revoked_at == null) revokeQ.run(now(), id);
	return true;
}

// Reinstate a revoked key (clear revoked_at). Returns false if it does not exist.
export function reinstateApiKey(id) {
	const k = getKey.get(id);
	if (!k) return false;
	if (k.revoked_at != null) revokeQ.run(null, id);
	return true;
}

// Rotate a key's secret in place: same id, name, limits, scopes, and usage
// history, but a brand-new secret. The old token stops verifying immediately (its
// hash no longer matches) and every browser portal session bound to the old
// secret is invalidated. Returns the new full token (surfaced to the operator
// exactly once, like creation), or null if the key does not exist.
export function rotateApiKey(id) {
	const k = getKey.get(id);
	if (!k) return null;
	const secret = randomId(40);
	rotateQ.run(sha256(secret).toString('hex'), id);
	return { id, name: k.name, token: `${KEY_PREFIX}_${id}_${secret}`, prefix: `${KEY_PREFIX}_${id}` };
}

// Hard-delete a key row. Shares it created keep their (now dangling) api_key_id.
export function deleteApiKey(id) {
	return deleteQ.run(id).changes > 0;
}
