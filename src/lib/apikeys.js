// API-key authentication for programmatic uploads. A key is a single opaque
// bearer token of the form `rsk_<id>_<secret>`:
//   - `id` is public: it is the database primary key (so lookup is O(1)) and the
//     recognizable prefix shown in the admin UI.
//   - `secret` is high-entropy and shown to the operator exactly once at creation.
// Only SHA-256(secret) is stored, so the database row can never recover a usable
// key. The secret has ~230 bits of entropy, so a fast hash (not argon2) is the
// right tradeoff: it is verified on every API request and is not brute-forceable.

import { createHash, timingSafeEqual } from 'node:crypto';
import { db, now } from '../db.js';
import { randomId } from './ids.js';

const KEY_PREFIX = 'rsk';

const insertKey = db.query('INSERT INTO api_keys (id, name, key_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)');
const getKey = db.query('SELECT * FROM api_keys WHERE id = ?');
const touchKey = db.query('UPDATE api_keys SET last_used_at = ? WHERE id = ?');
const bumpKey = db.query('UPDATE api_keys SET upload_count = upload_count + ?, bytes_uploaded = bytes_uploaded + ? WHERE id = ?');
const revokeQ = db.query('UPDATE api_keys SET revoked_at = ? WHERE id = ?');
const deleteQ = db.query('DELETE FROM api_keys WHERE id = ?');
const listQ = db.query(
	`SELECT k.*, (SELECT COUNT(*) FROM shares s WHERE s.api_key_id = k.id AND s.deleted_at IS NULL) AS live_shares
	 FROM api_keys k ORDER BY k.created_at DESC`,
);

function sha256(s) {
	return createHash('sha256').update(String(s)).digest();
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
	};
}

// Create a key. Returns the public id/prefix plus the full token, which the
// caller must surface to the operator ONCE - it is not recoverable afterwards.
export function createApiKey(name, expiresAt = null) {
	const id = randomId(12);
	const secret = randomId(40);
	const token = `${KEY_PREFIX}_${id}_${secret}`;
	insertKey.run(id, name, sha256(secret).toString('hex'), now(), expiresAt);
	return { id, name, token, prefix: `${KEY_PREFIX}_${id}`, expiresAt };
}

// Parse and verify a presented token. Returns the raw key row, or null when the
// token is malformed, unknown, revoked, expired, or the secret does not match.
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

// Authenticate a request in one step. On success the key's last_used_at is
// stamped and the row is returned; otherwise null.
export function authenticate(req) {
	const key = verifyApiKey(readApiKey(req));
	if (key) touchKey.run(now(), key.id);
	return key;
}

// Add to a key's lifetime usage tallies (shares created, bytes stored).
export function recordKeyUsage(id, { shares = 0, bytes = 0 } = {}) {
	if (!id) return;
	if (shares || bytes) bumpKey.run(shares, bytes, id);
}

// ---- Admin management ------------------------------------------------------

export function listApiKeys() {
	return listQ.all().map(mapKey);
}

export function getApiKey(id) {
	const k = getKey.get(id);
	return k ? mapKey(k) : null;
}

// Revoke (disable) a key without deleting it, preserving its usage history.
// Returns false if the key does not exist.
export function revokeApiKey(id) {
	const k = getKey.get(id);
	if (!k) return false;
	if (k.revoked_at == null) revokeQ.run(now(), id);
	return true;
}

// Hard-delete a key row. Shares it created keep their (now dangling) api_key_id.
export function deleteApiKey(id) {
	return deleteQ.run(id).changes > 0;
}
