// Signing primitives. We sign small JSON payloads (admin sessions, per-share
// access grants, edit tokens) with HMAC-SHA256 so they are tamper-evident
// without a server-side session store. Format: base64url(payload).base64url(sig).

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { config } from '../config.js';

function b64url(buf) {
	return Buffer.from(buf).toString('base64url');
}

function sign(data) {
	return createHmac('sha256', config.secret).update(data).digest('base64url');
}

// Create a signed token from an object. `ttlSeconds` (optional) embeds an
// expiry the verifier enforces.
export function signToken(payload, ttlSeconds) {
	const body = { ...payload };
	if (ttlSeconds) body.exp = Math.floor(Date.now() / 1000) + ttlSeconds;
	const data = b64url(JSON.stringify(body));
	return `${data}.${sign(data)}`;
}

// Verify and decode a token. Returns the payload object, or null if the
// signature is invalid, malformed, or expired.
export function verifyToken(token) {
	if (typeof token !== 'string' || !token.includes('.')) return null;
	const [data, sig] = token.split('.');
	if (!data || !sig) return null;
	const expected = sign(data);
	let ok = false;
	try {
		const a = Buffer.from(sig);
		const b = Buffer.from(expected);
		ok = a.length === b.length && timingSafeEqual(a, b);
	} catch {
		return null;
	}
	if (!ok) return null;
	let payload;
	try {
		payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
	} catch {
		return null;
	}
	if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
	return payload;
}

// Password hashing uses Bun's built-in argon2id (no native dependency).
export async function hashPassword(plain) {
	return Bun.password.hash(plain, { algorithm: 'argon2id' });
}

export async function verifyPassword(plain, hash) {
	if (!hash) return false;
	try {
		return await Bun.password.verify(plain, hash);
	} catch {
		return false;
	}
}

// A short, domain-separated fingerprint of a credential (an admin/upload
// password), keyed by SECRET. Embedded in the session tokens minted after that
// credential is verified, and re-checked on every request: when the credential
// is rotated (or SECRET changes), the fingerprint no longer matches and every
// outstanding session that carried the old value is invalidated. `purpose`
// domain-separates the tags so an admin fingerprint can never equal an upload
// one. Not secret material itself (the whole token is already HMAC-signed) - it
// is a tamper-proof "which password was this issued under" marker.
export function credentialTag(purpose, credential) {
	return createHmac('sha256', config.secret).update(`${purpose}\0${credential ?? ''}`).digest('base64url').slice(0, 22);
}

// Constant-time string compare for shared secrets (admin/upload passwords and
// edit tokens) where we do not store a hash. Both sides are first hashed to a
// fixed 32-byte digest so the comparison never short-circuits on a length
// mismatch (which would otherwise leak the secret's length via timing).
export function safeEqual(a, b) {
	const ab = createHash('sha256').update(String(a)).digest();
	const bb = createHash('sha256').update(String(b)).digest();
	return timingSafeEqual(ab, bb);
}
