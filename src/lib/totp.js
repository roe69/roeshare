// RFC 6238 TOTP (Time-based One-Time Password), zero dependencies. Parameters
// are fixed at SHA-1 / 6 digits / 30s - the Google Authenticator-compatible
// default that every mainstream authenticator app supports. We deliberately do
// NOT offer SHA-256/SHA-512 or a different digit count: many authenticator
// apps ignore the otpauth `algorithm`/`digits` params entirely and always do
// SHA-1/6-digit, so offering anything else would silently produce codes the
// app never generates.
//
// hotp() implements RFC 4226 (HOTP: the counter-based primitive TOTP layers a
// time-derived counter on top of). verifyTotp() is the only export routes/
// mfa.js should call for checking a user-submitted code - it handles the
// +-1 step clock-drift window and the replay guard (never accepts a step at
// or before one already consumed).

import { createHmac, randomBytes } from 'node:crypto';
import { safeEqual } from './crypto.js';

const STEP_SECONDS = 30;
const DIGITS = 6;

// ---- Base32 (RFC 4648, A-Z2-7 alphabet, no padding) ------------------------

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
	let bits = '';
	for (const byte of buf) bits += byte.toString(2).padStart(8, '0');
	let out = '';
	for (let i = 0; i < bits.length; i += 5) {
		const chunk = bits.slice(i, i + 5).padEnd(5, '0');
		out += ALPHABET[parseInt(chunk, 2)];
	}
	return out;
}

export function base32Decode(str) {
	const clean = String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
	let bits = '';
	for (const c of clean) {
		const idx = ALPHABET.indexOf(c);
		if (idx === -1) continue;
		bits += idx.toString(2).padStart(5, '0');
	}
	const bytes = [];
	for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
	return Buffer.from(bytes);
}

// A fresh 160-bit (20-byte) secret, base32-encoded - the size every
// authenticator app expects for a SHA-1 TOTP secret.
export function generateSecret() {
	return base32Encode(randomBytes(20));
}

// ---- RFC 4226 HOTP -----------------------------------------------------------

// `secretBytes` is the raw (decoded) secret. `counter` is a non-negative
// integer (the time-step number for TOTP). Returns the 6-digit code as a
// zero-padded string.
export function hotp(secretBytes, counter) {
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(BigInt(counter));
	const digest = createHmac('sha1', secretBytes).update(buf).digest();
	// Dynamic truncation (RFC 4226 5.3).
	const offset = digest[19] & 0xf;
	const code =
		((digest[offset] & 0x7f) << 24) |
		((digest[offset + 1] & 0xff) << 16) |
		((digest[offset + 2] & 0xff) << 8) |
		(digest[offset + 3] & 0xff);
	return String(code % 10 ** DIGITS).padStart(DIGITS, '0');
}

// Verify a user-submitted 6-digit code against a base32 TOTP secret, allowing
// +-1 step (90s total) of clock drift. `lastUsedStep` is the highest step
// number already accepted (0 if none yet) - any step at or before it is
// skipped even if it would otherwise compute a matching code, which is what
// stops the exact same code (or a code from an already-consumed step) being
// replayed. Returns the accepted step number on success (the caller should
// persist it as the new lastUsedStep), or null on failure.
export function verifyTotp(code, secretB32, lastUsedStep = 0) {
	if (!/^\d{6}$/.test(String(code ?? ''))) return null;
	const secretBytes = base32Decode(secretB32);
	if (!secretBytes.length) return null;
	const nowStep = Math.floor(Date.now() / 1000 / STEP_SECONDS);
	for (const drift of [-1, 0, 1]) {
		const step = nowStep + drift;
		if (step <= lastUsedStep) continue;
		const expected = hotp(secretBytes, step);
		if (safeEqual(code, expected)) return step;
	}
	return null;
}
