// Admin TOTP MFA (F-13): a single-operator second factor layered on top of the
// shared admin password. Everything here is pure DB/crypto - no HTTP, no
// cookies, no session concept - so it stays a leaf module (imports only
// db.js, config.js, crypto.js, totp.js) that auth.js can safely import
// without a cycle: auth.js -> mfa.js is fine, mfa.js must NEVER import
// auth.js.
//
// Storage model: admin_mfa is a single CHECK(id=1) row (mirrors
// storage_ledger). `secret` is set only once enrollment is confirmed - its
// presence (non-null) IS the "MFA enabled" flag, so a half-finished
// enrollment (pending_secret set, never confirmed) has zero effect on login.
// admin_backup_codes holds only hashes (hashSecretToken, like edit tokens and
// API-key secrets) - the plaintext codes exist only in the return value of
// confirmEnrollment()/regenerateBackupCodes(), shown to the operator once.

import { config } from '../config.js';
import { db, now } from '../db.js';
import { hashSecretToken, verifySecretToken } from './crypto.js';
import { generateSecret, base32Encode, verifyTotp } from './totp.js';
import { randomBytes } from 'node:crypto';

const getRow = db.query('SELECT * FROM admin_mfa WHERE id = 1');
const upsertPending = db.query(`
	INSERT INTO admin_mfa (id, pending_secret, pending_created_at)
	VALUES (1, ?, ?)
	ON CONFLICT(id) DO UPDATE SET pending_secret = excluded.pending_secret, pending_created_at = excluded.pending_created_at
`);
const confirmQ = db.query(`
	UPDATE admin_mfa
	SET secret = pending_secret, enabled_at = ?, last_used_step = ?, pending_secret = NULL, pending_created_at = NULL
	WHERE id = 1
`);
const updateStepQ = db.query('UPDATE admin_mfa SET last_used_step = ? WHERE id = 1');
const deleteMfaRowQ = db.query('DELETE FROM admin_mfa WHERE id = 1');
const deleteBackupCodesQ = db.query('DELETE FROM admin_backup_codes');
const insertBackupCodeQ = db.query('INSERT INTO admin_backup_codes (code_hash, created_at) VALUES (?, ?)');
const liveBackupCodesQ = db.query('SELECT * FROM admin_backup_codes WHERE used_at IS NULL');
const burnBackupCodeQ = db.query('UPDATE admin_backup_codes SET used_at = ? WHERE id = ?');
const remainingBackupCodesQ = db.query('SELECT COUNT(*) AS n FROM admin_backup_codes WHERE used_at IS NULL');

// ---- Status ------------------------------------------------------------------

export function mfaEnabled() {
	const row = getRow.get();
	return !!(row && row.secret);
}

// Feeds auth.js's adminTag() so toggling MFA invalidates every outstanding
// admin session cookie. null when disabled (also null for a merely-pending,
// unconfirmed enrollment).
export function mfaEnabledAt() {
	const row = getRow.get();
	return row && row.secret ? (row.enabled_at ?? null) : null;
}

export function pendingEnrollment() {
	const row = getRow.get();
	return !!(row && row.pending_secret);
}

export function backupCodesRemaining() {
	return remainingBackupCodesQ.get().n;
}

// ---- Enrollment ----------------------------------------------------------

// Begin (or restart) enrollment: overwrites any prior pending secret without
// touching a currently-CONFIRMED secret (so starting a re-enrollment never
// disturbs an already-working MFA setup until confirmEnrollment() completes
// it). Returns the secret (for manual entry) and a ready-to-render otpauth://
// URI (the browser turns this into a QR code client-side via qrcode.js -
// nothing server-side ever renders an image).
export function beginEnrollment() {
	const secret = generateSecret();
	upsertPending.run(secret, now());
	const label = encodeURIComponent(config.appName);
	const otpauth = `otpauth://totp/${label}:admin?secret=${secret}&issuer=${label}&algorithm=SHA1&digits=6&period=30`;
	return { secret, otpauth };
}

function generateBackupCode() {
	// 7 random bytes -> 12 base32 chars; the first 10 (50 bits of entropy) are
	// used, formatted as XXXXX-XXXXX for readability.
	const raw = base32Encode(randomBytes(7)).slice(0, 10);
	return { raw, formatted: `${raw.slice(0, 5)}-${raw.slice(5)}` };
}

function issueBackupCodes() {
	deleteBackupCodesQ.run();
	const codes = [];
	const t = now();
	for (let i = 0; i < 10; i++) {
		const { raw, formatted } = generateBackupCode();
		insertBackupCodeQ.run(hashSecretToken(raw), t);
		codes.push(formatted);
	}
	return codes;
}

// Confirm a pending enrollment with a code generated against pending_secret.
// On success: pending_secret becomes the live secret, a fresh set of 10
// backup codes is minted (replacing any prior set), and the plaintext codes
// are returned - the ONLY moment they exist in plaintext. Returns null if
// there is no pending enrollment or the code does not verify (lastUsedStep is
// always 0 here: a brand-new secret has never accepted a step yet).
export function confirmEnrollment(code) {
	const row = getRow.get();
	if (!row || !row.pending_secret) return null;
	const step = verifyTotp(code, row.pending_secret, 0);
	if (step == null) return null;
	confirmQ.run(now(), step);
	return issueBackupCodes();
}

// Disable MFA entirely: drops the admin_mfa row (both confirmed and any
// pending secret) and every backup code. Invalidates outstanding admin
// sessions via auth.js's mfaEnabledAt()-derived fingerprint the moment this
// runs (enabled_at goes from a number back to null).
export function disableMfa() {
	deleteMfaRowQ.run();
	deleteBackupCodesQ.run();
}

export function regenerateBackupCodes() {
	return issueBackupCodes();
}

// ---- Verification (login / step-up actions) --------------------------------

// Verify a 6-digit code against the CONFIRMED secret, using (and persisting)
// the row's last_used_step as the replay guard - so the guard survives across
// requests/processes, not just within one. Returns true/false.
export function verifyLoginCode(code) {
	const row = getRow.get();
	if (!row || !row.secret) return false;
	const step = verifyTotp(code, row.secret, row.last_used_step ?? 0);
	if (step == null) return false;
	updateStepQ.run(step);
	return true;
}

// Consume a backup code exactly once. Normalizes by stripping the formatting
// dash and uppercasing, then compares against every still-live code's hash
// via the constant-time verifySecretToken pattern (never an SQL equality
// lookup, which would leak the hash's existence/shape through a fast/slow
// query plan rather than through timing on the comparison itself). On match,
// burns the code (used_at) so it can never be reused.
export function consumeBackupCode(code) {
	const normalized = String(code ?? '').replace(/-/g, '').toUpperCase();
	if (!normalized) return false;
	for (const row of liveBackupCodesQ.all()) {
		if (verifySecretToken(normalized, row.code_hash)) {
			burnBackupCodeQ.run(now(), row.id);
			return true;
		}
	}
	return false;
}

// Accept either a 6-digit TOTP code or a backup code - used by step-up flows
// (e.g. disabling MFA) where either factor should satisfy the check.
export function verifyMfaCode(code) {
	if (/^\d{6}$/.test(String(code ?? ''))) return verifyLoginCode(code);
	return consumeBackupCode(code);
}
