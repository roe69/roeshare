// Central configuration. Reads from the environment once at boot and exposes a
// frozen config object. Bun auto-loads .env, so no dotenv dependency is needed.

import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';

function int(name, fallback) {
	const raw = process.env[name];
	if (raw === undefined || raw === '') return fallback;
	const n = Number(raw);
	return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function str(name, fallback = '') {
	const raw = process.env[name];
	return raw === undefined || raw === '' ? fallback : raw;
}

function bool(name, fallback = false) {
	const raw = process.env[name];
	if (raw === undefined || raw === '') return fallback;
	return /^(1|true|yes|on)$/i.test(raw.trim());
}

const dataDir = resolve(str('DATA_DIR', './data'));

// A SECRET is mandatory for signing. If none is provided we generate an
// ephemeral one and warn - sessions/tokens will not survive a restart.
let secret = str('SECRET');
let ephemeralSecret = false;
if (!secret) {
	secret = randomBytes(32).toString('hex');
	ephemeralSecret = true;
}

export const config = Object.freeze({
	host: str('HOST', '0.0.0.0'),
	port: int('PORT', 3300),
	baseUrl: str('BASE_URL', `http://localhost:${int('PORT', 3300)}`).replace(/\/+$/, ''),

	adminPassword: str('ADMIN_PASSWORD'),
	uploadPassword: str('UPLOAD_PASSWORD'),
	secret,
	ephemeralSecret,

	// Only honor X-Forwarded-For / X-Real-IP when behind a trusted reverse proxy.
	// When false (the default for a directly-exposed server), rate-limit and audit
	// keys use the real socket peer so a client cannot spoof its identity.
	trustProxy: bool('TRUST_PROXY', false),

	dataDir,
	storageDir: resolve(dataDir, 'storage'),
	dbPath: resolve(dataDir, 'roeshare.db'),

	maxFileSize: int('MAX_FILE_SIZE', 5 * 1024 ** 3),
	maxShareSize: int('MAX_SHARE_SIZE', 10 * 1024 ** 3),
	maxTotalSize: int('MAX_TOTAL_SIZE', 0),
	chunkSize: int('CHUNK_SIZE', 8 * 1024 * 1024),

	// Caps that bound per-share metadata growth and abusive inputs.
	maxFilesPerShare: int('MAX_FILES_PER_SHARE', 10000),
	maxPasswordLength: int('MAX_PASSWORD_LENGTH', 1024),

	defaultExpiry: int('DEFAULT_EXPIRY', 7 * 24 * 3600),
	sweepInterval: int('SWEEP_INTERVAL', 3600),

	// Session lifetime for the admin cookie, in seconds (7 days).
	adminSessionTtl: 7 * 24 * 3600,
	// Lifetime of a per-share access token granted after password unlock (1 hour).
	accessTokenTtl: 3600,
});
