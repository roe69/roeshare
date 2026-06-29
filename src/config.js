// Central configuration. Reads from the environment once at boot and exposes a
// frozen config object. Bun auto-loads .env, so no dotenv dependency is needed.

import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { applyManagedSettings } from './lib/settings.js';
import { addSecret } from './lib/logbuffer.js';

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

// Apply the admin-managed settings file (in the data volume) over the
// environment for allowlisted keys BEFORE the rest of config is read - this is
// what makes a panel edit take effect on the next restart (the container keeps
// its compose-injected env and never re-reads the host .env). DATA_DIR itself is
// read above, so the file can never relocate its own source.
applyManagedSettings(dataDir);

// BASE_URL may be a single URL or a comma-separated list of public origins (for
// serving the same instance on multiple domains, e.g. share.example.com and
// files.example.com). The first entry is canonical: it's used for the startup log
// and as the fallback when a request arrives on an unrecognized host. Every
// listed host is allowlisted, so links are built from whichever of YOUR domains
// the visitor is actually on, while a spoofed Host header falls back to canonical.
const baseUrls = str('BASE_URL', `http://localhost:${int('PORT', 3300)}`)
	.split(',')
	.map(s => s.trim().replace(/\/+$/, ''))
	.filter(Boolean);
if (baseUrls.length === 0) baseUrls.push(`http://localhost:${int('PORT', 3300)}`);

const allowedHosts = new Set();
for (const b of baseUrls) {
	try {
		allowedHosts.add(new URL(b).host.toLowerCase());
	} catch {
		console.warn(`  WARNING: BASE_URL entry is not a valid URL, ignoring: ${b}`);
	}
}

// Brand wordmark. APP_NAME is injected verbatim as HTML into the header span so
// the operator can keep the default ember colouring (the <b> is gradient-clipped
// by `.rl-wordmark b` in app.css) or supply their own markup/inline colours,
// e.g. APP_NAME='Acme<span style="color:#3b82f6">Share</span>'. This is
// OPERATOR-TRUSTED config (it comes from the server environment, never from a
// request), so the raw HTML carries no end-user XSS vector - do not wire it to
// any user-supplied source. appTitle is the tag-stripped plain text for <title>.
const appName = str('APP_NAME', 'Roe<b>Share</b>');
const appTitle = appName.replace(/<[^>]*>/g, '').trim() || 'RoeShare';

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
	// Canonical origin (first BASE_URL entry); used for logging and as the
	// fallback for requests arriving on a host not in the allowlist.
	baseUrl: baseUrls[0],
	// All configured public origins, and the set of their hosts. requestOrigin()
	// (lib/http.js) matches the incoming host against allowedHosts to build links
	// for the domain the visitor is actually using.
	baseUrls,
	allowedHosts,

	adminPassword: str('ADMIN_PASSWORD'),
	uploadPassword: str('UPLOAD_PASSWORD'),
	secret,
	ephemeralSecret,

	// Brand name (raw HTML) and its plain-text form; see the comment above.
	appName,
	appTitle,

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

// Defensively scrub these from any log line the buffer captures (they should
// never be logged in the first place).
addSecret(config.secret);
addSecret(config.adminPassword);
addSecret(config.uploadPassword);
