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

function escapeHtml(s) {
	return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Render a brand string with OSRS-style tags to safe HTML. `<col=RRGGBB>` sets the
// colour of the text that follows (until the next `<col>`/`</col>`); `<b>..</b>`
// bolds. Every literal character is escaped and only colour/bold are honoured, so
// this stays XSS-safe even though the result is injected as raw HTML into the page
// template (APP_NAME is operator-trusted env, never request input).
function brandHtml(s) {
	let out = '', color = null, bold = 0;
	const re = /<col=([0-9a-fA-F]{3,8})>|<\/col>|<b>|<\/b>|([^<]+)|(<)/g;
	let m;
	while ((m = re.exec(s)) !== null) {
		if (m[1] !== undefined) color = m[1];
		else if (m[0] === '</col>') color = null;
		else if (m[0] === '<b>') bold++;
		else if (m[0] === '</b>') bold = Math.max(0, bold - 1);
		else {
			let chunk = escapeHtml(m[2] !== undefined ? m[2] : '<');
			if (bold > 0) chunk = `<b>${chunk}</b>`;
			if (color) chunk = `<span style="color:#${color}">${chunk}</span>`;
			out += chunk;
		}
	}
	return out;
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

// Brand wordmark. APP_NAME carries its own colours via OSRS-style tags:
// `<col=RRGGBB>` colours the following text and `<b>..</b>` bolds it, e.g.
// `<col=e4e4ce>Roe<b><col=ff6b35>Share</b>` (cream "Roe" + bold orange "Share").
// brandHtml() renders it to safe HTML (text escaped; only colour/bold honoured)
// for the header/sidebar template, so re-theming the brand needs no CSS change -
// just the env. appTitle is the tag-stripped plain text for <title>.
const appName = str('APP_NAME', '<col=e4e4ce>Roe<b><col=ff6b35>Share</b>');
const appNameHtml = brandHtml(appName);
const appTitle = appName.replace(/<[^>]*>/g, '').trim() || 'RoeShare';

// Optional one-line re-theming with no CSS edit or build step: THEME_PRIMARY and
// THEME_ACCENT (hex colours like #3b82f6) override the two semantic brand tokens
// the whole UI is built from, injected as a <style> into every page's <head> (see
// {{BRAND_STYLE}} in the HTML shells). Only strict hex is accepted so the value
// can never break out of the style block. For deeper control, edit
// public/css/tokens.css directly (the full source of truth for the palette).
const hexColor = v => (/^#[0-9a-fA-F]{3,8}$/.test(v) ? v : '');
const themePrimary = hexColor(str('THEME_PRIMARY'));
const themeAccent = hexColor(str('THEME_ACCENT'));
function buildBrandStyle() {
	const rules = [];
	if (themePrimary) rules.push(`--rl-primary:${themePrimary};--rl-primary-dark:${themePrimary};--rl-primary-light:${themePrimary}`);
	if (themeAccent) rules.push(`--rl-accent:${themeAccent};--rl-accent-dark:${themeAccent}`);
	return rules.length ? `<style>:root{${rules.join(';')}}</style>` : '';
}
const brandStyle = buildBrandStyle();

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

	// Brand name: the raw env string (for the settings editor), the rendered safe
	// HTML (injected into pages), and the plain-text form (for <title>). brandStyle
	// is the optional theme-colour <style> override injected into every page head.
	appName,
	appNameHtml,
	appTitle,
	brandStyle,

	// Only honor X-Forwarded-For / X-Real-IP when behind a trusted reverse proxy.
	// When false (the default for a directly-exposed server), rate-limit and audit
	// keys use the real socket peer so a client cannot spoof its identity.
	trustProxy: bool('TRUST_PROXY', false),

	// Reverse-proxy byte-serving offload. When set, the preview endpoint hands
	// blobs that need no server-side decryption (E2E shares, or any file when
	// ENCRYPT_AT_REST is off) to the proxy to serve via kernel sendfile instead of
	// streaming them through this process - so one core can serve far more
	// concurrent video streams. X_ACCEL_REDIRECT is an nginx internal-location
	// prefix (e.g. /_roeshare_blobs); X_SENDFILE=1 uses the Apache/Lighttpd
	// X-Sendfile header (absolute path). Off by default (bytes stream through the
	// app). See the reverse-proxy setup guide.
	xAccelRedirect: str('X_ACCEL_REDIRECT'),
	xSendfile: bool('X_SENDFILE', false),

	// New shares default to end-to-end encryption (client-side crypto; the server
	// never sees the key or does any crypto for these). Operators can set
	// DEFAULT_E2E=0 to default to server-managed shares.
	defaultE2e: bool('DEFAULT_E2E', true),
	// When true (default), server-managed (non-E2E) blobs are AES-256-CTR
	// encrypted at rest; when false they are stored as plaintext (no server
	// crypto - lighter, but raw-disk/backup access can read them). Existing
	// already-encrypted files keep decrypting correctly regardless of this
	// setting.
	encryptAtRest: bool('ENCRYPT_AT_REST', true),

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
	// Non-finalized (abandoned) uploads are swept after this many seconds.
	abandonedUploadTtl: int('ABANDONED_UPLOAD_TTL', 24 * 3600),

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
