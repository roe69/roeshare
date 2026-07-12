// Central configuration. Reads from the environment once at boot and exposes a
// frozen config object. Bun auto-loads .env, so no dotenv dependency is needed.

import { randomBytes } from 'node:crypto';
import { resolve, join } from 'node:path';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { applyManagedSettings } from './lib/settings.js';
import { addSecret } from './lib/logbuffer.js';
import { parseCidrList } from './lib/net.js';

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

// A SECRET is mandatory for signing. If none is provided we generate one and
// persist it to the data volume (.secret) so it survives restarts - sessions
// and at-rest AES-256-CTR ciphertext would otherwise break on every reboot.
let secret = str('SECRET');
let ephemeralSecret = false;
if (!secret) {
	ephemeralSecret = true;
	const secretPath = join(dataDir, '.secret');
	try {
		const existing = readFileSync(secretPath, 'utf8').trim();
		if (existing) secret = existing;
	} catch {}
	if (!secret) {
		secret = randomBytes(32).toString('hex');
		mkdirSync(dataDir, { recursive: true });
		writeFileSync(secretPath, secret, { mode: 0o600 });
	}
}

// Refuse to boot with a well-known placeholder admin password - a real value
// must be set via env or the data-volume admin-managed settings before the
// panel is reachable. Checked after applyManagedSettings() so a placeholder
// set through the admin panel is caught too.
const adminPassword = str('ADMIN_PASSWORD');
const PLACEHOLDER_PASSWORDS = new Set(['change-me', 'changeme', 'change_me', 'admin', 'password', 'admin123', 'root', 'default', '123456']);
if (adminPassword && PLACEHOLDER_PASSWORDS.has(adminPassword.trim().toLowerCase())) {
	throw new Error('ADMIN_PASSWORD is set to a well-known placeholder value, set a real one via env or the data volume settings before starting RoeShare.');
}

// Only honor X-Forwarded-For / X-Real-IP / X-Forwarded-Proto / X-Forwarded-Host
// when the DIRECT socket peer is inside this allowlist - otherwise those
// headers are fully attacker-controlled on a directly-exposed server and are
// ignored outright. TRUSTED_PROXY_CIDRS is the explicit policy (comma-separated
// CIDRs, e.g. "127.0.0.1/32,::1/128,10.20.0.0/24"). TRUST_PROXY=1 is kept as a
// back-compat alias for existing single-reverse-proxy-on-localhost deployments
// (the documented Caddy/nginx examples proxy from 127.0.0.1): if it's set and
// TRUSTED_PROXY_CIDRS is not, it trusts loopback only, with a one-time warning
// to set TRUSTED_PROXY_CIDRS explicitly.
const trustProxyLegacy = (() => {
	const v = bool('TRUST_PROXY', false);
	if (v) console.log('  NOTE: TRUST_PROXY=1 - only set this when the app is unreachable except via a trusted reverse proxy.');
	return v;
})();
const trustedProxyCidrsRaw = str('TRUSTED_PROXY_CIDRS');
const trustedProxyCidrs = trustedProxyCidrsRaw
	? parseCidrList(trustedProxyCidrsRaw, entry => console.warn(`  WARNING: ignoring invalid TRUSTED_PROXY_CIDRS entry: ${entry}`))
	: trustProxyLegacy
		? (() => {
				console.warn('  WARNING: TRUST_PROXY=1 without TRUSTED_PROXY_CIDRS - defaulting to trusting only the loopback interface (127.0.0.1/32, ::1/128). Set TRUSTED_PROXY_CIDRS explicitly to the real proxy address(es) instead.');
				return parseCidrList('127.0.0.1/32,::1/128');
			})()
		: [];
// Number of trusted-proxy hops to skip from the RIGHT of X-Forwarded-For
// before taking the client address (the standard "walk from the right"
// algorithm - each additional relay hop appends its own entry, so the real
// client is exactly this many entries in from the end). Defaults to 1, the
// shape of a single local reverse proxy (nginx/Caddy on the same host) that
// appends its own peer address to whatever it received. Set to 0 when the
// ONE trusted proxy is the thing that directly terminates the client
// connection and sets (not appends to) X-Forwarded-For itself - e.g. a CDN
// like Cloudflare connecting straight to this origin with no local reverse
// proxy in between: its single XFF entry already IS the real client, so nothing
// should be skipped. Clamped to at least 0 (never negative).
const trustedProxyHops = Math.max(0, int('TRUSTED_PROXY_HOPS', 1));

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

	adminPassword,
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

	// Back-compat flag, still surfaced in the admin panel's effective-settings
	// display (see routes/admin.js). The actual trust decision is
	// trustedProxyCidrs below - a socket peer outside that allowlist never gets
	// its forwarding headers honored regardless of this flag.
	trustProxy: trustProxyLegacy,
	// Parsed CIDR allowlist (see lib/net.js) of proxies allowed to set
	// X-Forwarded-For / X-Real-IP / X-Forwarded-Proto / X-Forwarded-Host.
	// Empty = trust nothing, always use the real socket peer/scheme/host.
	trustedProxyCidrs,
	trustedProxyHops,

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

	// M-04: per-actor byte-rate budgets (bytes/second) on top of the request-
	// count and concurrency-slot controls above - see lib/semaphore.js's
	// takeBytes(). Bucket capacity (the allowed burst) is a short multiple of
	// the rate, not a separate knob, so a normal chunk/range request landing
	// in the same second as the previous one is never throttled purely for
	// that. 0 disables the byte-rate check entirely for that direction
	// (request-count/concurrency limits still apply).
	uploadBytesPerSec: int('UPLOAD_BYTES_PER_SEC', 50 * 1024 * 1024),
	downloadBytesPerSec: int('DOWNLOAD_BYTES_PER_SEC', 50 * 1024 * 1024),

	// Caps that bound per-share metadata growth and abusive inputs.
	maxFilesPerShare: int('MAX_FILES_PER_SHARE', 10000),
	maxPasswordLength: int('MAX_PASSWORD_LENGTH', 1024),

	// Default lifetime share cap applied to a new API key when it isn't given
	// an explicit max_shares.
	defaultKeyMaxShares: int('DEFAULT_KEY_MAX_SHARES', 1000),

	defaultExpiry: int('DEFAULT_EXPIRY', 7 * 24 * 3600),
	sweepInterval: int('SWEEP_INTERVAL', 3600),
	// Non-finalized (abandoned) uploads are swept after this many seconds.
	abandonedUploadTtl: int('ABANDONED_UPLOAD_TTL', 24 * 3600),

	// Security-audit finding (2026-07): how long a one-time/maxDownloads-capped
	// share's "full" delivery stays in a redeliverable PENDING state after its
	// stream first appears to drain server-side, before the destructive step
	// (burning a one-time share's blobs, or treating a maxDownloads slot as
	// permanently spent) is actually committed - see download.js's
	// pendingDelivery/armDeliveryGrace. A reverse proxy/CDN in front of this
	// process can itself fully absorb a streamed response even when the real
	// client's connection was dropped after only a few bytes, so a single
	// "stream drained" observation is not reliable enough on its own to justify
	// an irreversible action. downloadGraceMaxMs bounds the TOTAL time from the
	// FIRST apparent completion, regardless of how many retries extend the
	// window.
	downloadGraceMs: int('DOWNLOAD_GRACE_MS', 20_000),
	downloadGraceMaxMs: int('DOWNLOAD_GRACE_MAX_MS', 3 * 60_000),
	// Security-audit follow-up (2026-07, "grace window itself defeats
	// maxDownloads"): the number of extra redelivery retries a SINGLE
	// completed claim (see download.js's pendingDelivery/tryClaimRetry) may be
	// granted during its grace window, on top of its own original delivery.
	// Bounds the mechanism above by COUNT, not just by time - the grace
	// window's time bound alone still allows an unbounded number of full
	// redeliveries for as long as each one keeps re-arming it before the
	// window expires; this caps that at a small, fixed number (default 1: one
	// legitimate completion's worth of retries) regardless of how many
	// requests arrive or how long the window stays open.
	downloadGraceMaxRetries: Math.max(0, int('DOWNLOAD_GRACE_MAX_RETRIES', 1)),

	// Security-audit finding (2026-07): floor bytes/sec a chunk-upload PATCH's
	// body read must sustain before its admission-control slot (see
	// routes/uploads.js's acquireAll()) is forcibly released - bounds the
	// WALL-CLOCK hold time independent of Bun's idleTimeout below, which only
	// fires on total silence and does not bound a slow-but-continuously-
	// trickling body. Generous enough to never trip for a real connection, even
	// a badly throttled mobile one. chunkReadTimeoutMaxMs is a sanity ceiling on
	// top of the floor-rate-derived timeout, protecting against an absurdly long
	// wait if an operator configures a very large CHUNK_SIZE.
	chunkReadMinBytesPerSec: int('CHUNK_READ_MIN_BYTES_PER_SEC', 16 * 1024),
	chunkReadTimeoutMinMs: int('CHUNK_READ_TIMEOUT_MIN_MS', 15_000),
	chunkReadTimeoutMaxMs: int('CHUNK_READ_TIMEOUT_MAX_MS', 20 * 60_000),

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
