// HTTP helpers shared by every route: JSON responses, cookies, Range parsing,
// client IP extraction, and security headers.

import { config } from '../config.js';
import { parseIp, ipInCidrs } from './net.js';
import { audit } from './audit.js';

const SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'X-Frame-Options': 'SAMEORIGIN',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
	// Isolates our browsing context from any cross-origin opener/openee (blocks
	// Spectre-style cross-window snooping). Safe everywhere: nothing in this app
	// relies on a window.opener relationship - every target=_blank link already
	// carries rel="noopener", and the only postMessage traffic is the page
	// talking to its own same-origin Service Worker (see public/js/view.js /
	// public/sw.js), never a cross-origin window.
	'Cross-Origin-Opener-Policy': 'same-origin',
	// Blocks cross-origin no-cors subresource loads (<img>/<video>/<script>/...)
	// of OUR pages/API/admin responses - the app's own origin never needs to be
	// embedded elsewhere. NOT applied to shared file bytes: src/routes/download.js
	// overrides this back to 'cross-origin' on preview/download/zip responses,
	// since those are meant to be hotlinked/embedded from other origins (an
	// <img>/<video> pointed at a public share link) and access to them is
	// already gated by the share id/token/password, not by an ambient cookie -
	// so CORP's cross-site-probing protection buys nothing there while breaking
	// a real feature.
	'Cross-Origin-Resource-Policy': 'same-origin',
	// HSTS: only sent when the deployment's canonical public origin (BASE_URL) is
	// https, so a plain-http local/dev instance is never told to force https on
	// itself. Decided once at boot from config rather than per-request via
	// requestScheme(): a CDN-fronted deployment (e.g. Cloudflare) commonly
	// terminates TLS upstream and hands this process a plain http connection, so
	// requestScheme() would see 'http' on every request and this header would
	// never go out at all - even though the site is TLS-only to every visitor.
	// BASE_URL is the operator-declared public origin, so it reflects that truth
	// regardless of which proxy/CDN sits in front.
	...(config.baseUrl.startsWith('https://') ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
};

// Same headers, but with CORP relaxed to 'cross-origin' for responses that
// stream actual shared file bytes (preview/download/zip in
// src/routes/download.js). Those are meant to be loaded cross-origin - an
// <img>/<video>/<audio> tag on another site pointed at a share link, or a
// direct cross-origin fetch of a public download - so CORP:same-origin here
// would silently break hotlinking/embedding of shared content without adding
// real protection (these routes are already gated by share id/token/password,
// not by an ambient cookie CORP exists to protect).
export const FILE_SECURITY_HEADERS = { ...SECURITY_HEADERS, 'Cross-Origin-Resource-Policy': 'cross-origin' };

export function json(data, init = {}) {
	const status = typeof init === 'number' ? init : (init.status ?? 200);
	const headers = { 'Content-Type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...(init.headers || {}) };
	return new Response(JSON.stringify(data), { status, headers });
}

export function error(status, message, extra = {}) {
	return json({ error: message, ...extra }, status);
}

export function text(body, status = 200, headers = {}) {
	return new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS, ...headers } });
}

// Route-class JSON body ceilings (L-03). The server's global maxRequestBodySize
// (server.js) is sized for upload chunks (>=64 MiB) and applies to every
// request - a login/metadata endpoint would otherwise buffer/parse a body far
// larger than it ever needs before any semantic validation runs. These are
// deliberately small relative to that ceiling.
export const LOGIN_BODY_MAX = 16 * 1024; // login/MFA/password endpoints
export const METADATA_BODY_MAX = 64 * 1024; // share/admin metadata endpoints

// Parse a JSON request body capped at `maxBytes`. Rejects an oversized body
// BEFORE buffering it, from a declared Content-Length (mirrors the
// Content-Length precheck idiom used by the PATCH chunk-upload route in
// routes/uploads.js) - and caps the actual bytes read too, since
// Content-Length can be absent or dishonest (e.g. chunked transfer encoding).
// Returns { value } with the parsed body (null for an empty body) on success,
// or { response } with a ready-to-return 413/400 Response on failure. Never
// throws, so every call site can do:
//   const { value, response } = await readJson(req, MAX);
//   if (response) return response;
export async function readJson(req, maxBytes) {
	const declaredLen = Number(req.headers.get('content-length'));
	if (Number.isFinite(declaredLen) && declaredLen > maxBytes) return { response: error(413, 'Request body too large') };
	let buf;
	try {
		buf = await req.arrayBuffer();
	} catch {
		return { response: error(400, 'Invalid request body') };
	}
	if (buf.byteLength > maxBytes) return { response: error(413, 'Request body too large') };
	if (buf.byteLength === 0) return { value: null };
	try {
		return { value: JSON.parse(Buffer.from(buf).toString('utf8')) };
	} catch {
		return { response: error(400, 'Invalid JSON body') };
	}
}

export function noContent(headers = {}) {
	return new Response(null, { status: 204, headers: { ...SECURITY_HEADERS, ...headers } });
}

// Parse the Cookie header into a plain object.
export function parseCookies(req) {
	const header = req.headers.get('cookie');
	const out = {};
	if (!header) return out;
	for (const part of header.split(';')) {
		const idx = part.indexOf('=');
		if (idx === -1) continue;
		const k = part.slice(0, idx).trim();
		const v = part.slice(idx + 1).trim();
		if (!k) continue;
		// A malformed percent-encoding (e.g. a lone "%ZZ") makes decodeURIComponent
		// throw; treat that single cookie as absent rather than letting it crash
		// the whole request up to a generic 500.
		try {
			out[k] = decodeURIComponent(v);
		} catch {
			continue;
		}
	}
	return out;
}

export function cookie(name, value, { maxAge, httpOnly = true, sameSite = 'Lax', path = '/', secure } = {}) {
	const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`];
	if (httpOnly) parts.push('HttpOnly');
	if (secure) parts.push('Secure');
	if (maxAge !== undefined) parts.push(`Max-Age=${maxAge}`);
	return parts.join('; ');
}

export const clearCookie = (name, secure = false) => cookie(name, '', { maxAge: 0, secure });

// L-08: every ambient session cookie in the app (admin, admin-mfa, upload,
// apikey, and the per-share owner cookie - see lib/auth.js/lib/apikeys.js) is
// named through this pair, keyed off the SAME per-request `secure` boolean
// every cookie()-setting call site already computes via requestScheme() - not
// a fixed boot-time choice, so a plain-http local/dev instance keeps the
// unprefixed name (a browser silently refuses to store a "__Host-" cookie
// without the Secure attribute, which would otherwise make dev logins
// mysteriously not stick).
//
// "__Host-" is a browser-enforced guarantee on top of Secure/HttpOnly/
// SameSite: the browser refuses to store (or forward to any other origin/
// subdomain) a cookie with this prefix unless it ALSO carries Path=/, no
// Domain attribute, and Secure - every cookie() call in this app already
// satisfies all three, so opting in costs nothing but naming.
export function sessionCookieName(base, secure) {
	return secure ? `__Host-${base}` : base;
}

// Read a cookie set via sessionCookieName() above: try the "__Host-" name
// first (what an https request actually carries), then the plain name (http/
// dev). A single request only ever has one of the two in its Cookie header,
// so this needs no knowledge of which scheme minted it.
export function readSessionCookie(req, base) {
	const cookies = parseCookies(req);
	return cookies[`__Host-${base}`] ?? cookies[base] ?? null;
}

// Clear a cookie set via sessionCookieName() above, for every name
// readSessionCookie() would accept - not just the one the current request's
// scheme would mint. readSessionCookie() falls back to the legacy plain name
// for migration compatibility, so a session issued before a http->https flip
// (or before this cookie adopted the "__Host-" prefix) carries that plain
// name - a logout that only clears sessionCookieName(base, secure) leaves
// that cookie live and still authenticating. Returns both clear-cookie
// header VALUES for the caller to append as separate Set-Cookie headers.
export function clearSessionCookie(base, secure) {
	return [clearCookie(sessionCookieName(base, secure), secure), clearCookie(base)];
}

// Direct socket peer address for this request, or null if unavailable.
// This is the one value a client cannot spoof (unlike any header), so it is
// the trust boundary every forwarding header is gated on below.
function socketPeer(req, server) {
	try {
		return server?.requestIP?.(req)?.address ?? null;
	} catch {
		return null;
	}
}

// Whether `peer` (a direct socket address) is inside config.trustedProxyCidrs
// - i.e. whether THIS specific connection is allowed to set X-Forwarded-For /
// X-Real-IP / X-Forwarded-Proto / X-Forwarded-Host at all. An empty allowlist
// (the default for a directly-exposed server) trusts nothing.
function isTrustedPeer(peer) {
	return !!peer && config.trustedProxyCidrs.length > 0 && ipInCidrs(peer, config.trustedProxyCidrs);
}

const MAX_FORWARDED_ENTRIES = 20;

// Walk an X-Forwarded-For chain from the right, skipping exactly `hops`
// trusted-proxy-appended entries, and return the next one - the address the
// nearest trusted proxy reported as the client. Returns null (caller falls
// back to the socket peer) when the header has too few entries for that many
// hops, is implausibly long, or the resulting entry isn't a parseable IP -
// rather than trying to fully parse an attacker-sized/malformed header.
function clientFromForwardedFor(header, hops) {
	const parts = header.split(',').map(s => s.trim()).filter(Boolean);
	if (parts.length === 0 || parts.length > MAX_FORWARDED_ENTRIES) return null;
	if (parts.length <= hops) return null;
	const candidate = parts[parts.length - 1 - hops];
	return parseIp(candidate) ? candidate : null;
}

// Client IP used for rate-limit and audit keys. Client-supplied forwarding
// headers (X-Forwarded-For / X-Real-IP) are fully attacker-controlled on a
// directly-exposed server, so they are only honored when the direct socket
// peer is itself inside config.trustedProxyCidrs (i.e. the deployment really
// sits behind a trusted reverse proxy at that address). Otherwise - or if the
// header is missing/malformed - we always use the real socket peer, which a
// client cannot spoof.
export function clientIp(req, server) {
	const socket = socketPeer(req, server);
	if (isTrustedPeer(socket)) {
		const fwd = req.headers.get('x-forwarded-for');
		if (fwd) {
			const client = clientFromForwardedFor(fwd, config.trustedProxyHops);
			if (client) return client;
		} else {
			const real = req.headers.get('x-real-ip')?.trim();
			if (real && parseIp(real)) return real;
		}
	}
	return socket;
}

// First value of a possibly comma-joined header (e.g. X-Forwarded-*), trimmed.
function firstHeader(req, name) {
	const v = req.headers.get(name);
	return v ? v.split(',')[0].trim() : '';
}

// The actual transport scheme of this request ('http' | 'https'). Honors
// X-Forwarded-Proto only when the direct socket peer is a trusted proxy (see
// isTrustedPeer above), where TLS is terminated upstream; otherwise uses the
// real connection scheme. Used to set the Secure flag on cookies correctly
// per request.
export function requestScheme(req, url, server) {
	if (isTrustedPeer(socketPeer(req, server))) {
		const p = firstHeader(req, 'x-forwarded-proto').toLowerCase();
		if (p === 'http' || p === 'https') return p;
	}
	return url.protocol === 'https:' ? 'https' : 'http';
}

// The public origin to build share links/QR codes from, derived from the host
// the visitor actually used so a single instance can serve multiple domains.
// The host comes from X-Forwarded-Host (trusted proxy) or the Host header. To
// stop a spoofed Host from poisoning links, only hosts listed in BASE_URL are
// honored; anything else falls back to the canonical BASE_URL. No trailing slash.
export function requestOrigin(req, url, server) {
	let host = url.host;
	if (isTrustedPeer(socketPeer(req, server))) {
		const xfh = firstHeader(req, 'x-forwarded-host');
		if (xfh) host = xfh;
	}
	host = host.toLowerCase();
	if (config.allowedHosts.has(host)) return `${requestScheme(req, url, server)}://${host}`;
	return config.baseUrl;
}

// Parse a single-range "bytes=start-end" header against a known total size.
// Returns { start, end, length } (inclusive end) or null if absent, or
// { invalid: true } if the range is unsatisfiable.
export function parseRange(header, size) {
	if (!header) return null;
	const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
	if (!m) return { invalid: true };
	let [, s, e] = m;
	if (s === '' && e === '') return { invalid: true };
	let start, end;
	if (s === '') {
		// suffix range: last N bytes
		const n = Number(e);
		if (n <= 0) return { invalid: true };
		start = Math.max(0, size - n);
		end = size - 1;
	} else {
		start = Number(s);
		end = e === '' ? size - 1 : Number(e);
	}
	if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= size) return { invalid: true };
	end = Math.min(end, size - 1);
	return { start, end, length: end - start + 1 };
}

// Sanitize a value for use in a Content-Disposition filename. Strips control
// chars and quotes; provides both the legacy and RFC 5987 (UTF-8) forms.
export function contentDisposition(filename, inline = false) {
	const fallback = String(filename).replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
	const encoded = encodeURIComponent(filename);
	const type = inline ? 'inline' : 'attachment';
	return `${type}; filename="${fallback}"; filename*=UTF-8''${encoded}`;
}

// Reject a cookie-authenticated state change unless the request provably came
// from our own origin. Browser cross-site requests always carry Sec-Fetch-Site
// and/or Origin on non-GET fetch/XHR/form submissions - a request with NEITHER
// header is not a legitimate browser-issued cross-origin-relevant request, so
// it is rejected too (fail closed). Callers that authenticate via a header
// credential instead of an ambient cookie (X-Edit-Token, X-API-Key,
// Authorization) never call this function at all - see each call site.
export function requireSameOrigin(req) {
	// No `ip` is available in this helper's signature (widening it across every
	// call site is not worth it for an audit-only field) - the csrf.rejected
	// event is logged with ip: null. pathname ONLY, never the query string -
	// see lib/audit.js's redaction policy.
	const reject = () => {
		let path = null;
		try {
			path = new URL(req.url).pathname;
		} catch {}
		audit('csrf.rejected', { detail: { method: req.method, path } });
		return error(403, 'Cross-origin request blocked');
	};
	const sfs = (req.headers.get('sec-fetch-site') || '').toLowerCase();
	if (sfs) {
		// 'same-origin' = our own pages; 'none' = direct user action (address bar,
		// bookmark) - neither is attacker-forgeable. 'same-site' (a subdomain) and
		// 'cross-site' are both rejected.
		if (sfs === 'same-origin' || sfs === 'none') return null;
		return reject();
	}
	const origin = req.headers.get('origin');
	if (origin) {
		try {
			if (config.allowedHosts.has(new URL(origin).host.toLowerCase())) return null;
		} catch {}
		return reject();
	}
	// Neither header present: a real browser fetch/XHR/form submission always
	// sends at least one on a same-origin or cross-origin non-GET request, so a
	// request with neither is treated as a forged/spoofed request, not a
	// trusted non-browser client (L-01: fail closed instead of falling through).
	return reject();
}

export { SECURITY_HEADERS };
