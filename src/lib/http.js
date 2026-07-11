// HTTP helpers shared by every route: JSON responses, cookies, Range parsing,
// client IP extraction, and security headers.

import { config } from '../config.js';

const SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'X-Frame-Options': 'SAMEORIGIN',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
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
		if (k) out[k] = decodeURIComponent(v);
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

export const clearCookie = name => cookie(name, '', { maxAge: 0 });

// Client IP used for rate-limit and audit keys. Client-supplied forwarding
// headers (X-Forwarded-For / X-Real-IP) are fully attacker-controlled on a
// directly-exposed server, so they are only honored when config.trustProxy is
// set (i.e. the deployment really sits behind a trusted reverse proxy).
// Otherwise we always use the real socket peer, which a client cannot spoof.
export function clientIp(req, server) {
	let socket = null;
	try {
		socket = server?.requestIP?.(req)?.address ?? null;
	} catch {
		socket = null;
	}
	if (config.trustProxy) {
		const fwd = req.headers.get('x-forwarded-for');
		if (fwd) return fwd.split(',')[0].trim();
		const real = req.headers.get('x-real-ip');
		if (real) return real.trim();
	}
	return socket;
}

// First value of a possibly comma-joined header (e.g. X-Forwarded-*), trimmed.
function firstHeader(req, name) {
	const v = req.headers.get(name);
	return v ? v.split(',')[0].trim() : '';
}

// The actual transport scheme of this request ('http' | 'https'). Honors
// X-Forwarded-Proto only behind a trusted proxy (TRUST_PROXY=1), where TLS is
// terminated upstream; otherwise uses the real connection scheme. Used to set
// the Secure flag on cookies correctly per request.
export function requestScheme(req, url) {
	if (config.trustProxy) {
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
export function requestOrigin(req, url) {
	let host = url.host;
	if (config.trustProxy) {
		const xfh = firstHeader(req, 'x-forwarded-host');
		if (xfh) host = xfh;
	}
	host = host.toLowerCase();
	if (config.allowedHosts.has(host)) return `${requestScheme(req, url)}://${host}`;
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

export { SECURITY_HEADERS };
