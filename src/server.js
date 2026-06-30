// RoeShare entry point. Wires the router, static assets, security headers, the
// expired-share sweeper, and starts Bun.serve. Run with `bun run src/server.js`.

import './lib/logbuffer.js'; // first, so console capture covers the earliest boot logs
import { join, normalize, sep } from 'node:path';
import { statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { config } from './config.js';
import { db, now } from './db.js';
import { Router } from './router.js';
import { registerRoutes } from './routes/index.js';
import { servePage } from './routes/pages.js';
import { clientIp, error, json, SECURITY_HEADERS } from './lib/http.js';
import { hasUploadAccess, isAdmin } from './lib/auth.js';
import { deleteShareFiles } from './lib/storage.js';
import { pickEncoding, compressBytes, isCompressibleType, compressResponse } from './lib/compress.js';

const PUBLIC_DIR = join(import.meta.dir, '..', 'public');

const router = new Router();
registerRoutes(router);

// ---- Static assets ---------------------------------------------------------

const STATIC_TYPES = {
	'.css': 'text/css; charset=utf-8',
	'.js': 'text/javascript; charset=utf-8',
	'.mjs': 'text/javascript; charset=utf-8',
	'.html': 'text/html; charset=utf-8',
	'.svg': 'image/svg+xml',
	'.png': 'image/png',
	'.jpg': 'image/jpeg',
	'.ico': 'image/x-icon',
	'.woff2': 'font/woff2',
	'.ttf': 'font/ttf',
	'.json': 'application/json; charset=utf-8',
	'.webmanifest': 'application/manifest+json',
};

// In-memory static cache: each asset is read once, hashed for an ETag, and its
// brotli/gzip variants are computed lazily and kept. The entry is re-read when
// the file's mtime changes, so editing or re-pulling a file under public/ takes
// effect WITHOUT a server restart (no more stale assets from a long-lived cache).
const staticCache = new Map();

async function staticEntry(full, type) {
	let mtime = 0;
	try { mtime = statSync(full).mtimeMs; } catch { /* fall through to a fresh read */ }
	const cached = staticCache.get(full);
	if (cached && cached.mtime === mtime) return cached;

	const identity = Buffer.from(await Bun.file(full).arrayBuffer());
	const etag = '"' + createHash('sha1').update(identity).digest('base64url').slice(0, 20) + '"';
	// JS/CSS are served `no-store`: never cached by the browser, so an ES module
	// can never load a fresh file next to a stale import (the bug behind "I have
	// to hard-refresh"). Other assets (images, fonts) use `no-cache` - cacheable
	// but revalidated via the ETag, with cheap 304s when unchanged.
	const ext = full.slice(full.lastIndexOf('.'));
	const cacheControl = ext === '.js' || ext === '.mjs' || ext === '.css' ? 'no-store' : 'no-cache';
	const e = { type, etag, identity, enc: {}, mtime, cacheControl };
	staticCache.set(full, e);
	return e;
}

function staticResponse(req, e) {
	// Only the revalidated (no-cache) assets take part in 304s; no-store assets
	// are never cached, so the browser never conditionally requests them.
	if (e.cacheControl === 'no-cache' && req.headers.get('if-none-match') === e.etag) {
		return new Response(null, { status: 304, headers: { ETag: e.etag, 'Cache-Control': e.cacheControl } });
	}
	const headers = { 'Content-Type': e.type, ETag: e.etag, 'Cache-Control': e.cacheControl, ...SECURITY_HEADERS };
	let body = e.identity;
	if (isCompressibleType(e.type)) {
		const enc = pickEncoding(req);
		if (enc) {
			if (!e.enc[enc]) e.enc[enc] = compressBytes(e.identity, enc, 11); // max quality, computed once
			body = e.enc[enc];
			headers['Content-Encoding'] = enc;
			headers['Vary'] = 'Accept-Encoding';
		}
	}
	return new Response(body, { headers });
}

async function serveStatic(req, pathname) {
	// Only assets under these prefixes are public. Everything else 404s.
	if (!/^\/(css|js|fonts|assets|favicon|apple-touch-icon|android-chrome|icon|robots|manifest|site\.webmanifest)/.test(pathname)) return null;
	// The upload portal's code is gated behind the upload-password cookie: an
	// unauthorized visitor gets a 404 for it, so the source never leaks.
	if (pathname === '/js/upload.js' && !hasUploadAccess(req)) return null;
	// Likewise, the admin dashboard's code is served only to a logged-in admin.
	// The /login page uses the separate, ungated /js/login.js instead.
	if (pathname === '/js/admin.js' && !isAdmin(req)) return null;
	const rel = normalize(pathname).replace(/^(\.\.[/\\])+/, '');
	const full = join(PUBLIC_DIR, rel);
	if (full !== PUBLIC_DIR && !full.startsWith(PUBLIC_DIR + sep)) return null; // traversal guard
	if (!(await Bun.file(full).exists())) return null;
	const ext = full.slice(full.lastIndexOf('.'));
	const type = STATIC_TYPES[ext] || 'application/octet-stream';
	return staticResponse(req, await staticEntry(full, type));
}

// ---- Expired-share sweeper -------------------------------------------------

const selectExpired = db.query('SELECT id FROM shares WHERE deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at < ?');
const markDeleted = db.query('UPDATE shares SET deleted_at = ? WHERE id = ?');

async function sweep() {
	const ts = now();
	const expired = selectExpired.all(ts);
	for (const { id } of expired) {
		try {
			await deleteShareFiles(id);
			markDeleted.run(ts, id);
		} catch (e) {
			console.error('sweep failed for', id, e);
		}
	}
	if (expired.length) console.log(`[sweep] removed ${expired.length} expired share(s)`);
}

// ---- Server ----------------------------------------------------------------

const server = Bun.serve({
	hostname: config.host,
	port: config.port,
	maxRequestBodySize: Math.max(64 * 1024 * 1024, config.chunkSize * 2),
	async fetch(req, server) {
		const url = new URL(req.url);
		const method = req.method;
		try {
			let res = null;
			if (url.pathname === '/healthz') {
				res = json({ ok: true, uptime: Math.floor(process.uptime()) });
			} else {
				const matched = router.match(method, url.pathname);
				if (matched) {
					const ctx = { req, url, params: matched.params, server, ip: clientIp(req, server), query: url.searchParams };
					res = await matched.handler(ctx);
				} else if (method === 'GET' || method === 'HEAD') {
					res = await serveStatic(req, url.pathname);
					// Root-level custom slug (e.g. /my-files): serve the view page, which
					// resolves the share by its last path segment. Runs only after real
					// routes and static assets have been tried, so it can never shadow
					// /admin, /api/*, or a favicon.
					if (!res && /^\/[A-Za-z0-9_-]{1,64}$/.test(url.pathname)) res = await servePage('view.html');
				}
			}
			if (!res) res = error(404, 'Not found');
			// Compress text-like responses (brotli/gzip); file streams are skipped.
			return await compressResponse(req, res);
		} catch (e) {
			console.error(`${method} ${url.pathname} ->`, e);
			return error(500, 'Internal server error');
		}
	},
});

// Periodic sweep (plus one on boot).
sweep();
setInterval(sweep, Math.max(60, config.sweepInterval) * 1000);

console.log(`\n  RoeShare running at ${config.baseUrls.join(', ')}`);
console.log(`  Listening on http://${config.host}:${server.port}`);
console.log(`  Data dir: ${config.dataDir}`);
if (!config.adminPassword) console.warn('  WARNING: ADMIN_PASSWORD is unset - the admin panel is locked out.');
if (config.ephemeralSecret) console.warn('  WARNING: SECRET is unset - using an ephemeral key; sessions reset AND encrypted uploads become unreadable on restart. Set SECRET.');
console.log('');

export { server, router };
