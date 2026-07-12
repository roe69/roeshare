// RoeShare entry point. Wires the router, static assets, security headers, the
// expired-share sweeper, and starts Bun.serve. Run with `bun run src/server.js`.

import './lib/logbuffer.js'; // first, so console capture covers the earliest boot logs
import { join, normalize, sep } from 'node:path';
import { statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { config } from './config.js';
import { db, now } from './db.js';
import { Router, RouterError } from './router.js';
import { registerRoutes } from './routes/index.js';
import { assertRouteCoverage } from './lib/routePolicy.js';
import { servePage } from './routes/pages.js';
import { clientIp, error, noContent, SECURITY_HEADERS } from './lib/http.js';
import { hasUploadAccess, isAdmin } from './lib/auth.js';
import { deleteShareFiles } from './lib/storage.js';
import { pickEncoding, compressBytes, isCompressibleType, compressResponse } from './lib/compress.js';
import * as quota from './lib/quota.js';
import { reconcileShareRenames } from './lib/renames.js';
import { reconcileMigrations, startMigrationSweep } from './lib/migrate.js';
import { audit, AUDIT_RETENTION_SECONDS } from './lib/audit.js';

// Authoritative recompute of the storage quota ledger (see lib/quota.js) -
// self-initializing (creates the single ledger row) and self-healing (a crash
// between a disk write and a ledger update, or any missed release call, is
// corrected here rather than diverging forever). Runs once, before the server
// starts accepting requests, so every request from the first one onward sees
// an accurate ledger.
quota.reconcile();

// Same self-healing idea, for an admin share rename (F-19): rolls any journal
// row left behind by a crash between the DB-side rename and the filesystem
// directory move forward to completion. Also runs once, before the server
// starts accepting requests, so no request can race a half-finished rename.
await reconcileShareRenames();

// M-06: roll forward any v1->v2 at-rest migration left mid-flight by a crash
// (see lib/migrate.js's module comment for the state table) - also run once,
// before the server accepts any request, so a request can never race a
// half-finished migration swap.
await reconcileMigrations();

const PUBLIC_DIR = join(import.meta.dir, '..', 'public');

const router = new Router();
registerRoutes(router);
// M-02: fail-closed route-policy coverage. Every in-scope registered route
// must carry a declareRoutePolicy(...) declaration (and every declaration
// must match a real route) - a gap throws here, before Bun.serve() binds a
// port, so the server refuses to start rather than silently serving an
// undeclared route.
assertRouteCoverage(router.routes);

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
	// `sw.js` is served from the root so its Service Worker scope covers the whole
	// origin (it intercepts the virtual /_e2e/* URLs used for streamed E2E media).
	// Normalize the request path ONCE up front and gate on the *normalized* value,
	// so the access checks below can never disagree with the file that actually gets
	// served. `path.normalize` collapses `..`, `.` and repeated slashes, so e.g.
	// `/js//admin.js` becomes `/js/admin.js`; gating on the raw pathname let that
	// slip past the string equality check yet still resolve to the real file.
	const rel = normalize(pathname).replace(/\\/g, '/').replace(/^(\.\.\/)+/, '');
	if (!/^\/(css|js|fonts|assets|favicon|apple-touch-icon|android-chrome|icon|robots|manifest|site\.webmanifest|sw\.js)/.test(rel)) return null;
	// The upload portal's code is gated behind the upload-password cookie: an
	// unauthorized visitor gets a 404 for it, so the source never leaks.
	if (rel === '/js/upload.js' && !hasUploadAccess(req)) return null;
	// Likewise, the admin dashboard's code is served only to a logged-in admin.
	// The /login page uses the separate, ungated /js/login.js instead.
	if (rel === '/js/admin.js' && !isAdmin(req)) return null;
	const full = join(PUBLIC_DIR, rel);
	if (full !== PUBLIC_DIR && !full.startsWith(PUBLIC_DIR + sep)) return null; // traversal guard
	if (!(await Bun.file(full).exists())) return null;
	const ext = full.slice(full.lastIndexOf('.'));
	const type = STATIC_TYPES[ext] || 'application/octet-stream';
	return staticResponse(req, await staticEntry(full, type));
}

// ---- Expired-share sweeper -------------------------------------------------

// Disk/db cleanup only: every read and upload path already refuses an expired
// share at request time, so this interval never gates visibility - the sweep
// just reclaims the bytes.
//
// Only a finalized share's published-link expiry is enforced here - a
// not-yet-finalized (still uploading) share must never be swept out from
// under an in-progress upload just because its (not-yet-started) expiry
// clock would otherwise have elapsed. Those are instead handled below as
// abandoned uploads, on their own (much longer) TTL.
const selectExpired = db.query('SELECT id FROM shares WHERE deleted_at IS NULL AND finalized = 1 AND expires_at IS NOT NULL AND expires_at < ?');
const selectAbandoned = db.query('SELECT id FROM shares WHERE deleted_at IS NULL AND finalized = 0 AND created_at < ?');
// Ghost-share cleanup: finalize() now refuses to flip a share to finalized
// while any of its files is still incomplete (see shares.js's finalizeTx), so
// this should never match a share created after that fix shipped. It exists
// to recover any "ghost" share finalized before the fix - permanently
// unfinished, yet invisible to both queries above (not abandoned, since
// finalized = 1; not necessarily expired, since its clock may not have
// elapsed or may not exist at all). Same created_at + abandonedUploadTtl
// grace period as selectAbandoned, so a share finalized moments ago whose
// last chunk simply hasn't landed yet is not swept out from under it.
const selectStuckFinalized = db.query(
	'SELECT DISTINCT s.id FROM shares s JOIN files f ON f.share_id = s.id WHERE s.deleted_at IS NULL AND s.finalized = 1 AND f.complete = 0 AND s.created_at < ?'
);
const markDeleted = db.query('UPDATE shares SET deleted_at = ? WHERE id = ?');
const sweepAuditEvents = db.query('DELETE FROM audit_events WHERE ts < ?');

async function sweep() {
	const ts = now();
	const expired = selectExpired.all(ts);
	for (const { id } of expired) {
		try {
			await deleteShareFiles(id);
			markDeleted.run(ts, id);
			quota.releaseShare(id);
			audit('share.expired', { target: id });
		} catch (e) {
			console.error('sweep failed for', id, e);
		}
	}
	if (expired.length) console.log(`[sweep] removed ${expired.length} expired share(s)`);

	// Abandoned (never finalized) uploads: no visitor has ever seen a link to
	// these, so they cannot be "expired" in the published-link sense - but a
	// draft that nobody ever finishes uploading/publishing must not sit on
	// disk forever, so it gets its own, much longer TTL.
	const abandoned = selectAbandoned.all(ts - config.abandonedUploadTtl);
	for (const { id } of abandoned) {
		try {
			await deleteShareFiles(id);
			markDeleted.run(ts, id);
			// Also clears any dead (never-completed) upload's reservation under
			// this share, since it never transitioned via releaseShare before now.
			quota.releaseShare(id);
		} catch (e) {
			console.error('sweep failed for', id, e);
		}
	}
	if (abandoned.length) console.log(`[sweep] removed ${abandoned.length} abandoned upload(s)`);

	// Legacy/defense-in-depth: reap any share that reached finalized = 1 with an
	// incomplete file still attached - a ghost that predates (or somehow evaded)
	// finalizeTx's completeness gate and that neither loop above can reach.
	const stuckFinalized = selectStuckFinalized.all(ts - config.abandonedUploadTtl);
	for (const { id } of stuckFinalized) {
		try {
			await deleteShareFiles(id);
			markDeleted.run(ts, id);
			quota.releaseShare(id);
			audit('share.swept.stuck_finalized', { target: id });
		} catch (e) {
			console.error('sweep failed for', id, e);
		}
	}
	if (stuckFinalized.length) console.log(`[sweep] removed ${stuckFinalized.length} stuck-finalized ghost share(s)`);

	// Audit-log retention (section 10 of the security audit): 90 days.
	sweepAuditEvents.run(ts - AUDIT_RETENTION_SECONDS);
}

// ---- Server ----------------------------------------------------------------

let warnedProxy = false;

const server = Bun.serve({
	hostname: config.host,
	port: config.port,
	maxRequestBodySize: Math.max(64 * 1024 * 1024, config.chunkSize * 2),
	// Bun's default idle timeout (~10s) aborts slow multi-GB chunk uploads and
	// quiet/paused streaming responses; 255s is Bun's documented maximum. The
	// streaming download handlers additionally disable the per-request timeout
	// entirely, for transfers that can legitimately run even longer.
	idleTimeout: 255,
	async fetch(req, server) {
		const url = new URL(req.url);
		const method = req.method;
		try {
			if (!config.trustedProxyCidrs.length && !warnedProxy && (req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip'))) {
				warnedProxy = true;
				console.warn('  WARNING: received X-Forwarded-For/X-Real-IP but no trusted proxy is configured - all clients share one rate-limit bucket and real IPs are not seen. Set TRUSTED_PROXY_CIDRS (or TRUST_PROXY=1 for loopback-only) only if behind a trusted reverse proxy.');
			}
			let res = null;
			if (url.pathname === '/health') {
				// Public liveness probe only: fixed, cheap, no auth. Deliberately
				// discloses nothing (no uptime/version/DB state) - see audit L-07.
				// Handled before routing/rate-limiting so it stays near-zero cost.
				res = noContent();
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
			// A malformed path segment (bad percent-encoding, or one decoding to a
			// smuggled "/", "\" or NUL) is a client error, not a server fault - and
			// must not fall through to serveStatic()/the custom-slug page above,
			// which is why router.match() throws instead of returning null for it.
			if (e instanceof RouterError) return error(e.status, e.message);
			console.error(`${method} ${url.pathname} ->`, e);
			return error(500, 'Internal server error');
		}
	},
});

// Periodic sweep (plus one on boot).
sweep();
setInterval(sweep, Math.max(60, config.sweepInterval) * 1000);

// M-06: secondary v1->v2 at-rest migration trigger (plus one on boot), so a
// file nobody ever reads again still converges to v2 without any admin
// action - the primary trigger is lazy, on next read (see routes/download.js).
startMigrationSweep();

console.log(`\n  RoeShare running at ${config.baseUrls.join(', ')}`);
console.log(`  Listening on http://${config.host}:${server.port}`);
console.log(`  Data dir: ${config.dataDir}`);
if (!config.adminPassword) console.warn('  WARNING: ADMIN_PASSWORD is unset - the admin panel is locked out.');
if (config.ephemeralSecret) console.warn('  WARNING: SECRET is unset - using an ephemeral key; sessions reset AND encrypted uploads become unreadable on restart. Set SECRET.');
console.log('');

export { server, router };
