// Page routes: serve the three static HTML shells. Each loads its own module
// and the shared CSS/JS. API routes are registered first so these never shadow
// them.

import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { db } from '../db.js';
import { config } from '../config.js';
import { error, requestOrigin, clientIp, SECURITY_HEADERS } from '../lib/http.js';
import { hasUploadAccess, isAdmin } from '../lib/auth.js';
import { escapeHtmlAttr } from '../lib/html.js';
import { declareRoutePolicy } from '../lib/routePolicy.js';
import { liveShare } from './shares.js';
import { servePreview } from './download.js';

const PAGES_DIR = join(import.meta.dir, '..', '..', 'public');

// App pages only load same-origin module scripts and the design-system CSS, plus
// same-origin media for previews. Inline styles (style="..." attributes) need
// 'unsafe-inline' for style-src; there are no inline scripts.
//
// L-04: object-src is 'none' - nothing in this app ever renders an <object>/
// <embed>, so there is nothing for it to be load-bearing for; a same-origin/
// blob object embed was needless attack surface for a MIME-confused or
// parser-exploited upload. frame-src keeps 'self' (PDF preview iframes at
// public/js/view.js load the same-origin /preview URL) and 'blob:' (the E2E
// preview path decrypts client-side and frames the plaintext via a blob: URL,
// see e2ePreview in view.js) - both are genuinely load-bearing for PDF
// preview, so they stay, but every iframe RoeShare creates for a preview is
// additionally given an empty sandbox (see view.js) so framed content can
// never script, submit forms, or navigate the top-level page.
const PAGE_CSP =
	"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; frame-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'";

// Templated files are rendered once and memoised per file: the tokens
// ({{APP_NAME}} / {{APP_TITLE}}) resolve from config, which is frozen at boot, so
// a file's output never changes within a process. Editing a file on disk needs a
// restart to take effect (same as the static-asset cache); a redeploy restarts
// the process, so new markup ships then. A missing file caches as null (404).
const pageCache = new Map();

function renderPage(file) {
	if (pageCache.has(file)) return pageCache.get(file);
	let out;
	try {
		out = readFileSync(join(PAGES_DIR, file), 'utf8')
			.replaceAll('{{APP_NAME}}', config.appNameHtml)
			.replaceAll('{{APP_TITLE}}', config.appTitle)
			.replaceAll('{{BRAND_STYLE}}', config.brandStyle);
	} catch {
		out = null;
	}
	pageCache.set(file, out);
	return out;
}

export function servePage(file, extraHeaders) {
	const html = renderPage(file);
	if (html === null) return error(404, 'Not found');
	return new Response(html, {
		// no-cache = the browser revalidates each load, so a redeploy's new markup
		// is served immediately (the `/` route overrides this with a stronger
		// no-store). The rendered string itself is cached per process (see above).
		headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'Content-Security-Policy': PAGE_CSP, ...SECURITY_HEADERS, ...(extraHeaders || {}) },
	});
}

// ---- Share embed metadata (Discord/web link previews) ---------------------
//
// C in the API contract: server-rendered OpenGraph/Twitter meta for the view
// page, injected per request (never memoized - see pageCache above, which is
// keyed per FILE and would otherwise leak one share's title to every visitor
// of every share). Rich meta only for a share the server can actually see
// plaintext for (non-E2E) and that is safe to summarize publicly (not
// password-protected, not one-time, not download-capped, finalized, and has
// at least one complete image or mp4 video file) - everything else, including
// a missing id, gets byte-identical GENERIC meta with zero per-share data, so
// the meta itself never reveals whether an id exists, is private, or is E2E.

// Deliberate subset of download.js's SAFE_INLINE: no svg (script-capable),
// no bmp/x-icon (not worth a rich preview).
const EMBED_IMAGE_MIME = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif']);

// Also a deliberate subset of SAFE_INLINE: webm/ogg are left out even though
// download.js serves them inline fine - Discord's own unfurler only reliably
// inlines mp4 as a playable video, and a share URL that resolves to bytes a
// crawler can't actually play is worse than no rich embed at all.
const EMBED_VIDEO_MIME = new Set(['video/mp4']);

const GENERIC_EMBED_DESCRIPTION = 'Secure, self-hosted file sharing.';

// Case-insensitive fallback lookup for a custom slug typed with different
// casing - excludes soft-deleted rows, same as shares.js's own slug-conflict
// check. Only the id is selected; liveShare() below re-reads the full row and
// re-applies the exact same expiry predicate GET /api/shares/:id uses.
const getIdByLowerSlug = db.query('SELECT id FROM shares WHERE lower(id) = lower(?) AND deleted_at IS NULL');

// A minimal, read-only file lookup - no download_count/view_count touched,
// no write of any kind. First complete file (upload order) whose mime is
// embeddable, or null.
const getEmbeddableFile = db.query(
	"SELECT id, name, size, mime FROM files WHERE share_id = ? AND complete = 1 ORDER BY created_at ASC, id ASC"
);

function formatBytesServer(bytes) {
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	let n = Number(bytes) || 0;
	let i = 0;
	while (n >= 1024 && i < units.length - 1) {
		n /= 1024;
		i++;
	}
	return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

// Direct, read-only resolution matching liveShare()'s exact predicate (live/
// finalized/not-deleted/not-expired) - id first (the common case), then a
// case-insensitive slug fallback. Never touches view_count.
function resolveShareForMeta(idOrSlug) {
	const byId = liveShare(idOrSlug);
	if (byId) return byId;
	const row = getIdByLowerSlug.get(idOrSlug);
	if (!row || row.id === idOrSlug) return null;
	return liveShare(row.id);
}

function metaTag(prop, attr, content) {
	return `<meta ${attr}="${prop}" content="${escapeHtmlAttr(content)}">`;
}

function genericMetaHtml() {
	return [
		metaTag('og:site_name', 'property', config.appTitle),
		metaTag('og:title', 'property', config.appTitle),
		metaTag('og:type', 'property', 'website'),
		metaTag('og:description', 'property', GENERIC_EMBED_DESCRIPTION),
		metaTag('twitter:card', 'name', 'summary'),
	].join('\n\t');
}

function richMetaHtml(share, file, origin) {
	const title = share.title || file.name;
	const description = `${file.name} (${formatBytesServer(file.size)})`;
	const mediaUrl = `${origin}/api/shares/${share.id}/files/${file.id}/preview`;
	const isVideo = EMBED_VIDEO_MIME.has(String(file.mime || '').toLowerCase().split(';')[0].trim());
	const base = [
		metaTag('og:site_name', 'property', config.appTitle),
		metaTag('og:title', 'property', title),
		metaTag('og:description', 'property', description),
		metaTag('og:url', 'property', `${origin}/s/${share.id}`),
	];
	// Video and image shares each get only their own media tag - an og:video
	// pointing at an image (or vice versa) is meaningless, and Discord itself
	// never reaches this HTML anyway (it hits the bare-bytes bot path above).
	const media = isVideo
		? [
				metaTag('og:type', 'property', 'video.other'),
				metaTag('og:video', 'property', mediaUrl),
				metaTag('og:video:secure_url', 'property', mediaUrl),
				metaTag('og:video:type', 'property', file.mime),
			]
		: [
				metaTag('og:type', 'property', 'website'),
				metaTag('og:image', 'property', mediaUrl),
				metaTag('og:image:type', 'property', file.mime),
				metaTag('twitter:card', 'name', 'summary_large_image'),
				metaTag('twitter:title', 'name', title),
				metaTag('twitter:image', 'name', mediaUrl),
			];
	return [...base, ...media].join('\n\t');
}

// The single eligibility predicate for "is this share safe to summarize/embed
// publicly at all" - finalized, non-E2E (server can see plaintext), not
// password-protected, not one-time, not download-capped, with at least one
// complete image or mp4 video file. Shared by buildShareMeta (rich OG meta
// for browsers) and the bare-bytes bot path below (serveSharePage) so there
// is exactly one place that decides embeddability, not two that could drift
// apart. Image wins over video when a share has both: the first complete
// image (in upload order) is preferred, falling back to the first complete
// mp4 only when the share has no embeddable image at all.
function embeddableFile(share) {
	if (!share || !share.finalized || share.e2e || share.password_hash || share.one_time || share.max_downloads !== null) return null;
	const files = getEmbeddableFile.all(share.id);
	const mimeOf = f => String(f.mime || '').toLowerCase().split(';')[0].trim();
	return files.find(f => EMBED_IMAGE_MIME.has(mimeOf(f))) || files.find(f => EMBED_VIDEO_MIME.has(mimeOf(f))) || null;
}

// Builds the meta block for an already-resolved share (or null - generic
// meta). Any unexpected failure (e.g. a malformed row the queries above
// choke on) degrades to generic meta rather than a 500 - a link preview is
// never load-bearing for the page itself.
function buildShareMeta(share, origin) {
	try {
		const file = embeddableFile(share);
		if (!file) return genericMetaHtml();
		return richMetaHtml(share, file, origin);
	} catch (e) {
		console.error('embed meta build failed for', share?.id, e);
		return genericMetaHtml();
	}
}

// Chat/link-preview crawler UAs (not general search bots - Googlebot etc. are
// deliberately excluded so they keep indexing the real HTML page). Discord's
// own image-proxy re-fetch uses a plain browser UA (see research notes), but
// that fetch never happens under this scheme: the crawler's first and only
// request to this URL already gets image bytes directly, so there's no
// separate og:image URL for it to chase.
const BOT_UA_RE = /Discordbot|Slackbot-LinkExpanding|TelegramBot|facebookexternalhit|WhatsApp|SkypeUriPreview|LinkedInBot|Twitterbot/i;

function isBotUA(req) {
	return BOT_UA_RE.test(req.headers.get('user-agent') || '');
}

// Serves the view page for a share id or custom slug with per-request embed
// meta spliced into the cached base HTML (renderPage() below caches the base
// file - including the still-unsubstituted {{SHARE_META}} token - per
// process; only the meta block itself is computed fresh every time and never
// cached, so two different shares can never leak each other's title/image).
//
// A case-variant slug/id (resolveShareForMeta's lower() fallback) redirects
// to the canonically-cased /s/:id first, rather than rendering meta for a URL
// the page itself cannot load: GET /api/shares/:id (view.js's fetch) is
// byte-case-sensitive, so serving 200-with-rich-meta at the wrong case would
// show a full embed for a link that 404s the moment anyone clicks it.
//
// Bare-bytes bot path: a chat-app link-preview crawler (isBotUA) fetching a
// share URL that resolves to an eligible image or mp4 video (embeddableFile -
// the exact same predicate buildShareMeta uses for og:image/og:video) gets
// the raw bytes back at THIS url, not an HTML page - Discord's unfurler never
// follows redirects, so the bytes have to come back on the first response.
// Delegates entirely to servePreview (the /preview route's own handler)
// rather than reading storage.js directly, so this gets the exact same
// access/rate-limit/one-time/capped gate chain for free (including Range/HEAD
// support for video), and req/url/server are only needed for this branch.
export async function serveSharePage(idOrSlug, origin, req, url, server) {
	let share = null;
	try {
		share = resolveShareForMeta(idOrSlug);
	} catch (e) {
		console.error('share resolution failed for', idOrSlug, e);
	}
	if (share && share.id !== idOrSlug) {
		return new Response(null, { status: 302, headers: { Location: `/s/${share.id}`, 'Cache-Control': 'no-store' } });
	}
	if (req && isBotUA(req)) {
		const file = embeddableFile(share);
		if (file) {
			const res = await servePreview({ req, url, params: { id: share.id, fileId: file.id }, ip: clientIp(req, server), server });
			res.headers.set('Vary', 'User-Agent');
			return res;
		}
	}
	const html = renderPage('view.html');
	if (html === null) return error(404, 'Not found');
	const meta = buildShareMeta(share, origin);
	const out = html.replace('{{SHARE_META}}', meta);
	return new Response(out, {
		headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'Content-Security-Policy': PAGE_CSP, ...SECURITY_HEADERS, 'Vary': 'User-Agent' },
	});
}

export default function pages(router) {
	// When an upload password is set, an unauthorized visitor gets only the lock
	// page - the upload portal's markup is never served without the cookie.
	// The route itself needs no credential (it branches to lock.html for an
	// unauthorized visitor internally).
	//
	// M-03: a bare GET/HEAD here must NEVER consume the magic-link token. This
	// route is reachable by a server-side link-preview scanner (Slack, Teams,
	// Outlook Safe Links, Proofpoint, iMessage, ...) that prefetches a pasted
	// URL with no cookie and no JS execution - router.js auto-routes HEAD to
	// GET, so the old design (redeeming the single-use token directly in this
	// handler) let such a prefetch silently and permanently burn the token
	// before the intended human ever clicked the link. A token in the query
	// string now only selects an interstitial page (link.html) that redeems
	// it via a real POST fired from browser JS (public/js/link-redeem.js,
	// see POST /api/upload/link/redeem in routes/shares.js) - something a
	// non-JS-executing scanner cannot do. Nothing here has a side effect, so
	// no rate limit/audit is needed on this route itself.
	declareRoutePolicy('GET', '/', { auth: 'public', csrf: false, rateLimit: null, audit: null });
	router.get('/', ctx => {
		const { req, url } = ctx;

		if (config.uploadPassword && !hasUploadAccess(req) && url.searchParams.get('token')) {
			return servePage('link.html', { 'Cache-Control': 'no-store' });
		}

		const file = config.uploadPassword && !hasUploadAccess(req) ? 'lock.html' : 'upload.html';
		return servePage(file, { 'Cache-Control': 'no-store' });
	});
	declareRoutePolicy('GET', '/s/:id', { auth: 'public', csrf: false, rateLimit: null, audit: null });
	router.get('/s/:id', ctx => serveSharePage(ctx.params.id, requestOrigin(ctx.req, ctx.url, ctx.server), ctx.req, ctx.url, ctx.server));
	declareRoutePolicy('GET', '/mine', { auth: 'public', csrf: false, rateLimit: null, audit: null });
	router.get('/mine', () => servePage('myshares.html'));
	// API-key portal: sign in with a key name + token to manage that key's shares.
	declareRoutePolicy('GET', '/api', { auth: 'public', csrf: false, rateLimit: null, audit: null });
	router.get('/api', () => servePage('apikey.html'));

	// Admin auth is an explicit two-route flow:
	//   /login - the password form (always available, ungated).
	//   /admin - the dashboard, only for an authenticated admin; anyone else is
	//            redirected to /login (never served the dashboard shell). The
	//            matching /js/admin.js is gated the same way in the static handler,
	//            so the management markup/code never leaves the server unauthorized.
	const redirect = to => new Response(null, { status: 302, headers: { Location: to, 'Cache-Control': 'no-store' } });
	declareRoutePolicy('GET', '/login', { auth: 'public', csrf: false, rateLimit: null, audit: null });
	router.get('/login', ({ req }) => (isAdmin(req) ? redirect('/admin') : servePage('login.html', { 'Cache-Control': 'no-store' })));
	// The dashboard shell is only ever served past isAdmin() - the redirect-to-
	// /login fallback is the deny path, not a public serve.
	declareRoutePolicy('GET', '/admin', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/admin', ({ req }) => (isAdmin(req) ? servePage('admin.html', { 'Cache-Control': 'no-store' }) : redirect('/login')));

	// The web app manifest is templated too, so the PWA/install name follows
	// APP_TITLE. Registered as a route (runs before the static handler) so the
	// {{APP_TITLE}} token is substituted rather than served verbatim.
	declareRoutePolicy('GET', '/site.webmanifest', { auth: 'public', csrf: false, rateLimit: null, audit: null });
	router.get('/site.webmanifest', () => {
		const body = renderPage('site.webmanifest');
		if (body === null) return error(404, 'Not found');
		return new Response(body, {
			headers: { 'Content-Type': 'application/manifest+json; charset=utf-8', 'Cache-Control': 'no-cache', ...SECURITY_HEADERS },
		});
	});
}
