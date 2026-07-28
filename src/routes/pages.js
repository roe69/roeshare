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
// a missing id, gets byte-identical EMPTY meta (no OG/Twitter tags at all, so
// chat apps generate no embed whatsoever for such links), and the absence of
// meta never reveals whether an id exists, is private, or is E2E.

// Deliberate subset of download.js's SAFE_INLINE: no svg (script-capable),
// no bmp/x-icon (not worth a rich preview).
const EMBED_IMAGE_MIME = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif']);

// Also a deliberate subset of SAFE_INLINE: webm/ogg are left out even though
// download.js serves them inline fine - Discord's own unfurler only reliably
// inlines mp4 as a playable video, and a share URL that resolves to bytes a
// crawler can't actually play is worse than no rich embed at all.
const EMBED_VIDEO_MIME = new Set(['video/mp4']);

// ---- Direct-media links (/<id>.<ext>) -------------------------------------
//
// A share URL may carry the real file extension of its embeddable file, and
// that form serves the bytes themselves to EVERY caller - bot or browser -
// exactly like a CDN/image-host link. Two independently measured reasons
// (2026-07-28, against the live deployment + Discord's own API):
//
//  1. Discord's media proxy picks its output format from the extension in the
//     URL path, not from the origin's Content-Type. The same animated GIF,
//     unfurled from an extensionless URL, comes back from
//     images-ext-1.discordapp.net as a STATIC image/png first frame; served
//     from a URL ending in .gif it comes back as the full animated image/gif.
//     The embed JSON is byte-identical in both cases, so this is not fixable
//     from the meta/response side - only the URL shape moves it.
//  2. Because the extensioned form does not branch on User-Agent, its response
//     is a single representation and is therefore safe to cache in a CDN that
//     ignores `Vary: User-Agent` (Cloudflare, in front of the live
//     deployment). The extensionless share URL, which serves HTML to humans
//     and bytes to crawlers, can never be - one cached representation would be
//     handed to the wrong audience.
//
// Extensions are matched to an exact mime: a `.gif` URL only ever resolves to
// a file actually stored as image/gif, so the extension can never lie to the
// proxy about what the bytes are.
const MEDIA_EXT_MIME = new Map([
	['png', 'image/png'],
	['jpg', 'image/jpeg'],
	['jpeg', 'image/jpeg'],
	['gif', 'image/gif'],
	['webp', 'image/webp'],
	['avif', 'image/avif'],
	['mp4', 'video/mp4'],
]);

// The canonical extension to advertise for a stored mime (the inverse of the
// map above, minus the 'jpeg' alias - both spellings resolve, only 'jpg' is
// ever built into a link).
const MIME_MEDIA_EXT = new Map([
	['image/png', 'png'],
	['image/jpeg', 'jpg'],
	['image/gif', 'gif'],
	['image/webp', 'webp'],
	['image/avif', 'avif'],
	['video/mp4', 'mp4'],
]);

// Short, deliberate exception to the no-store rule the rest of the share bytes
// live under (see download.js's L-05 comment). A share is only reachable at a
// direct-media URL when embeddableFile() says it is public in every sense -
// finalized, non-E2E, no password, not one-time, not download-capped - so
// these bytes are already served to any anonymous caller that has the link.
// Five minutes is sized for the burst that actually matters (a chat app
// unfurls, scans, then fans the same URL out to its own edges within seconds
// of a link being posted) while keeping the window in which a since-deleted
// share could still be served from a CDN edge to minutes, not the year
// Discord's own media proxy caches it for regardless of what we send.
const DIRECT_MEDIA_CACHE = 'public, max-age=300';

const mimeOf = f => String(f?.mime || '').toLowerCase().split(';')[0].trim();

// Split a trailing media extension off a path segment, or null when there is
// none. Share ids and custom slugs are [A-Za-z0-9_-] only (lib/slug.js), so a
// dot in the segment is unambiguously an extension separator and never part of
// the id itself.
function splitMediaExt(segment) {
	const dot = segment.lastIndexOf('.');
	if (dot <= 0) return null;
	const ext = segment.slice(dot + 1).toLowerCase();
	if (!MEDIA_EXT_MIME.has(ext)) return null;
	return { id: segment.slice(0, dot), ext };
}

// The direct-media URL for a share, or null when it has no embeddable
// image/video to point at (not finalized yet, E2E, password-protected,
// one-time, download-capped, or simply not media). Takes an id or an
// already-fetched share row - callers that hold the row must not pay for a
// second lookup. Never throws: a link is not worth failing a request over.
function directMediaUrl(idOrShare, origin) {
	try {
		const share = typeof idOrShare === 'string' ? liveShare(idOrShare) : idOrShare;
		const file = embeddableFile(share);
		const ext = file && MIME_MEDIA_EXT.get(mimeOf(file));
		return ext ? `${origin}/${share.id}.${ext}` : null;
	} catch (e) {
		console.error('direct media link build failed for', typeof idOrShare === 'string' ? idOrShare : idOrShare?.id, e);
		return null;
	}
}

// The public link to advertise for a share: the direct-media form when there
// is one (so a pasted link unfurls as bare, animated, CDN-cacheable media),
// the plain share page otherwise.
export function shareLink(idOrShare, origin) {
	const id = typeof idOrShare === 'string' ? idOrShare : idOrShare?.id;
	return directMediaUrl(idOrShare, origin) || `${origin}/${id}`;
}

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
//
// `wantMime` narrows the search to files of exactly that mime instead of
// applying the image-then-video preference - used by the direct-media route
// below so a `.mp4` URL resolves to the share's mp4 even when the share also
// carries an image that would otherwise win. It is a filter ON TOP of this
// predicate, never a second predicate: an ineligible share resolves to null
// here whatever mime is asked for.
function embeddableFile(share, wantMime) {
	if (!share || !share.finalized || share.e2e || share.password_hash || share.one_time || share.max_downloads !== null) return null;
	const files = getEmbeddableFile.all(share.id);
	if (wantMime) {
		return files.find(f => mimeOf(f) === wantMime && (EMBED_IMAGE_MIME.has(wantMime) || EMBED_VIDEO_MIME.has(wantMime))) || null;
	}
	return files.find(f => EMBED_IMAGE_MIME.has(mimeOf(f))) || files.find(f => EMBED_VIDEO_MIME.has(mimeOf(f))) || null;
}

// Builds the meta block for an already-resolved share (or null - empty: no
// OG/Twitter tags means no embed at all for a non-embeddable link). Any
// unexpected failure (e.g. a malformed row the queries above choke on)
// degrades to empty meta rather than a 500 - a link preview is never
// load-bearing for the page itself.
function buildShareMeta(share, origin) {
	try {
		const file = embeddableFile(share);
		if (!file) return '';
		return richMetaHtml(share, file, origin);
	} catch (e) {
		console.error('embed meta build failed for', share?.id, e);
		return '';
	}
}

// Chat/link-preview crawler UAs (not general search bots - Googlebot etc. are
// deliberately excluded so they keep indexing the real HTML page).
const BOT_UA_RE = /Discordbot|Slackbot-LinkExpanding|TelegramBot|facebookexternalhit|WhatsApp|SkypeUriPreview|LinkedInBot|Twitterbot/i;

// Discord is documented to send a SECOND, non-Discordbot-UA fetch of the same
// URL (discord-api-docs#1600) using this exact, frozen 2015-era UA string.
// Without recognizing it, that second fetch falls into the HTML branch below
// and gets a document where media bytes were expected - an embed card that
// never plays. Matched by exact equality only (never a partial/pattern match
// on "Firefox"), so no real Firefox user can ever be misidentified as a bot.
const DISCORD_SECOND_FETCH_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0';

function isBotUA(req) {
	const ua = req.headers.get('user-agent') || '';
	return BOT_UA_RE.test(ua) || ua === DISCORD_SECOND_FETCH_UA;
}

// Direct-media route: /<id>.<ext> (and /s/<id>.<ext>) serves the share's own
// bytes to every caller, with no User-Agent branching at all - see the
// MEDIA_EXT_MIME comment above for the two measured reasons that shape exists.
// Delegates to servePreview for the same reason the bot path does: it inherits
// the whole gate chain (liveShare -> rename-pending -> rate limit ->
// accessCheck -> the F-01 one-time/capped 403) plus Range/HEAD support, rather
// than reaching into storage.js on its own.
//
// Returns null (not a 404) when the extension is not a media extension at all,
// so the caller can fall through to its own not-found handling; every other
// miss - unknown id, private/E2E/password/one-time/capped share, or an
// extension that does not match a file this share actually has - answers with
// one byte-identical 404, so the response reveals nothing about which it was.
export async function serveShareMedia(idOrSlug, ext, req, url, server) {
	const wantMime = MEDIA_EXT_MIME.get(ext);
	if (!wantMime) return null;
	let share = null;
	try {
		share = resolveShareForMeta(idOrSlug);
	} catch (e) {
		console.error('share resolution failed for', idOrSlug, e);
	}
	const file = embeddableFile(share, wantMime);
	if (!file) return notFoundMedia();
	const res = await servePreview({ req, url, params: { id: share.id, fileId: file.id }, ip: clientIp(req, server), server });
	// Only a real body gets the cacheable header. Everything else here is
	// transient or per-caller (a 503 while a rename is mid-flight, a 429, a
	// 403) and must never be stored by an intermediary and replayed - and a
	// bare error() carries no Cache-Control of its own, which would leave a
	// CDN free to apply its default heuristic for a ".gif"/".mp4" path.
	if (res.status === 200 || res.status === 206) res.headers.set('Cache-Control', DIRECT_MEDIA_CACHE);
	else res.headers.set('Cache-Control', 'no-store');
	return res;
}

// The generic 404 shape, explicitly marked no-store: a CDN in front of us
// applies its own default caching heuristic to an uncontrolled response for a
// ".gif"/".mp4" path, and a share that is briefly unresolvable (mid-rename, or
// simply not finalized yet) must not have that 404 pinned at an edge.
function notFoundMedia() {
	const res = error(404, 'Not found');
	res.headers.set('Cache-Control', 'no-store');
	return res;
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
// A crawler fetching any NON-embeddable share URL gets an empty 204 instead
// of the HTML page, so no embed of any kind is ever generated for it.
export async function serveSharePage(idOrSlug, origin, req, url, server) {
	// /s/<id>.<ext> is the same direct-media link as /<id>.<ext> (the root-level
	// form is what gets published, but both resolve, exactly as /s/<id> and
	// /<id> both resolve to the share page).
	const media = splitMediaExt(idOrSlug);
	if (media) return (await serveShareMedia(media.id, media.ext, req, url, server)) || notFoundMedia();
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
		// Non-embeddable (or missing/private/E2E) share: a preview crawler gets
		// nothing at all - no HTML, no <title>, no meta - so the chat app renders
		// no embed of any kind. Byte-identical for every excluded case, so the
		// empty response itself reveals nothing about why it was excluded.
		return new Response(null, { status: 204, headers: { 'Vary': 'User-Agent', 'Cache-Control': 'no-store', ...SECURITY_HEADERS } });
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
