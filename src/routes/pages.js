// Page routes: serve the three static HTML shells. Each loads its own module
// and the shared CSS/JS. API routes are registered first so these never shadow
// them.

import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { config } from '../config.js';
import { error, cookie, requestScheme, SECURITY_HEADERS } from '../lib/http.js';
import { hasUploadAccess, isAdmin, checkUploadLink, issueUploadToken, UPLOAD_COOKIE } from '../lib/auth.js';
import { enforce } from '../lib/ratelimit.js';

const PAGES_DIR = join(import.meta.dir, '..', '..', 'public');

// App pages only load same-origin module scripts and the design-system CSS, plus
// same-origin media for previews. Inline styles (style="..." attributes) need
// 'unsafe-inline' for style-src; there are no inline scripts.
const PAGE_CSP =
	"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'self' blob:; frame-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'";

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

export default function pages(router) {
	// When an upload password is set, an unauthorized visitor gets only the lock
	// page - the upload portal's markup is never served without the cookie.
	router.get('/', ctx => {
		const { req, url, ip, server } = ctx;

		// Magic-link login: ?token=<upload password | quick-access token> grants
		// the upload cookie and redirects to a clean URL (so the token does not
		// linger in the address bar/history). Rate-limited and constant-time so the
		// query string cannot be brute-forced; an invalid token silently falls
		// through to the lock page, revealing nothing.
		if (config.uploadPassword && !hasUploadAccess(req)) {
			const token = url.searchParams.get('token');
			if (token) {
				const limited = enforce('magic-link', ip, 20, 5 * 60 * 1000);
				if (!limited && checkUploadLink(token)) {
					const setCookie = cookie(UPLOAD_COOKIE, issueUploadToken(), {
						maxAge: config.adminSessionTtl, httpOnly: true, sameSite: 'Lax',
						secure: requestScheme(req, url, server) === 'https',
					});
					return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': setCookie, 'Cache-Control': 'no-store' } });
				}
			}
		}

		const file = config.uploadPassword && !hasUploadAccess(req) ? 'lock.html' : 'upload.html';
		return servePage(file, { 'Cache-Control': 'no-store' });
	});
	router.get('/s/:id', () => servePage('view.html'));
	router.get('/mine', () => servePage('myshares.html'));
	// API-key portal: sign in with a key name + token to manage that key's shares.
	router.get('/api', () => servePage('apikey.html'));

	// Admin auth is an explicit two-route flow:
	//   /login - the password form (always available, ungated).
	//   /admin - the dashboard, only for an authenticated admin; anyone else is
	//            redirected to /login (never served the dashboard shell). The
	//            matching /js/admin.js is gated the same way in the static handler,
	//            so the management markup/code never leaves the server unauthorized.
	const redirect = to => new Response(null, { status: 302, headers: { Location: to, 'Cache-Control': 'no-store' } });
	router.get('/login', ({ req }) => (isAdmin(req) ? redirect('/admin') : servePage('login.html', { 'Cache-Control': 'no-store' })));
	router.get('/admin', ({ req }) => (isAdmin(req) ? servePage('admin.html', { 'Cache-Control': 'no-store' }) : redirect('/login')));

	// The web app manifest is templated too, so the PWA/install name follows
	// APP_TITLE. Registered as a route (runs before the static handler) so the
	// {{APP_TITLE}} token is substituted rather than served verbatim.
	router.get('/site.webmanifest', () => {
		const body = renderPage('site.webmanifest');
		if (body === null) return error(404, 'Not found');
		return new Response(body, {
			headers: { 'Content-Type': 'application/manifest+json; charset=utf-8', 'Cache-Control': 'no-cache', ...SECURITY_HEADERS },
		});
	});
}
