// Page routes: serve the three static HTML shells. Each loads its own module
// and the shared CSS/JS. API routes are registered first so these never shadow
// them.

import { join } from 'node:path';
import { config } from '../config.js';
import { error, cookie, requestScheme, SECURITY_HEADERS } from '../lib/http.js';
import { hasUploadAccess, checkUploadLink, issueUploadToken, UPLOAD_COOKIE } from '../lib/auth.js';
import { enforce } from '../lib/ratelimit.js';

const PAGES_DIR = join(import.meta.dir, '..', '..', 'public');

// App pages only load same-origin module scripts and the design-system CSS, plus
// same-origin media for previews. Inline styles (style="..." attributes) need
// 'unsafe-inline' for style-src; there are no inline scripts.
const PAGE_CSP =
	"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'self' blob:; frame-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'";

export async function servePage(file, extraHeaders) {
	const f = Bun.file(join(PAGES_DIR, file));
	if (!(await f.exists())) return error(404, 'Not found');
	return new Response(f, {
		// Always revalidate HTML so a deploy's new markup is served immediately
		// (the `/` route overrides this with a stronger no-store).
		headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'Content-Security-Policy': PAGE_CSP, ...SECURITY_HEADERS, ...(extraHeaders || {}) },
	});
}

export default function pages(router) {
	// When an upload password is set, an unauthorized visitor gets only the lock
	// page - the upload portal's markup is never served without the cookie.
	router.get('/', ctx => {
		const { req, url, ip } = ctx;

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
						secure: requestScheme(req, url) === 'https',
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
	router.get('/admin', () => servePage('admin.html'));
}
