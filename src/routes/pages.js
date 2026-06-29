// Page routes: serve the three static HTML shells. Each loads its own module
// and the shared CSS/JS. API routes are registered first so these never shadow
// them.

import { join } from 'node:path';
import { config } from '../config.js';
import { error, SECURITY_HEADERS } from '../lib/http.js';
import { hasUploadAccess } from '../lib/auth.js';

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
		headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': PAGE_CSP, ...SECURITY_HEADERS, ...(extraHeaders || {}) },
	});
}

export default function pages(router) {
	// When an upload password is set, an unauthorized visitor gets only the lock
	// page - the upload portal's markup is never served without the cookie.
	router.get('/', ctx => {
		const file = config.uploadPassword && !hasUploadAccess(ctx.req) ? 'lock.html' : 'upload.html';
		return servePage(file, { 'Cache-Control': 'no-store' });
	});
	router.get('/s/:id', () => servePage('view.html'));
	router.get('/admin', () => servePage('admin.html'));
}
