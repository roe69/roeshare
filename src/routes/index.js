// Route registration hub. Each module default-exports a function that takes the
// router and registers its routes. Order does not matter (the router matches on
// segment structure), but pages are registered last so API paths win.

import shares from './shares.js';
import uploads from './uploads.js';
import download from './download.js';
import admin from './admin.js';
import pages from './pages.js';

export function registerRoutes(router) {
	shares(router);
	uploads(router);
	download(router);
	admin(router);
	pages(router);
	return router;
}
