// Regression test for the modulepreload hint fix: each page's entry <script
// type="module"> only lets the browser discover its nested import graph
// (shared.js / e2e.js / sidebar.js) AFTER fetching and parsing the entry file
// itself - serializing what could be parallel fetches. Fix: add
// <link rel="modulepreload"> hints for every module the entry script (and its
// static imports, transitively) actually imports, so the browser starts all
// of those fetches from the initial HTML parse instead of discovering them
// one hop at a time.
//
// This only inspects the static files (no server boot needed) - it exists to
// pin: (1) each page hints exactly the modules its real import graph needs,
// no more and no less, (2) lock.html's transitive case (lock.js imports only
// sidebar.js, but sidebar.js itself imports shared.js) hints BOTH files, and
// (3) qrcode.js - deliberately lazy-loaded via a dynamic `await import()' in
// upload.js/view.js/admin.js - is never preload-hinted anywhere, since that
// would defeat the point of lazy-loading it.

import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');

const readHtml = (file) => readFileSync(join(ROOT, 'public', file), 'utf8');

const preloadHints = (html) =>
	[...html.matchAll(/<link\s+rel="modulepreload"\s+href="([^"]+)"\s*\/?>/g)].map((m) => m[1]);

// Expected hint set per page, derived from each entry script's real (static)
// import graph - see public/js/<entry>.js for the imports this encodes.
const EXPECTED = {
	'view.html': ['/js/shared.js', '/js/e2e.js', '/js/sidebar.js'],
	'upload.html': ['/js/shared.js', '/js/e2e.js', '/js/sidebar.js'],
	'myshares.html': ['/js/shared.js', '/js/sidebar.js'],
	'login.html': ['/js/shared.js', '/js/sidebar.js'],
	'apikey.html': ['/js/shared.js', '/js/sidebar.js'],
	'admin.html': ['/js/shared.js', '/js/sidebar.js'],
	// lock.js itself imports only sidebar.js, but sidebar.js imports shared.js -
	// a hint for sidebar.js alone would leave shared.js one hop behind, so both
	// are required here.
	'lock.html': ['/js/shared.js', '/js/sidebar.js'],
	// link-redeem.js has zero imports - no hints needed or expected.
	'link.html': [],
};

describe('modulepreload hints match each page\'s real import graph', () => {
	for (const [file, expected] of Object.entries(EXPECTED)) {
		test(`${file} hints exactly ${JSON.stringify(expected)}`, () => {
			const hints = preloadHints(readHtml(file));
			expect(hints.sort()).toEqual([...expected].sort());
		});
	}

	test('no page ever preload-hints qrcode.js (it is deliberately lazy-loaded)', () => {
		for (const file of Object.keys(EXPECTED)) {
			const hints = preloadHints(readHtml(file));
			expect(hints).not.toContain('/js/qrcode.js');
		}
	});

	test('every modulepreload hint appears before {{BRAND_STYLE}} in <head>', () => {
		for (const file of Object.keys(EXPECTED)) {
			const html = readHtml(file);
			const brandIdx = html.indexOf('{{BRAND_STYLE}}');
			const headEndIdx = html.indexOf('</head>');
			for (const m of html.matchAll(/<link\s+rel="modulepreload"/g)) {
				expect(m.index).toBeLessThan(brandIdx);
				expect(m.index).toBeLessThan(headEndIdx);
			}
		}
	});
});
