// Regression test for the render-blocking @import fix: app.css used to
// `@import './tokens.css'`, which forces a *sequential* fetch on every page
// load - the browser can't discover/request tokens.css until it has fetched
// AND begun parsing app.css, adding a full extra round-trip to first paint.
// Fix: drop the @import, and instead link tokens.css directly in every HTML
// shell's <head>, immediately before app.css's own <link>, so both stylesheets
// are discovered from the initial HTML parse and fetch in parallel.
//
// This only inspects the static files (no server boot needed) - it exists to
// pin two things: (1) the @import can never quietly creep back into app.css,
// and (2) every HTML shell keeps linking tokens.css before app.css in the
// right order.

import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');

const HTML_FILES = [
	'admin.html',
	'apikey.html',
	'link.html',
	'lock.html',
	'login.html',
	'myshares.html',
	'upload.html',
	'view.html',
];

describe('CSS parallel-fetch (no sequential @import)', () => {
	test('app.css never re-imports tokens.css', () => {
		const css = readFileSync(join(ROOT, 'public/css/app.css'), 'utf8');
		// Match an actual @import rule (@import followed by a url(...) or a
		// quoted string), not the word "@import" as it appears prose-style in
		// the warning comment at the top of the file.
		expect(css).not.toMatch(/@import\s+(url\(|['"])/i);
	});

	for (const file of HTML_FILES) {
		test(`${file} links tokens.css before app.css`, () => {
			const html = readFileSync(join(ROOT, 'public', file), 'utf8');
			const tokensIdx = html.indexOf('/css/tokens.css');
			const appIdx = html.indexOf('/css/app.css');
			expect(tokensIdx).toBeGreaterThan(-1);
			expect(appIdx).toBeGreaterThan(-1);
			expect(tokensIdx).toBeLessThan(appIdx);
		});
	}
});
