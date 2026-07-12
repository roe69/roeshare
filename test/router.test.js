// L-02 regression: Router.match() must never let a malformed path segment
// escape as a raw decodeURIComponent() exception - that used to fall through
// to server.js's generic catch-all and come back as an unhelpful 500. It must
// instead surface as a RouterError (status 400) with a message that says
// nothing about the internal decode failure. Also covers the related
// hardening: a decoded param that smuggles in an encoded "/", "\" or NUL byte
// is rejected the same way, since route params are meant to be a single
// opaque segment.

import { test, expect, describe } from 'bun:test';
import { Router, RouterError } from '../src/router.js';

function makeRouter() {
	return new Router().get('/api/shares/:id', () => new Response('ok'));
}

describe('Router malformed segment handling (L-02)', () => {
	const malformed = {
		'lone %': '/api/shares/%',
		'incomplete escape': '/api/shares/%2',
		'encoded slash': '/api/shares/foo%2Fbar',
		'encoded backslash': '/api/shares/foo%5Cbar',
		'encoded NUL': '/api/shares/foo%00bar',
	};

	for (const [name, pathname] of Object.entries(malformed)) {
		test(`${name} -> RouterError(400), not a raw exception`, () => {
			const router = makeRouter();
			expect(() => router.match('GET', pathname)).toThrow(RouterError);
			try {
				router.match('GET', pathname);
			} catch (e) {
				expect(e.status).toBe(400);
				expect(e.message).toBe('Malformed URL encoding');
				// No internals (decodeURIComponent, URIError, stack details) leaked.
				expect(e.message).not.toMatch(/URIError|decodeURIComponent|at matchSegments/i);
			}
		});
	}

	test('well-formed percent-encoded params still decode normally', () => {
		const router = makeRouter();
		const matched = router.match('GET', '/api/shares/hello%20world');
		expect(matched).not.toBeNull();
		expect(matched.params.id).toBe('hello world');
	});

	test('a plain, non-percent-encoded param is unaffected', () => {
		const router = makeRouter();
		const matched = router.match('GET', '/api/shares/abc123');
		expect(matched.params.id).toBe('abc123');
	});

	test('malformed encoding confined to a literal (non-param) segment does not throw', () => {
		// Literal route segments are compared raw, never decoded, so this must
		// behave exactly as before this fix: no match, no throw.
		const router = new Router().get('/health', () => new Response('ok'));
		expect(router.match('GET', '/health%')).toBeNull();
	});
});
