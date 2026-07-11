// F-20: coverage gate for the central endpoint-policy registry (see
// src/lib/routePolicy.js). Unlike every other test in this repo, this one
// imports the app's route modules directly IN-PROCESS (not via a spawned
// child server) - all it needs is the registered route table and the
// declared-policy registry, neither of which requires an HTTP listener.
// DATA_DIR/SECRET/ADMIN_PASSWORD are set (to a throwaway temp dir) BEFORE the
// dynamic import below, since src/config.js and src/db.js read the
// environment and create their data directory/db file as a side effect of
// being imported - exactly why every other test in this repo boots a real
// child process against its own fresh dir instead of importing src/ code
// into the shared test-runner process.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'roeshare-route-policy-'));
process.env.DATA_DIR = dir;
process.env.SECRET = 'route-policy-test-secret';
process.env.ADMIN_PASSWORD = 'RoutePolicyTest-Pw-2026';
process.env.UPLOAD_PASSWORD = '';
process.env.BASE_URL = 'http://127.0.0.1:9999';
process.env.TRUST_PROXY = '0';

const { Router } = await import('../src/router.js');
const { registerRoutes } = await import('../src/routes/index.js');
const { allPolicies } = await import('../src/lib/routePolicy.js');

const router = registerRoutes(new Router());
const policies = allPolicies();

// (2) inScope predicate, exactly as specified: every /api/v1/* route, every
// non-GET /api/admin/* route, and the three retrieval routes from
// routes/download.js.
const EXTRA_IN_SCOPE = new Set([
	'GET /api/shares/:id/files/:fileId/preview',
	'GET /api/shares/:id/files/:fileId/download',
	'GET /api/shares/:id/download-all',
]);

function inScope(route) {
	if (route.pattern.startsWith('/api/v1/')) return true;
	if (route.pattern.startsWith('/api/admin/') && route.method !== 'GET') return true;
	return EXTRA_IN_SCOPE.has(`${route.method} ${route.pattern}`);
}

describe('F-20 route policy coverage gate', () => {
	test('every in-scope registered route has a declared policy', () => {
		const missing = [];
		for (const route of router.routes) {
			if (!inScope(route)) continue;
			const key = `${route.method} ${route.pattern}`;
			if (!policies.has(key)) missing.push(key);
		}
		expect(missing).toEqual([]);
	});

	test('every declared policy corresponds to a registered route (no stale/typo declarations)', () => {
		const registered = new Set(router.routes.map(r => `${r.method} ${r.pattern}`));
		const stale = [];
		for (const key of policies.keys()) {
			if (!registered.has(key)) stale.push(key);
		}
		expect(stale).toEqual([]);
	});

	test('sanity: at least the known in-scope routes are present and declared', () => {
		// Guards against inScope()/the route table silently matching nothing (which
		// would make the two tests above vacuously pass).
		const inScopeCount = router.routes.filter(inScope).length;
		expect(inScopeCount).toBeGreaterThan(20);
		expect(policies.get('POST /api/v1/upload')).toEqual({ auth: 'apiKeyOrSession', csrf: true, rateLimit: 'api-upload', audit: 'share.created' });
		expect(policies.get('PATCH /api/admin/shares/:id')).toBeDefined();
		expect(policies.get('GET /api/shares/:id/files/:fileId/download')).toBeDefined();
	});
});

process.on('exit', () => {
	try {
		rmSync(dir, { recursive: true, force: true });
	} catch {}
});
