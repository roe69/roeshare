// F-20: central endpoint-policy registry. This is a declarative REGISTRY, not a
// routing framework - dispatch (router.js) and in-handler enforcement (the
// auth checks, requireSameOrigin(), enforce()/enforceKey(), audit() calls
// inside each handler) stay exactly as they are, completely unchanged. All
// this module does is let each route file declare, directly above the
// router.<verb>() call it describes, what that handler already does - so a
// reviewer can diff the one-line declaration against the handler body, and
// test/route-policy.test.js can assert every in-scope route has one.
//
// Declarations run when each route module's default-exported function
// executes (i.e. when routes/index.js's registerRoutes() calls it at boot) -
// "module load" in the sense that it happens once, before any request is
// served, not per-request. A duplicate key or a malformed policy throws
// there, so a mistake fails the boot, never silently.
//
// M-02: boot-enforced fail-closed. assertRouteCoverage() (below) is called
// from server.js right after registerRoutes(), before Bun.serve() binds a
// port - a gap between the registered route table and this registry throws
// there too, so the process never starts serving traffic with an undeclared
// in-scope route. test/route-policy.test.js calls the exact same function
// (imported, not reimplemented) as a fast pre-deploy signal, so the test and
// the boot gate can never disagree.

const AUTH_MODES = new Set([
	'public',            // no credential required to reach the handler
	'admin',             // requires the roeshare_admin cookie (isAdmin())
	'adminIntermediate', // requires the short-lived MFA intermediate cookie only
	'apiKey',            // requires a bearer/X-Api-Key token (verifyApiKey())
	'apiKeyOrSession',   // bearer/X-Api-Key token OR the apikey portal-session cookie
	'shareAccess',       // per-share access token, edit token, owning API key, or the per-share owner cookie (M-05)
	'editTokenOrKey',    // X-Edit-Token header, the owning API key, or the per-share owner cookie (M-05) - the header/key paths carry no ambient credential and so need no CSRF proof; the cookie path does (see the handler's ownerVia()/CSRF branch)
	'uploadGate',        // upload password in body OR the upload cookie (hasUploadAccess); public when no UPLOAD_PASSWORD is configured
	'editTokenOrAdmin',  // X-Edit-Token (with keyValidForShare), the per-share owner cookie (M-05), OR the admin cookie
]);

const registry = new Map();

function assertShape(key, policy) {
	if (!policy || typeof policy !== 'object') throw new Error(`declareRoutePolicy(${key}): policy must be an object`);
	if (!AUTH_MODES.has(policy.auth)) throw new Error(`declareRoutePolicy(${key}): invalid auth "${policy.auth}"`);
	if (typeof policy.csrf !== 'boolean') throw new Error(`declareRoutePolicy(${key}): csrf must be a boolean`);
	if (policy.rateLimit !== null && typeof policy.rateLimit !== 'string') throw new Error(`declareRoutePolicy(${key}): rateLimit must be a string or null`);
	if (policy.audit !== null && typeof policy.audit !== 'string') throw new Error(`declareRoutePolicy(${key}): audit must be a string or null`);
}

// Declare the policy for one registered route. `pattern` must be the EXACT
// string passed to the matching router.<verb>() call. Throws on a duplicate
// key (the same method+pattern declared twice) or a malformed policy.
export function declareRoutePolicy(method, pattern, policy) {
	const key = `${String(method).toUpperCase()} ${pattern}`;
	assertShape(key, policy);
	if (registry.has(key)) throw new Error(`declareRoutePolicy: duplicate declaration for ${key}`);
	registry.set(key, policy);
}

// The policy for one route, or undefined if never declared.
export function policyFor(method, pattern) {
	return registry.get(`${String(method).toUpperCase()} ${pattern}`);
}

// The full registry (consumed by test/route-policy.test.js's coverage gate).
export function allPolicies() {
	return registry;
}

// Page routes (src/routes/pages.js): no common prefix worth generalizing, so
// each is listed literally.
const EXTRA_IN_SCOPE = new Set([
	'GET /',
	'GET /s/:id',
	'GET /mine',
	'GET /api',
	'GET /login',
	'GET /admin',
	'GET /site.webmanifest',
]);

// Which registered routes must carry a declared policy. Every route the
// Router actually dispatches to (router.routes) is in scope - GET
// /api/admin/* routes are NOT excluded (a prior version carved them out,
// which meant a new GET /api/admin/* route could boot silently instead of
// throwing when it lacked a declaration - exactly the silent-bypass risk
// M-02 exists to close). The only things exempt from this gate are /health
// and static-asset serving, and they are exempt by CONSTRUCTION, not by a
// predicate here: server.js answers /health and serves public/ before/after
// router.match() ever runs, so neither one is ever a member of router.routes
// in the first place - see test/route-policy.test.js's assertion that
// EVERY registered route is in scope, which would fail the moment this
// function special-cased anything out again.
export function inScope(route) {
	if (route.pattern.startsWith('/api/v1/')) return true;
	if (route.pattern.startsWith('/api/admin/')) return true;
	// shares.js (create/unlock/meta/finalize/delete), uploads.js (register/
	// status/chunk), and download.js (preview/download/download-all) all share
	// this prefix.
	if (route.pattern.startsWith('/api/shares')) return true;
	if (route.pattern.startsWith('/api/upload/')) return true;
	if (route.method === 'GET' && route.pattern === '/api/config') return true;
	return EXTRA_IN_SCOPE.has(`${route.method} ${route.pattern}`);
}

// Boot-time (and test-time) fail-closed coverage gate: every in-scope
// registered route must have a declared policy, and every declared policy
// must correspond to a registered route (no stale/typo declarations). Throws
// an Error listing every offending "METHOD pattern" key so a gap is
// unmissable, rather than returning a boolean a caller could ignore.
export function assertRouteCoverage(routes) {
	const registered = new Set(routes.map(r => `${r.method} ${r.pattern}`));

	const missing = [];
	for (const route of routes) {
		if (!inScope(route)) continue;
		const key = `${route.method} ${route.pattern}`;
		if (!registry.has(key)) missing.push(key);
	}

	const stale = [];
	for (const key of registry.keys()) {
		if (!registered.has(key)) stale.push(key);
	}

	if (missing.length || stale.length) {
		const lines = [
			...missing.map(k => `  missing declaration: ${k}`),
			...stale.map(k => `  stale declaration (no matching route): ${k}`),
		];
		throw new Error(`Route policy coverage gap:\n${lines.join('\n')}`);
	}
}
