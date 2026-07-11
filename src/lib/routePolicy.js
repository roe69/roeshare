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
// FOLLOW-UP (not implemented in this batch): src/routes/shares.js,
// src/routes/uploads.js, and src/routes/pages.js have no declarations yet and
// are outside test/route-policy.test.js's inScope() predicate. Extending
// coverage to them needs zero changes to this mechanism - only new
// declareRoutePolicy(...) lines in those files and a widened inScope()
// predicate in the test.

const AUTH_MODES = new Set([
	'public',           // no credential required to reach the handler
	'admin',            // requires the roeshare_admin cookie (isAdmin())
	'adminIntermediate',// requires the short-lived MFA intermediate cookie only
	'apiKey',           // requires a bearer/X-Api-Key token (verifyApiKey())
	'apiKeyOrSession',  // bearer/X-Api-Key token OR the apikey portal-session cookie
	'shareAccess',       // per-share access token, edit token, or owning API key
	'editTokenOrKey',    // X-Edit-Token header or the owning API key, no session/cookie
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
