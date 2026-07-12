// Tiny pattern router. Patterns use ":name" segments and an optional trailing
// "*" wildcard. Handlers receive a single context object:
//
//   { req, url, params, server, ip, query }
//
// and return a Response (or a promise of one). Registration is order-independent
// because matching is exact on the segment structure.

// Thrown when a path segment can't be safely decoded/used as a route param -
// the request is malformed, not merely "no route matched", so callers must
// answer 400 instead of letting it fall through to the generic 500 handler
// or to static-file/slug fallback matching (see server.js's fetch() catch).
export class RouterError extends Error {
	constructor(message) {
		super(message);
		this.status = 400;
	}
}

export class Router {
	constructor() {
		this.routes = [];
	}

	add(method, pattern, handler) {
		const segments = pattern.split('/').filter(Boolean);
		// `pattern` is kept verbatim (not just its parsed segments) so tests can
		// enumerate registered routes by their exact declared pattern string - see
		// lib/routePolicy.js's coverage gate (test/route-policy.test.js).
		this.routes.push({ method: method.toUpperCase(), segments, handler, wildcard: pattern.endsWith('*'), pattern });
		return this;
	}

	get(p, h) {
		return this.add('GET', p, h);
	}
	post(p, h) {
		return this.add('POST', p, h);
	}
	patch(p, h) {
		return this.add('PATCH', p, h);
	}
	put(p, h) {
		return this.add('PUT', p, h);
	}
	delete(p, h) {
		return this.add('DELETE', p, h);
	}

	match(method, pathname) {
		const parts = pathname.split('/').filter(Boolean);
		for (const route of this.routes) {
			if (route.method !== method && !(route.method === 'GET' && method === 'HEAD')) continue;
			const params = matchSegments(route.segments, parts);
			if (params) return { handler: route.handler, params };
		}
		return null;
	}
}

// Decode a single ":param" path segment. Throws RouterError (not the raw
// URIError) on malformed percent-encoding, and also rejects a decoded value
// that contains an encoded "/", "\" or NUL byte - route params are meant to
// be a single opaque segment (ids, filenames, etc.), so a smuggled separator
// or NUL can only be an attempt to confuse downstream path/comparison logic,
// never a legitimate value.
function decodeSegment(raw) {
	let decoded;
	try {
		decoded = decodeURIComponent(raw);
	} catch {
		throw new RouterError('Malformed URL encoding');
	}
	if (decoded.includes('/') || decoded.includes('\\') || decoded.includes('\0')) {
		throw new RouterError('Malformed URL encoding');
	}
	return decoded;
}

function matchSegments(segments, parts) {
	const params = {};
	for (let i = 0; i < segments.length; i++) {
		const seg = segments[i];
		if (seg === '*') {
			params['*'] = parts.slice(i).join('/');
			return params;
		}
		if (i >= parts.length) return null;
		if (seg.startsWith(':')) {
			params[seg.slice(1)] = decodeSegment(parts[i]);
		} else if (seg !== parts[i]) {
			return null;
		}
	}
	return parts.length === segments.length ? params : null;
}
