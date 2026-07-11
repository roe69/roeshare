// Tiny pattern router. Patterns use ":name" segments and an optional trailing
// "*" wildcard. Handlers receive a single context object:
//
//   { req, url, params, server, ip, query }
//
// and return a Response (or a promise of one). Registration is order-independent
// because matching is exact on the segment structure.

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
			params[seg.slice(1)] = decodeURIComponent(parts[i]);
		} else if (seg !== parts[i]) {
			return null;
		}
	}
	return parts.length === segments.length ? params : null;
}
