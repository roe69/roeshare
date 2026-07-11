// F-09: byte/concurrency governance beyond simple request-count rate limits.
// Bun is single-threaded, so a plain counter map IS the semaphore - no locking,
// no async, no queueing. Every caller either gets a slot immediately or is
// told to retry (overloaded()); nobody ever waits in line, since a queue would
// itself become a resource-exhaustion vector (unbounded pending requests
// piling up behind a full semaphore).

import { SECURITY_HEADERS } from './http.js';

const counts = new Map(); // `${name}\0${key}` -> live holder count

// Try to take one slot of the named semaphore for `key`. Returns an idempotent
// release() function on success, or null when `limit` slots are already held.
// key may be null/undefined for a global semaphore (normalized to 'global').
export function acquire(name, key, limit) {
	const k = `${name}\0${key ?? 'global'}`;
	const n = counts.get(k) || 0;
	if (n >= limit) return null;
	counts.set(k, n + 1);
	let done = false;
	return function release() {
		if (done) return;
		done = true;
		const m = (counts.get(k) || 1) - 1;
		if (m <= 0) counts.delete(k); else counts.set(k, m);
	};
}

// All-or-nothing acquisition of several [name, key, limit] triples (rolls back
// the ones already taken when a later one is full). Returns a combined
// release() or null.
export function acquireAll(specs) {
	const releases = [];
	for (const [name, key, limit] of specs) {
		const r = acquire(name, key, limit);
		if (!r) { for (const done of releases) done(); return null; }
		releases.push(r);
	}
	let done = false;
	return () => { if (done) return; done = true; for (const r of releases) r(); };
}

// Ready-made 503, mirroring ratelimit.enforce's Response shape.
export function overloaded(retryAfter = 3) {
	return new Response(JSON.stringify({ error: 'Server is busy. Please retry shortly.', retryAfter }), {
		status: 503,
		headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': String(retryAfter), ...SECURITY_HEADERS },
	});
}
