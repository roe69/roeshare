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

// M-04: request-count limits (ratelimit.js) and concurrency slots (acquire()
// above) do not bound bytes/second - a client can stay under both by sending
// fewer, larger requests. This is a simple in-memory token bucket (byte-rate
// resets on restart are low severity compared to the SQLite-persisted
// credential/download-count buckets in ratelimit.js, so no persistence here -
// see ratelimit.js's file header) keyed with the exact same `${name}\0${key}`
// convention as acquire()/acquireAll() above, reusing whatever actor/resource
// dimension the caller's neighboring acquire() call already uses for that
// route.
const byteBuckets = new Map(); // `${name}\0${key}` -> { tokens(bytes), last(ms) }
const MAX_BYTE_BUCKETS = 20000; // same rationale as ratelimit.js's MAX_BUCKETS

function reclaimByteBuckets() {
	const over = byteBuckets.size - MAX_BYTE_BUCKETS;
	let n = 0;
	for (const k of byteBuckets.keys()) {
		byteBuckets.delete(k);
		if (++n >= over) break;
	}
}

// Try to spend `cost` bytes of the named+keyed token bucket (capacity
// `capacityBytes`, refilling at `refillBytesPerSec`). Returns null when
// admitted, or a ready-to-return 429 Response (same shape as
// ratelimit.enforce/enforceKey) when the actor currently has no budget left.
//
// A request costing more than the bucket can ever hold is still admitted
// as long as SOME budget is available right now - it just spends the bucket
// into debt (negative tokens), which throttles every subsequent request from
// the same actor/resource until the debt is repaid by refill. This is what
// makes a single very large download/upload still count fully against the
// budget instead of either being rejected forever (if cost were capped to
// capacity and never fit) or passing for free (if cost were capped and
// admitted at zero marginal charge).
export function takeBytes(name, key, cost, capacityBytes, refillBytesPerSec) {
	const k = `${name}\0${key ?? 'global'}`;
	const t = Date.now();
	let b = byteBuckets.get(k);
	if (!b) {
		if (byteBuckets.size >= MAX_BYTE_BUCKETS) reclaimByteBuckets();
		b = { tokens: capacityBytes, last: t };
		byteBuckets.set(k, b);
	} else {
		const elapsedSec = Math.max(0, (t - b.last) / 1000);
		b.tokens = Math.min(capacityBytes, b.tokens + elapsedSec * refillBytesPerSec);
		b.last = t;
	}
	if (b.tokens <= 0) {
		const retryAfter = Math.max(1, Math.ceil((-b.tokens + 1) / refillBytesPerSec));
		return new Response(JSON.stringify({ error: 'Too many requests. Please slow down.', retryAfter }), {
			status: 429,
			headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': String(retryAfter), ...SECURITY_HEADERS },
		});
	}
	b.tokens -= cost;
	return null;
}
