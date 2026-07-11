// In-memory fixed-window rate limiter (no dependency, per-process). Keyed by an
// arbitrary string (typically "<bucket>:<ip>"). Suitable for a single-instance
// self-hosted deployment; for multi-instance you would back this with Redis.
//
// Each call to `hit` records one request and returns whether it is allowed plus
// the seconds until the window resets. Expired buckets are swept periodically.

import { SECURITY_HEADERS } from './http.js';

const buckets = new Map(); // key -> { count, resetAt(ms) }

// Hard ceiling on distinct buckets so a flood of unique keys (e.g. spoofed ids)
// cannot grow the Map without bound and exhaust the heap.
const MAX_BUCKETS = 200000;

// Evict the oldest entries (Map preserves insertion order) down to the
// ceiling. Deliberately does NOT do a full-map expiry scan first - that would
// make every call that creates a new bucket while at/over MAX_BUCKETS pay an
// O(buckets.size) cost, which is exactly the hot path an attacker minting
// unique keys (e.g. a flood of requests against random nonexistent ids) would
// force into a sustained, process-wide slowdown shared by every rate-limited
// route. Expiry is already handled by the periodic sweep below; this only
// needs to do the cheap, bounded part.
function reclaim() {
	const over = buckets.size - MAX_BUCKETS;
	let n = 0;
	for (const k of buckets.keys()) {
		buckets.delete(k);
		if (++n >= over) break;
	}
}

export function hit(key, max, windowMs) {
	const t = Date.now();
	let b = buckets.get(key);
	if (!b || t >= b.resetAt) {
		if (buckets.size >= MAX_BUCKETS) reclaim();
		b = { count: 0, resetAt: t + windowMs };
		buckets.set(key, b);
	}
	b.count++;
	const retryAfter = Math.max(1, Math.ceil((b.resetAt - t) / 1000));
	return { allowed: b.count <= max, retryAfter, remaining: Math.max(0, max - b.count) };
}

// Convenience: enforce a limit for (bucket, ip). Returns null when allowed, or a
// ready-to-return 429 Response when the limit is exceeded.
export function enforce(bucket, ip, max, windowMs) {
	const r = hit(`${bucket}:${ip || 'unknown'}`, max, windowMs);
	if (r.allowed) return null;
	return new Response(JSON.stringify({ error: 'Too many requests. Please slow down.', retryAfter: r.retryAfter }), {
		status: 429,
		headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': String(r.retryAfter), ...SECURITY_HEADERS },
	});
}

// Same as enforce(), but for buckets keyed by a trusted, server-verified
// identity (an API key id, a share id) rather than an attacker-controlled IP.
export function enforceKey(bucket, id, max, windowMs) {
	const r = hit(`${bucket}:${id || 'unknown'}`, max, windowMs);
	if (r.allowed) return null;
	return new Response(JSON.stringify({ error: 'Too many requests. Please slow down.', retryAfter: r.retryAfter }), {
		status: 429,
		headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': String(r.retryAfter), ...SECURITY_HEADERS },
	});
}

// Clear a bucket (e.g. after a successful admin login, to forgive the attempts).
export function reset(bucket, ip) {
	buckets.delete(`${bucket}:${ip || 'unknown'}`);
}

const sweep = setInterval(() => {
	const t = Date.now();
	for (const [k, b] of buckets) if (t >= b.resetAt) buckets.delete(k);
}, 60_000);
sweep.unref?.();
