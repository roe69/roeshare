// In-memory fixed-window rate limiter (per-process). Keyed by an arbitrary
// string (typically "<bucket>:<ip>"). Suitable for a single-instance
// self-hosted deployment; for multi-instance you would back this with Redis.
//
// Each call to `hit` records one request and returns whether it is allowed plus
// the seconds until the window resets. Expired buckets are swept periodically.
//
// F-08: the in-memory Map alone does not survive a restart (a redeploy wipes
// every counter) and evicts oldest-first under a flood of unique keys (see
// reclaim() below) - for most buckets that is an acceptable, deliberate
// tradeoff (see MAX_BUCKETS' comment), but for the credential brute-force
// buckets it means a restart, or a flood of unrelated keys crowding the Map,
// can silently reset an attacker's login/unlock counter. Those buckets get a
// synchronous SQLite write-through (see PERSIST_PREFIXES) so their state
// survives both. Every other bucket is unchanged: pure in-memory, zero disk
// I/O, zero behavior change.
//
// M-03: the same reset-on-restart problem applies to the request-count
// bucket that gates access to a maxDownloads-limited or password-protected
// share's bytes (preview/download's shared 'dl:<shareId>' bucket) - a restart
// mid-abuse would otherwise hand an attacker a fresh budget against those
// controls too. It is persisted the same way, but is NOT a credential
// bucket (no password/token is checked against it directly) so it is
// deliberately excluded from CREDENTIAL_PREFIXES below and never triggers a
// ratelimit.blocked audit entry - only the request-count signal is made
// durable.
//
// GAP 2 fix: this only matters for a share that is ACTUALLY password-
// protected or max_downloads-limited - those are the only two controls a
// restart could hand an attacker a fresh budget against. routes/download.js
// picks between the persisted 'dl:' bucket and a plain 'dlv:' bucket
// (identical request-count limit, just never written to SQLite - the prefix
// intentionally does not match PERSIST_PREFIXES below) based on the target
// share's password_hash/max_downloads at request time. An ordinary
// public/unlimited share - preview/download's highest-volume,
// unauthenticated, publicly-reachable path - has no restart-survival need,
// so it stays on the original zero-I/O in-memory path instead of paying a
// synchronous SQLite UPSERT on every single request.
//
// The download-all 'zip' bucket does NOT get this protected-vs-unprotected
// split: it is a single unconditional per-IP key regardless of the target
// share, persisted unconditionally too. Splitting it by share protection
// would (a) require resolving the share before enforce() can run, spending a
// SQLite SELECT on every request in exactly the flood scenario the limiter
// exists to reject at zero cost, and (b) hand an attacker a second,
// independent 30/60s allowance by exhausting the bucket against a
// password-protected share they made themselves before moving on to an
// unprotected one. Its cap is already low (30/60s), so the write-amplification
// concern that motivated the conditional split for the much higher-volume
// 'dl:' bucket doesn't apply here.

import { SECURITY_HEADERS } from './http.js';
import { db } from '../db.js';
import { audit } from './audit.js';

// Bucket-key prefixes (the exact strings enforce()/enforceKey() build - see
// routes/admin.js login and login/mfa, routes/api.js /api/v1/login,
// routes/shares.js /api/upload/verify and /api/shares/:id/unlock) that get
// persisted to SQLite in addition to living in memory. Keep in sync with
// those call sites.
const CREDENTIAL_PREFIXES = ['admin-login:', 'apikey-login:', 'upload-verify:', 'unlock:', 'admin-mfa:'];
// M-03: also persist the request-count bucket gating a maxDownloads-limited
// or password-protected share's byte-serving routes (routes/download.js's
// preview/download 'dl:<shareId>' bucket) - see the file-header comment
// above. Only a request against an actually-protected share ever mints a
// 'dl:' key; routes/download.js sends an unprotected share's requests
// through 'dlv:' instead, which deliberately does NOT match here (GAP 2
// fix). The download-all 'zip' bucket is unconditional (no protected/
// unprotected split - see the file-header comment above) and always
// persisted.
const PERSIST_PREFIXES = [...CREDENTIAL_PREFIXES, 'dl:', 'zip:'];
const isPersisted = key => PERSIST_PREFIXES.some(p => key.startsWith(p));

// Persisted (credential brute-force) buckets vs everything else. Splitting
// the map means the cheap oldest-first eviction below (reclaim()) only ever
// discards volatile, non-security-critical buckets - a flood of unique keys
// can no longer reset a login/unlock counter by crowding it out of memory,
// since a persisted bucket's authoritative state also lives in the
// rate_limits table and is reloaded on next use (see hit() below).
const volatile = new Map(); // key -> { count, resetAt(ms) }
const secure = new Map();   // key -> { count, resetAt(ms) }, mirrored to SQLite

// Hard ceilings on distinct buckets so a flood of unique keys (e.g. spoofed
// ids) cannot grow either Map without bound and exhaust the heap.
const MAX_BUCKETS = 200000;
const MAX_SECURE_BUCKETS = 50000;

// Evict the oldest entries (Map preserves insertion order) down to the
// ceiling. Deliberately does NOT do a full-map expiry scan first - that would
// make every call that creates a new bucket while at/over the ceiling pay an
// O(buckets.size) cost, which is exactly the hot path an attacker minting
// unique keys (e.g. a flood of requests against random nonexistent ids) would
// force into a sustained, process-wide slowdown shared by every rate-limited
// route. Expiry is already handled by the periodic sweep below; this only
// needs to do the cheap, bounded part.
function reclaim(map, max) {
	const over = map.size - max;
	let n = 0;
	for (const k of map.keys()) {
		map.delete(k);
		if (++n >= over) break;
	}
}

const selectPersisted = db.query('SELECT count, reset_at FROM rate_limits WHERE key = ?');
const upsertPersisted = db.query(
	'INSERT INTO rate_limits (key, count, reset_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET count = excluded.count, reset_at = excluded.reset_at',
);
const deletePersisted = db.query('DELETE FROM rate_limits WHERE key = ?');
const sweepPersisted = db.query('DELETE FROM rate_limits WHERE reset_at <= ?');

export function hit(key, max, windowMs) {
	const t = Date.now();
	const persisted = isPersisted(key);
	const map = persisted ? secure : volatile;

	let b = map.get(key);
	if (!b || t >= b.resetAt) {
		// For a persisted key, a miss in memory (restart, or evicted from the
		// Map) does not necessarily mean the window is fresh - check SQLite
		// before starting a new window, so a restart mid-window resumes the
		// count instead of silently forgiving the attempts so far.
		if (persisted) {
			const row = selectPersisted.get(key);
			if (row && t < row.reset_at) {
				b = { count: row.count, resetAt: row.reset_at };
				map.set(key, b);
			}
		}
		if (!b || t >= b.resetAt) {
			if (map.size >= (persisted ? MAX_SECURE_BUCKETS : MAX_BUCKETS)) reclaim(map, persisted ? MAX_SECURE_BUCKETS : MAX_BUCKETS);
			b = { count: 0, resetAt: t + windowMs };
			map.set(key, b);
		}
	}
	b.count++;
	if (persisted) upsertPersisted.run(key, b.count, b.resetAt);

	const retryAfter = Math.max(1, Math.ceil((b.resetAt - t) / 1000));
	return { allowed: b.count <= max, retryAfter, remaining: Math.max(0, max - b.count) };
}

// Convenience: enforce a limit for (bucket, ip). Returns null when allowed, or a
// ready-to-return 429 Response when the limit is exceeded.
export function enforce(bucket, ip, max, windowMs) {
	const key = `${bucket}:${ip || 'unknown'}`;
	const r = hit(key, max, windowMs);
	if (r.allowed) return null;
	// ratelimit.blocked is ONLY audited for the credential-brute-force
	// security buckets (CREDENTIAL_PREFIXES) - the password-unlock-threshold
	// signal. Every other bucket - including the persisted-but-not-credential
	// 'dl:'/'zip:' buckets - is deliberately never audited: noise plus
	// attacker-driven write amplification against a bucket that isn't a
	// credential-guessing signal in the first place (a legitimate visitor
	// hammering a hot share's download link is not a security event).
	const prefix = CREDENTIAL_PREFIXES.find(p => key.startsWith(p));
	if (prefix) audit('ratelimit.blocked', { ip, detail: { bucket: prefix.slice(0, -1) } });
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
	const key = `${bucket}:${ip || 'unknown'}`;
	volatile.delete(key);
	secure.delete(key);
	if (isPersisted(key)) deletePersisted.run(key);
}

const sweep = setInterval(() => {
	const t = Date.now();
	for (const [k, b] of volatile) if (t >= b.resetAt) volatile.delete(k);
	for (const [k, b] of secure) if (t >= b.resetAt) secure.delete(k);
	sweepPersisted.run(t);
}, 60_000);
sweep.unref?.();
