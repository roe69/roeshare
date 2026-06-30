// Lifetime stats that survive a share being deleted. Counters live in the
// `metrics` (key/value) and `uploaders` (per-IP) tables and are only ever bumped
// up as events happen (share created, file completed, download counted), so the
// historical totals are never lost when shares are swept, burned, or deleted.

import { db, now } from '../db.js';

const incMetric = db.query('INSERT INTO metrics(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = value + excluded.value');

// Add `n` to a lifetime counter (e.g. bumpMetric('downloads'), bumpMetric('bytes_uploaded', size)).
export function bumpMetric(key, n = 1) {
	if (n) incMetric.run(key, n);
}

const upsertUploader = db.query(`
	INSERT INTO uploaders(ip, shares, bytes, downloads, first_seen, last_seen)
	VALUES ($ip, $shares, $bytes, $downloads, $ts, $ts)
	ON CONFLICT(ip) DO UPDATE SET
		shares = shares + $shares,
		bytes = bytes + $bytes,
		downloads = downloads + $downloads,
		last_seen = $ts
`);

// Add to one uploader's lifetime tally (keyed by IP; null/empty -> 'unknown').
export function bumpUploader(ip, { shares = 0, bytes = 0, downloads = 0 } = {}) {
	upsertUploader.run({ $ip: ip || 'unknown', $shares: shares, $bytes: bytes, $downloads: downloads, $ts: now() });
}

const allMetrics = db.query('SELECT key, value FROM metrics');

// All lifetime totals as a tidy object (zero-filled), for the Overview.
export function lifetimeMetrics() {
	const m = {};
	for (const r of allMetrics.all()) m[r.key] = r.value;
	return {
		shares: m.shares_created || 0,
		files: m.files_uploaded || 0,
		bytes: m.bytes_uploaded || 0,
		downloads: m.downloads || 0,
		views: m.views || 0,
	};
}

const topUploadersQ = db.query(
	`SELECT ip, shares, bytes, downloads, first_seen AS firstSeen, last_seen AS lastSeen
	 FROM uploaders ORDER BY bytes DESC, shares DESC LIMIT ?`,
);

// The biggest lifetime uploaders by total bytes.
export function topUploaders(limit = 8) {
	return topUploadersQ.all(limit);
}
