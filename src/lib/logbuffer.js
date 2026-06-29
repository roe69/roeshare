// In-memory ring buffer that TEES console output so the admin panel can show
// recent process logs. The original console methods still write to
// stdout/stderr, so `docker logs` is unchanged. Double-bounded (line count AND
// total bytes, with a per-line cap) so a log flood can never exhaust the heap.
// In-process only: the buffer resets on restart (docker logs stays the durable
// record). Imported first (in server.js and config.js) so it captures the very
// first boot lines, including config.js's own warnings.

import { inspect } from 'node:util';

const MAX_LINES = 1000;
const MAX_BYTES = 2 * 1024 * 1024; // ~2 MB second bound
const MAX_MSG = 8 * 1024; // truncate any single rendered line

const buffer = []; // { ts, level, msg } oldest-first
let bytes = 0;

// Values to scrub from emitted lines. The app should never log a secret, but
// this is defense-in-depth: config.js registers SECRET and the passwords here.
const secrets = new Set();
export function addSecret(value) {
	// Floor avoids redacting ubiquitous 1-3 char tokens; low enough to still
	// catch a short admin/upload password set via the panel.
	if (typeof value === 'string' && value.length >= 4) secrets.add(value);
}

function redact(s) {
	if (!secrets.size) return s;
	for (const sec of secrets) if (s.includes(sec)) s = s.split(sec).join('[redacted]');
	return s;
}

function render(args) {
	let out = '';
	for (let i = 0; i < args.length; i++) {
		if (i) out += ' ';
		const a = args[i];
		out += typeof a === 'string' ? a : inspect(a, { depth: 3, breakLength: Infinity });
	}
	return out;
}

function push(level, args) {
	let msg = redact(render(args));
	if (msg.length > MAX_MSG) msg = msg.slice(0, MAX_MSG) + '… [truncated]';
	buffer.push({ ts: Date.now(), level, msg });
	bytes += msg.length;
	while (buffer.length > MAX_LINES || bytes > MAX_BYTES) {
		const old = buffer.shift();
		if (!old) break;
		bytes -= old.msg.length;
	}
}

const LEVELS = { log: 'info', info: 'info', warn: 'warn', error: 'error' };
for (const [method, level] of Object.entries(LEVELS)) {
	const orig = console[method].bind(console);
	console[method] = (...args) => {
		try {
			push(level, args);
		} catch {
			/* logging must never break the app */
		}
		orig(...args);
	};
}

// Most recent `limit` entries, oldest-first (newest-last).
export function getLogs(limit = 300) {
	const n = Number.isFinite(limit) && limit > 0 ? Math.min(Math.trunc(limit), MAX_LINES) : 300;
	return buffer.slice(-n);
}
