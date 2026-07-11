// Admin-managed settings: the single source of truth for which env keys the
// admin panel may edit, how to validate them, and how to read/apply/write the
// managed file. The file lives in the data volume (${DATA_DIR}/settings.env) and
// is applied OVER process.env at boot for allowlisted keys only - that is the
// one mechanism that makes a panel edit survive a Docker restart (the container
// keeps its compose-injected env and never re-reads the host .env).
//
// SECURITY: the allowlist is enforced on BOTH read (parse drops unknown keys)
// and write (only allowlisted keys are emitted), so a tampered settings.env can
// never inject HOST/PORT/DATA_DIR or a runtime hijack (NODE_OPTIONS, PATH, ...).
// This module imports nothing from config.js to avoid an import cycle.

import { existsSync, readFileSync, writeFileSync, renameSync, chmodSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

// ---- Validation rules (each returns { value } or { error }) ----------------

function intRule(min, max) {
	return raw => {
		const s = String(raw).trim();
		if (s === '') return { error: 'is required' };
		const n = Number(s);
		if (!Number.isInteger(n)) return { error: 'must be a whole number' };
		if (min != null && n < min) return { error: `must be at least ${min}` };
		if (max != null && n > max) return { error: `must be at most ${max}` };
		return { value: String(n) };
	};
}
const boolRule = raw => {
	const t = String(raw).trim().toLowerCase();
	if (!/^(0|1|true|false|yes|no|on|off)$/.test(t)) return { error: 'must be true or false' };
	return { value: /^(1|true|yes|on)$/.test(t) ? '1' : '0' };
};
function strRule(maxLen) {
	return raw => {
		const s = String(raw);
		if (/[\r\n]/.test(s)) return { error: 'must be a single line' };
		if (s.length > maxLen) return { error: `too long (max ${maxLen})` };
		return { value: s };
	};
}
const baseUrlRule = raw => {
	const parts = String(raw).split(',').map(s => s.trim()).filter(Boolean);
	if (!parts.length) return { error: 'at least one URL is required' };
	for (const p of parts) {
		try {
			const u = new URL(p);
			if (u.protocol !== 'http:' && u.protocol !== 'https:') return { error: `must be http(s): ${p}` };
		} catch {
			return { error: `invalid URL: ${p}` };
		}
	}
	return { value: parts.join(',') };
};

// ---- The allowlist (key -> rule + UI metadata) -----------------------------
// `secret` keys are never echoed to the browser; `clearable` keys may be reset
// to the env default; `danger` shows a red warning in the editor.

export const ALLOWLIST = {
	BASE_URL: { rule: baseUrlRule, type: 'text', label: 'Public base URL(s)', help: 'Comma-separate to serve multiple domains; the first is canonical.' },
	TRUST_PROXY: { rule: boolRule, type: 'bool', label: 'Trust reverse proxy', help: 'Honour X-Forwarded-* headers. Only enable behind a trusted proxy.' },
	APP_NAME: { rule: strRule(200), type: 'text', label: 'Brand name', help: 'Colour with <col=RRGGBB> and bold with <b>..</b>, e.g. <col=e4e4ce>Roe<b><col=ff6b35>Share</b>.' },
	MAX_FILE_SIZE: { rule: intRule(0), type: 'int', label: 'Max file size (bytes)' },
	MAX_SHARE_SIZE: { rule: intRule(0), type: 'int', label: 'Max share size (bytes)' },
	MAX_TOTAL_SIZE: { rule: intRule(0), type: 'int', label: 'Max total storage (bytes, 0 = unlimited)' },
	CHUNK_SIZE: { rule: intRule(64 * 1024, 1024 ** 3), type: 'int', label: 'Upload chunk size (bytes)' },
	MAX_FILES_PER_SHARE: { rule: intRule(1), type: 'int', label: 'Max files per share' },
	MAX_PASSWORD_LENGTH: { rule: intRule(8, 65536), type: 'int', label: 'Max password length' },
	DEFAULT_EXPIRY: { rule: intRule(0), type: 'int', label: 'Default expiry (seconds, 0 = never)' },
	SWEEP_INTERVAL: { rule: intRule(60), type: 'int', label: 'Expiry sweep interval (seconds)' },
};
export const ALLOWED_KEYS = Object.keys(ALLOWLIST);

const KEY_RE = /^[A-Z][A-Z0-9_]*$/;
export const settingsPath = dataDir => resolve(dataDir, 'settings.env');

// Parse KEY=VALUE text, dropping blank/comment lines and any key NOT in the
// allowlist. Strips one surrounding quote pair (and unescapes \" \\ in double
// quotes) so APP_NAME containing inline-style HTML round-trips.
export function parseEnv(text) {
	const out = {};
	for (const line of String(text).split(/\r?\n/)) {
		const t = line.trim();
		if (!t || t.startsWith('#')) continue;
		const eq = t.indexOf('=');
		if (eq === -1) continue;
		const key = t.slice(0, eq).trim();
		if (!KEY_RE.test(key) || !(key in ALLOWLIST)) continue; // allowlist on READ
		let val = t.slice(eq + 1).trim();
		if (val.length >= 2 && val[0] === '"' && val.at(-1) === '"') val = val.slice(1, -1).replace(/\\(["\\])/g, '$1');
		else if (val.length >= 2 && val[0] === "'" && val.at(-1) === "'") val = val.slice(1, -1);
		out[key] = val;
	}
	return out;
}

function quote(v) {
	if (v === '' || /[\s"'#=]/.test(v)) return '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
	return v;
}

export function serializeEnv(obj) {
	const lines = [
		'# RoeShare managed settings - written by the admin panel.',
		'# Applied over the environment at boot for allowlisted keys only.',
		'',
	];
	for (const k of ALLOWED_KEYS) if (k in obj) lines.push(`${k}=${quote(String(obj[k]))}`);
	return lines.join('\n') + '\n';
}

// Keys that were provided by the process environment at boot (compose file,
// host env, deploy-time secrets). The environment is the operator's source of
// truth: these keys are locked - the managed file never overrides them and
// the editor refuses to change them - so a panel edit can never shadow a
// deploy-time secret, and rotating one is done where it was set.
export const envManagedKeys = new Set();

// Boot hook: record which allowlisted keys the environment provides, then
// apply the managed file over process.env for the REMAINING allowlisted,
// VALID keys. Called from config.js right after DATA_DIR resolves, before any
// other config is read. Never throws; an invalid value is skipped with a
// warning.
export function applyManagedSettings(dataDir) {
	for (const key of ALLOWED_KEYS) if (key in process.env) envManagedKeys.add(key);
	const path = settingsPath(dataDir);
	if (!existsSync(path)) return {};
	let raw;
	try {
		raw = parseEnv(readFileSync(path, 'utf8'));
	} catch (e) {
		console.warn(`  WARNING: could not read ${path}: ${e.message}`);
		return {};
	}
	const applied = {};
	for (const key of ALLOWED_KEYS) {
		if (!(key in raw)) continue;
		if (envManagedKeys.has(key)) {
			console.warn(`  NOTE: managed ${key} ignored - the environment sets it, and the environment wins`);
			continue;
		}
		const r = ALLOWLIST[key].rule(raw[key]);
		if (r.error) {
			console.warn(`  WARNING: ignoring managed ${key} (${r.error})`);
			continue;
		}
		process.env[key] = r.value;
		applied[key] = r.value;
	}
	return applied;
}

export function readSettings(dataDir) {
	const path = settingsPath(dataDir);
	if (!existsSync(path)) return {};
	try {
		return parseEnv(readFileSync(path, 'utf8'));
	} catch {
		return {};
	}
}

// Validate a PUT body { values:{KEY:val}, clear:[keys] } into { set, clear } or
// { error }. Blank secret = leave unchanged; env-managed keys are rejected
// outright (the environment wins).
export function validatePatch(body) {
	if (!body || typeof body !== 'object') return { error: 'Body must be an object' };
	const values = body.values && typeof body.values === 'object' ? body.values : {};
	const clearReq = Array.isArray(body.clear) ? body.clear : [];
	const set = {};
	for (const [key, val] of Object.entries(values)) {
		const spec = ALLOWLIST[key];
		if (!spec) continue; // drop non-allowlisted
		if (val == null) continue;
		if (typeof val !== 'string') return { error: `${spec.label} must be text` };
		if (spec.secret && val === '') continue; // blank secret = leave unchanged
		if (envManagedKeys.has(key)) return { error: `${spec.label} is set by the server environment and cannot be changed here` };
		const r = spec.rule(val);
		if (r.error) return { error: `${spec.label}: ${r.error}` };
		set[key] = r.value;
	}
	const clear = [];
	for (const key of clearReq) {
		const spec = ALLOWLIST[key];
		if (!spec) continue;
		if (envManagedKeys.has(key)) return { error: `${spec.label} is set by the server environment and cannot be changed here` };
		if (!spec.clearable) return { error: `${spec.label} cannot be cleared` };
		clear.push(key);
	}
	return { set, clear };
}

// Read-modify-write merge of allowlisted keys, written atomically (temp file +
// rename on the same filesystem) with mode 0600 since it holds secrets.
export function writeSettings(dataDir, { set = {}, clear = [] } = {}) {
	mkdirSync(dataDir, { recursive: true });
	const path = settingsPath(dataDir);
	const current = existsSync(path) ? parseEnv(readFileSync(path, 'utf8')) : {};
	const merged = {};
	for (const k of ALLOWED_KEYS) {
		if (clear.includes(k)) continue;
		// Self-clean stale entries for keys the environment now provides - they
		// would be ignored at boot anyway, and a secret should not linger here.
		if (envManagedKeys.has(k)) continue;
		if (k in set) merged[k] = set[k];
		else if (k in current) merged[k] = current[k];
	}
	const tmp = path + '.tmp';
	writeFileSync(tmp, serializeEnv(merged), { mode: 0o600 });
	try {
		chmodSync(tmp, 0o600);
	} catch {
		/* best effort on platforms without chmod */
	}
	renameSync(tmp, path);
	return merged;
}
