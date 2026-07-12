// L-1 regression: a plain `OBJ[userControlledKey]` bracket lookup resolves a
// key like "__proto__" to Object.prototype - a truthy value with none of the
// shape the code downstream expects - instead of undefined. Two call sites hit
// this with attacker-reachable keys:
//
//   1. lib/settings.js's validatePatch(): PUT /api/admin/settings walks
//      Object.entries(body.values) / body.clear, both fully client-controlled
//      keys, and used to do `const spec = ALLOWLIST[key]; if (!spec) continue;`
//      - Object.prototype is truthy so this fell through to `spec.rule(val)` /
//      `spec.clearable`, throwing (spec.rule is not a function) and turning
//      an unrecognized key into a 500 instead of the intended silent drop /
//      "cannot be cleared" error.
//
//   2. routes/admin.js's GET /api/admin/shares: `SORT_COLUMNS[query.get('sort')]
//      || SORT_COLUMNS.created` - Object.prototype is truthy, so `|| default`
//      never kicks in, and the object gets interpolated into a raw SQL
//      `ORDER BY [object Object] ...` string, a syntax error (500).
//
// Both are admin-authenticated only (availability nuisance, not a security
// bypass), but must fail clean (400/default fallback), never 500. Fixed via
// Object.hasOwn() at both sites so a prototype-chain key is never mistaken
// for an allowlisted one.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validatePatch, ALLOWLIST } from '../src/lib/settings.js';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'ProtoPollutionTest-Pw-2026';

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
}

async function bootServer(dataDir, port) {
	const proc = Bun.spawn({
		cmd: [process.execPath, 'run', 'src/server.js'],
		cwd: ROOT,
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(port),
			DATA_DIR: dataDir,
			ADMIN_PASSWORD,
			SECRET: `proto-pollution-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			BASE_URL: `http://127.0.0.1:${port}`,
		},
		stdout: 'pipe',
		stderr: 'pipe',
	});

	const deadline = Date.now() + 10_000;
	let lastErr;
	while (Date.now() < deadline) {
		if (proc.exitCode !== null) break;
		try {
			const r = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(500) });
			if (r.ok) return proc;
		} catch (e) {
			lastErr = e;
		}
		await new Promise(r => setTimeout(r, 150));
	}

	const stderr = await new Response(proc.stderr).text();
	proc.kill();
	throw new Error(`server on port ${port} never became healthy (last error: ${lastErr})\n--- stderr ---\n${stderr}`);
}

async function stopServer(proc) {
	try {
		proc.kill();
		await Promise.race([proc.exited, new Promise(r => setTimeout(r, 3000))]);
	} catch {}
}

function cleanupDir(dir) {
	for (let attempt = 0; attempt < 10; attempt++) {
		try {
			rmSync(dir, { recursive: true, force: true });
			return;
		} catch (e) {
			if (attempt === 9) throw e;
			Bun.sleepSync(200);
		}
	}
}

async function adminCookie(base) {
	const res = await fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	if (res.status !== 200) throw new Error(`admin login failed: ${res.status} ${await res.text()}`);
	return res.headers.get('set-cookie').split(';')[0];
}

describe('L-1: __proto__ as an admin lookup key never resolves to Object.prototype', () => {
	test('validatePatch() drops a "__proto__" values key instead of throwing when spec.rule is missing', () => {
		// Sanity check the premise: a plain bracket lookup on the real ALLOWLIST
		// really does return the (truthy) Object.prototype for this key - proving
		// the bug is real, not just theoretical, before asserting the fixed
		// behavior below.
		expect(ALLOWLIST['__proto__']).toBe(Object.prototype);

		// An unquoted, non-computed `__proto__:` key in a JS object literal sets
		// the object's [[Prototype]] instead of creating an own property, so it
		// would never reach validatePatch()'s `Object.entries(values)` loop in
		// the first place - that's not the real attack (JSON.parse IS the real
		// attack: it makes "__proto__" a genuine own property). Build the values
		// object the same way a real request body does, via JSON.parse, so this
		// test actually exercises the vulnerable lookup.
		const values = JSON.parse('{"__proto__":"evil","APP_NAME":"ok name"}');
		expect(Object.hasOwn(values, '__proto__')).toBe(true);

		const result = validatePatch({ values });
		expect(result.error).toBeUndefined();
		expect(result.set).toEqual({ APP_NAME: 'ok name' });
		expect(Object.hasOwn(result.set, '__proto__')).toBe(false);
	});

	test('validatePatch() rejects a "__proto__" clear key the same way an unknown key is silently dropped, not thrown', () => {
		const result = validatePatch({ clear: ['__proto__'] });
		expect(result.error).toBeUndefined();
		expect(result.clear).toEqual([]);
	});

	test('validatePatch() still rejects a genuinely allowlisted-but-not-clearable key as before (clear path is not just blanket-permissive now)', () => {
		// MAX_FILE_SIZE is real but has no `clearable: true` - this must still
		// produce the intended validation error, proving the hasOwn fix didn't
		// accidentally widen what "clear" accepts.
		const result = validatePatch({ clear: ['MAX_FILE_SIZE'] });
		expect(result.error).toMatch(/cannot be cleared/);
	});

	test('PUT /api/admin/settings with a "__proto__" key returns 200 (silently dropped), never a 500', async () => {
		const dir = freshDataDir('proto-settings');
		const port = 3961;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const cookie = await adminCookie(base);
			const res = await fetch(`${base}/api/admin/settings`, {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
				body: JSON.stringify({ values: { __proto__: { polluted: true } } }),
			});
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.ok).toBe(true);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('GET /api/admin/shares?sort=__proto__ falls back to the default sort instead of a 500 SQL error', async () => {
		const dir = freshDataDir('proto-sort');
		const port = 3962;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const cookie = await adminCookie(base);
			const res = await fetch(`${base}/api/admin/shares?sort=__proto__&order=__proto__`, {
				headers: { Cookie: cookie },
			});
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(Array.isArray(body.shares)).toBe(true);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('GET /api/admin/shares?sort=constructor&order=toString also falls back cleanly (other inherited Object.prototype names, not just __proto__)', async () => {
		const dir = freshDataDir('proto-sort-ctor');
		const port = 3963;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const cookie = await adminCookie(base);
			const res = await fetch(`${base}/api/admin/shares?sort=constructor&order=toString`, {
				headers: { Cookie: cookie },
			});
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(Array.isArray(body.shares)).toBe(true);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});
