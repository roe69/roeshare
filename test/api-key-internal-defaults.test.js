// M-07: src/lib/apikeys.js's limitColumns() is the INTERNAL default applied
// when an allow/scope column is omitted from the object passed to
// createApiKey()/updateApiKey(). Before this fix every omitted field defaulted
// to enabled ("?? 1"), so any caller that forgot to pass a scope - or a future
// caller that never goes through routes/admin.js's sanitizeLimits() - would
// silently mint a full-access key instead of a no-permission one.
//
// This does NOT change the admin-facing behavior: routes/admin.js always runs
// admin input through sanitizeLimits() first, which independently defaults an
// omitted field to allowed (1) and hands limitColumns() fully-explicit 0/1
// values either way - see test/api-key-scopes.test.js's "admin UI default"
// test, which keeps asserting that omitting `scopes` from an admin request
// still yields a full-access key. What changes here is only the library's OWN
// fallback, reachable by any caller that skips sanitizeLimits.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
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

const ALL_DISABLED = {
	maxFileSize: null,
	maxShareSize: null,
	maxShares: null,
	maxExpiry: null,
	allowSlug: false,
	allowPassword: false,
	scopes: { create: false, write: false, read: false, delete: false },
};

describe('api key internal scope/limit defaults (M-07)', () => {
	test('createApiKey()/updateApiKey() default every omitted allow/scope field to disabled, not allowed', async () => {
		const dir = freshDataDir('apikey-defaults');
		try {
			const proc = Bun.spawn({
				cmd: [process.execPath, 'run', join(ROOT, 'test', 'fixtures', 'apikey-omitted-scopes-probe.js')],
				cwd: ROOT,
				env: {
					...process.env,
					DATA_DIR: dir,
					SECRET: 'apikey-internal-defaults-test-secret',
					ADMIN_PASSWORD: '',
					UPLOAD_PASSWORD: '',
					BASE_URL: 'http://127.0.0.1:9999',
					TRUST_PROXY: '0',
				},
				stdout: 'pipe',
				stderr: 'pipe',
			});

			const exitCode = await proc.exited;
			const stdout = await new Response(proc.stdout).text();
			const stderr = await new Response(proc.stderr).text();
			expect(exitCode, `probe script failed:\n${stderr}`).toBe(0);

			const { afterCreate, afterUpdate } = JSON.parse(stdout.trim().split('\n').pop());

			// A key created with every scope field omitted must come out with ALL
			// scopes (and allowSlug/allowPassword) disabled.
			expect(afterCreate).toEqual(ALL_DISABLED);

			// Updating a previously full-access key with every field omitted must
			// likewise strip it down to no permissions, not leave/re-grant them.
			expect(afterUpdate).toEqual(ALL_DISABLED);
		} finally {
			cleanupDir(dir);
		}
	});
});
