// Guards README.md/CONTRACT.md against the specific staleness found in the
// 2026-07 doc-accuracy sweep: undocumented magic-link + MFA endpoints, missing
// config vars, and the undocumented placeholder-password boot-crash. This is a
// docs-content check, not a behavior test - it just makes sure the docs keep
// mentioning things that actually exist in the code, so a future edit to
// config.js/shares.js/admin.js doesn't silently let the docs drift again
// without at least this test flagging it.

import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dir, '..');
const readme = readFileSync(join(root, 'README.md'), 'utf8');
const contract = readFileSync(join(root, 'CONTRACT.md'), 'utf8');

describe('README.md config table matches src/config.js', () => {
	test('documents the byte-rate limit env vars (src/config.js uploadBytesPerSec/downloadBytesPerSec)', () => {
		expect(readme).toContain('UPLOAD_BYTES_PER_SEC');
		expect(readme).toContain('DOWNLOAD_BYTES_PER_SEC');
	});

	test('documents DEFAULT_KEY_MAX_SHARES (src/config.js defaultKeyMaxShares)', () => {
		expect(readme).toContain('DEFAULT_KEY_MAX_SHARES');
	});

	test('documents the placeholder-ADMIN_PASSWORD boot-crash (src/config.js PLACEHOLDER_PASSWORDS)', () => {
		const adminRow = readme.split('\n').find(l => l.includes('| `ADMIN_PASSWORD` |'));
		expect(adminRow).toBeTruthy();
		expect(adminRow).toMatch(/placeholder/i);
		expect(adminRow).toMatch(/change-me/);
	});

	test('the Quick start example no longer uses a value config.js rejects at boot', () => {
		const quickStartSection = readme.slice(readme.indexOf('## Quick start'), readme.indexOf('## Configuration'));
		expect(quickStartSection).not.toMatch(/ADMIN_PASSWORD:\s*change-me\b/);
	});
});

describe('CONTRACT.md documents the magic-link and admin-MFA endpoints', () => {
	test('magic-link mint + redeem (src/routes/shares.js)', () => {
		expect(contract).toContain('/api/upload/link');
		expect(contract).toContain('/api/upload/link/redeem');
	});

	test('admin login reflects the mfaRequired step-up shape (src/routes/admin.js)', () => {
		expect(contract).toContain('mfaRequired');
	});

	test('admin MFA management endpoints (src/routes/admin.js)', () => {
		for (const path of [
			'/api/admin/login/mfa',
			'/api/admin/mfa',
			'/api/admin/mfa/setup',
			'/api/admin/mfa/confirm',
			'/api/admin/mfa/disable',
			'/api/admin/mfa/backup-codes',
		]) {
			expect(contract).toContain(path);
		}
	});
});
