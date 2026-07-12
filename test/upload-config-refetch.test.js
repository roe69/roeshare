// Regression test for the redundant /api/config refetch fix: doUpload() used
// to block on a second `await api.get('/api/config')` on every Upload button
// click, stalling the interaction users care most about timing about for a
// full round trip that bought nothing - POST /api/shares's response
// unconditionally carries chunkSize (see src/routes/shares.js's success
// json()) and POST /api/shares/:id/finalize's response unconditionally
// carries url, so the in-doUpload config refetch's only consumers
// (`share.chunkSize || config.chunkSize` and shareUrlFor's `config.baseUrl`
// fallback) were already dead code on every successful upload.
//
// This only inspects the static source (no server/browser boot needed) - it
// exists to pin that the page-load config fetch (loadConfig(), used to seed
// the default-E2E checkbox) stays, while the duplicate fetch inside doUpload()
// never quietly creeps back in.

import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const src = readFileSync(join(ROOT, 'public/js/upload.js'), 'utf8');

describe('upload.js does not refetch /api/config inside doUpload()', () => {
	test('exactly one api.get(\'/api/config\') call in the whole file (loadConfig\'s)', () => {
		const matches = [...src.matchAll(/api\.get\(\s*['"]\/api\/config['"]\s*\)/g)];
		expect(matches.length).toBe(1);
	});

	test('the sole /api/config fetch lives inside loadConfig(), not doUpload()', () => {
		const loadConfigStart = src.indexOf('async function loadConfig()');
		const loadConfigEnd = src.indexOf('\n}', loadConfigStart);
		const doUploadStart = src.indexOf('async function doUpload()');
		const doUploadEnd = src.indexOf('\nasync function', doUploadStart + 1) === -1
			? src.length
			: src.indexOf('\nasync function', doUploadStart + 1);

		expect(loadConfigStart).toBeGreaterThan(-1);
		expect(doUploadStart).toBeGreaterThan(-1);

		const loadConfigBody = src.slice(loadConfigStart, loadConfigEnd);
		const doUploadBody = src.slice(doUploadStart, doUploadEnd);

		expect(loadConfigBody).toMatch(/api\.get\(\s*['"]\/api\/config['"]\s*\)/);
		expect(doUploadBody).not.toMatch(/api\.get\(\s*['"]\/api\/config['"]\s*\)/);
	});
});
