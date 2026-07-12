// Regression tests for three findings that share src/routes/api.js and
// src/routes/uploads.js:
//
//   M-1: sanitizeName was duplicated in both route files and only stripped C0
//        controls + path segments, leaving Unicode bidi-control
//        (U+202A-U+202E, U+2066-U+2069) and zero-width (U+200B-U+200F,
//        U+FEFF) characters intact - enabling RTLO-style extension-spoofing
//        filenames. Fixed by a single shared helper (src/lib/names.js) used
//        by both routes.
//   M-2: POST /api/v1/upload (the one-shot upload path) was the only byte-
//        serving/receiving route with no byte-rate throttle at all.
//   L-2: the chunk-upload PATCH byte-rate bucket was keyed only by share id,
//        so one actor could multiply its effective bandwidth by spreading
//        chunks across several shares it created. Fixed by an additional
//        per-IP bucket on top of the existing per-share one.
//
// The M-1 unit tests exercise src/lib/names.js directly; M-1's end-to-end
// assertion plus M-2 and L-2 boot the real server as a child process (mirrors
// zip-byte-rate.test.js / semaphore.test.js) since byte-rate throttling and
// the Content-Disposition/JSON response surface are HTTP-level behaviors.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sanitizeName } from '../src/lib/names.js';
import { wouldPassBytes, takeBytes } from '../src/lib/semaphore.js';

// ---- M-1: unit tests for the shared sanitizeName helper --------------------

describe('M-1: sanitizeName strips bidi-control and zero-width characters', () => {
	test('an RTLO override character is removed, not just left to visually reverse the name', () => {
		const rtlo = String.fromCodePoint(0x202e); // RIGHT-TO-LEFT OVERRIDE
		const name = 'invoice_' + rtlo + 'txt.exe';
		const out = sanitizeName(name);
		expect(out).toBe('invoice_txt.exe');
		expect([...out].some(c => c.codePointAt(0) === 0x202e)).toBe(false);
	});

	test('every bidi-control and zero-width code point in the finding is stripped', () => {
		const codepoints = [
			0x200b, 0x200c, 0x200d, 0x200e, 0x200f, // ZWSP, ZWNJ, ZWJ, LRM, RLM
			0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // LRE, RLE, PDF, LRO, RLO
			0x2066, 0x2067, 0x2068, 0x2069, // LRI, RLI, FSI, PDI
			0xfeff, // BOM / ZWNBSP
		];
		for (const cp of codepoints) {
			const ch = String.fromCodePoint(cp);
			const out = sanitizeName('a' + ch + 'b.txt');
			expect(out).toBe('ab.txt');
		}
	});

	test('ordinary unicode text (not bidi/zero-width) is left intact', () => {
		expect(sanitizeName('résumé (final) — 日本語.pdf')).toBe('résumé (final) — 日本語.pdf');
	});

	test('path traversal segments are still stripped (pre-existing behavior preserved)', () => {
		expect(sanitizeName('../../etc/passwd')).toBe('etc/passwd');
	});

	test('backslash-separated folder paths still split into a forward-slash relative path', () => {
		const sep = String.fromCharCode(92); // backslash, avoids any escaping ambiguity
		expect(sanitizeName(['folder', 'sub', 'file.txt'].join(sep))).toBe('folder/sub/file.txt');
	});

	test('C0 control characters and DEL are still stripped', () => {
		expect(sanitizeName('a\x00\x1f\x7fb.txt')).toBe('ab.txt');
	});

	test('empty/only-invisible names fall back to "file"', () => {
		const zwsp = String.fromCodePoint(0x200b);
		expect(sanitizeName(zwsp + zwsp)).toBe('file');
		expect(sanitizeName('')).toBe('file');
		expect(sanitizeName(null)).toBe('file');
	});
});

// ---- Shared server-boot helpers (mirrors zip-byte-rate.test.js) -----------

const ROOT = join(import.meta.dir, '..');

function freshDataDir(prefix) {
	return mkdtempSync(join(tmpdir(), `roeshare-${prefix}-`));
}

async function bootServer(dataDir, port, extraEnv = {}) {
	const proc = Bun.spawn({
		cmd: [process.execPath, 'run', 'src/server.js'],
		cwd: ROOT,
		env: {
			...process.env,
			HOST: '127.0.0.1',
			PORT: String(port),
			DATA_DIR: dataDir,
			ADMIN_PASSWORD: 'UploadSecFixes-Pw-2026',
			SECRET: `upload-sec-fixes-secret-${port}`,
			UPLOAD_PASSWORD: '',
			TRUST_PROXY: '0',
			BASE_URL: `http://127.0.0.1:${port}`,
			...extraEnv,
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
		body: JSON.stringify({ password: 'UploadSecFixes-Pw-2026' }),
	});
	expect(res.status).toBe(200);
	return res.headers.get('set-cookie').split(';')[0];
}

async function makeApiKey(base, cookie, name) {
	const res = await fetch(`${base}/api/admin/api-keys`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
		body: JSON.stringify({ name }),
	});
	expect(res.status).toBe(201);
	return res.json();
}

describe('M-1: an RTLO/zero-width filename is sanitized end to end through the resumable-upload registration route', () => {
	test('POST /api/shares/:id/files strips the bidi override before it ever reaches the DB/response', async () => {
		const dir = freshDataDir('m1-uploads-name');
		const port = 3951;
		const proc = await bootServer(dir, port);
		try {
			const base = `http://127.0.0.1:${port}`;
			const createRes = await fetch(`${base}/api/shares`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ e2e: false }),
			});
			expect(createRes.status).toBe(201);
			const { id, editToken } = await createRes.json();

			const rtlo = String.fromCodePoint(0x202e);
			const spoofedName = 'invoice_' + rtlo + 'txt.exe';

			const regRes = await fetch(`${base}/api/shares/${id}/files`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
				body: JSON.stringify({ name: spoofedName, size: 0, mime: 'application/octet-stream' }),
			});
			expect(regRes.status).toBe(200);

			const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
			expect(metaRes.status).toBe(200);
			const meta = await metaRes.json();
			expect(meta.files.length).toBe(1);
			expect(meta.files[0].name).toBe('invoice_txt.exe');
			expect([...meta.files[0].name].some(c => c.codePointAt(0) === 0x202e)).toBe(false);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});

describe('M-2: the one-shot upload path (POST /api/v1/upload) is bound by the byte-rate budget', () => {
	test('a one-shot upload that exceeds the configured byte-rate budget is throttled (429), matching the chunk-upload path', async () => {
		const dir = freshDataDir('m2-oneshot-rate');
		const port = 3952;
		// capacity = uploadBytesPerSec * 4 = 400 bytes, refill = 100 bytes/sec.
		const proc = await bootServer(dir, port, { UPLOAD_BYTES_PER_SEC: '100' });
		try {
			const base = `http://127.0.0.1:${port}`;
			const cookie = await adminCookie(base);
			const key = await makeApiKey(base, cookie, 'm2-oneshot');
			const auth = { Authorization: `Bearer ${key.token}` };

			// 600 bytes is bigger than the 400-byte capacity - the first upload is
			// still admitted (some budget is available right now) but spends the
			// bucket into debt, exactly like a single large download would (see
			// zip-byte-rate.test.js).
			const bytes = new Uint8Array(600);
			for (let i = 0; i < bytes.length; i++) bytes[i] = 65 + (i % 26);

			const first = await fetch(`${base}/api/v1/upload?filename=a.bin`, {
				method: 'POST',
				headers: { ...auth, 'Content-Type': 'application/octet-stream' },
				body: bytes,
			});
			expect(first.status).toBe(201);

			// The bucket is now in debt - an immediate second one-shot upload must
			// be throttled. Before the fix, POST /api/v1/upload never called
			// takeBytes() at all, so this would keep succeeding forever regardless
			// of UPLOAD_BYTES_PER_SEC.
			const second = await fetch(`${base}/api/v1/upload?filename=b.bin`, {
				method: 'POST',
				headers: { ...auth, 'Content-Type': 'application/octet-stream' },
				body: new Uint8Array(10),
			});
			expect(second.status).toBe(429);
			const body = await second.json();
			expect(body.retryAfter).toBeGreaterThan(0);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('a one-shot upload within the byte-rate budget is not throttled', async () => {
		const dir = freshDataDir('m2-oneshot-rate-ok');
		const port = 3953;
		const proc = await bootServer(dir, port, { UPLOAD_BYTES_PER_SEC: '100' }); // capacity 400B
		try {
			const base = `http://127.0.0.1:${port}`;
			const cookie = await adminCookie(base);
			const key = await makeApiKey(base, cookie, 'm2-oneshot-ok');
			const auth = { Authorization: `Bearer ${key.token}` };

			const bytes = new Uint8Array(50); // well under the 400-byte capacity
			const res = await fetch(`${base}/api/v1/upload?filename=a.bin`, {
				method: 'POST',
				headers: { ...auth, 'Content-Type': 'application/octet-stream' },
				body: bytes,
			});
			expect(res.status).toBe(201);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});

describe('L-2: chunk-upload PATCH is also bound by a per-IP byte-rate budget on top of the per-share one', () => {
	test('spreading chunk uploads across two different shares from the same actor does not multiply the byte-rate budget', async () => {
		const dir = freshDataDir('l2-chunk-perip');
		const port = 3954;
		// capacity = uploadBytesPerSec * 4 = 400 bytes, refill = 100 bytes/sec.
		const proc = await bootServer(dir, port, { UPLOAD_BYTES_PER_SEC: '100' });
		try {
			const base = `http://127.0.0.1:${port}`;

			async function makeShareAndRegister(fileSize) {
				const createRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ e2e: false }),
				});
				expect(createRes.status).toBe(201);
				const { id, editToken } = await createRes.json();
				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'f.bin', size: fileSize, mime: 'application/octet-stream' }),
				});
				expect(regRes.status).toBe(200);
				const { fileId } = await regRes.json();
				return { id, editToken, fileId };
			}

			// 600 bytes is bigger than the 400-byte capacity - admitted (some
			// budget is available right now) but spends BOTH the per-share and the
			// per-IP bucket into debt, exactly like the single-large-request
			// pattern in zip-byte-rate.test.js.
			const bytes = new Uint8Array(600);
			for (let i = 0; i < bytes.length; i++) bytes[i] = 65 + (i % 26);

			const shareA = await makeShareAndRegister(600);
			const chunkA = await fetch(`${base}/api/shares/${shareA.id}/files/${shareA.fileId}?offset=0`, {
				method: 'PATCH',
				headers: { 'X-Edit-Token': shareA.editToken, 'Content-Type': 'application/octet-stream' },
				body: bytes,
			});
			expect(chunkA.status).toBe(200);

			// Share B: a brand-new share, so its OWN per-share bucket is still at
			// full 400-byte capacity - even a small chunk would pass a per-share-
			// only check every time (that was the L-2 gap: unlimited effective
			// bandwidth by fanning out across shares). The per-IP bucket, however,
			// is already in debt from share A's spend, so this must now be
			// throttled regardless of how small the chunk is.
			const shareB = await makeShareAndRegister(10);
			const chunkB = await fetch(`${base}/api/shares/${shareB.id}/files/${shareB.fileId}?offset=0`, {
				method: 'PATCH',
				headers: { 'X-Edit-Token': shareB.editToken, 'Content-Type': 'application/octet-stream' },
				body: new Uint8Array(10),
			});
			expect(chunkB.status).toBe(429);
			const body = await chunkB.json();
			expect(body.retryAfter).toBeGreaterThan(0);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});

	test('the existing per-share bucket still throttles repeated chunks on a single share (not weakened by the per-IP addition)', async () => {
		const dir = freshDataDir('l2-chunk-pershare-still-works');
		const port = 3955;
		const proc = await bootServer(dir, port, { UPLOAD_BYTES_PER_SEC: '100' }); // capacity 400B
		try {
			const base = `http://127.0.0.1:${port}`;
			const createRes = await fetch(`${base}/api/shares`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ e2e: false }),
			});
			const { id, editToken } = await createRes.json();
			const regRes = await fetch(`${base}/api/shares/${id}/files`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
				body: JSON.stringify({ name: 'f.bin', size: 1200, mime: 'application/octet-stream' }),
			});
			const { fileId } = await regRes.json();

			const bytes = new Uint8Array(600);
			const first = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=0`, {
				method: 'PATCH',
				headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
				body: bytes,
			});
			expect(first.status).toBe(200); // over capacity but still admitted, spends into debt

			const second = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=600`, {
				method: 'PATCH',
				headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
				body: bytes,
			});
			expect(second.status).toBe(429);
		} finally {
			await stopServer(proc);
			cleanupDir(dir);
		}
	});
});

// ---- L-2 follow-up: a rejected dual-bucket check must not drain the bucket
// that DID have room --------------------------------------------------------
//
// The peek-then-commit pattern in uploads.js's chunk-PATCH handler (added
// after this fix's first pass) checks wouldPassBytes() on both the per-share
// and per-IP buckets before calling the mutating takeBytes() on either - so a
// request rejected by one bucket never permanently charges the other. This
// unit test exercises that invariant directly against semaphore.js, since
// reproducing it via HTTP requires timing a request to land exactly between
// the two takeBytes() calls.
describe('L-2 follow-up: peeking both byte-rate buckets before committing to either', () => {
	test('a bucket that has room is not charged when a sibling check then rejects the request', () => {
		const shareKey = `l2-peek-share-${Math.random()}`;
		const ipKey = `l2-peek-ip-${Math.random()}`;
		const capacity = 400;
		const refill = 100;

		// Drain the IP bucket deep into debt (simulating contention from another
		// share on the same IP), leaving the share bucket untouched/full. Spend
		// more than capacity (a single over-budget request is still admitted
		// once and goes negative, by design - see takeBytes' doc comment) so a
		// few milliseconds of real time passing before the next check can't
		// refill it back above zero and make this test flaky.
		expect(takeBytes('chunk-bytes-ip', ipKey, capacity * 3, capacity, refill)).toBeNull();

		// Old (buggy) order: takeBytes('chunk-bytes', share) would have
		// unconditionally deducted here before ever checking the IP bucket.
		// New order: peek the share bucket (passes, it's full), peek the IP
		// bucket (fails, it's empty) - and reject WITHOUT having called the
		// mutating takeBytes on the share bucket at all.
		const cost = 50;
		expect(wouldPassBytes('chunk-bytes', shareKey, cost, capacity, refill)).toBe(true);
		expect(wouldPassBytes('chunk-bytes-ip', ipKey, cost, capacity, refill)).toBe(false);
		const rejection = takeBytes('chunk-bytes-ip', ipKey, cost, capacity, refill);
		expect(rejection).not.toBeNull();
		expect(rejection.status).toBe(429);

		// The share bucket must still be at full capacity - prove it by
		// successfully taking the ENTIRE capacity from it in one call, which
		// would fail if the rejected request above had already spent 50 of it.
		expect(takeBytes('chunk-bytes', shareKey, capacity, capacity, refill)).toBeNull();
	});
});
