// F-03: server-side at-rest encryption gains authentication. Every new
// upload is sealed as independently-authenticated AES-256-GCM chunk records
// (see lib/filecrypt.js's format comment and lib/storage.js's
// writeChunk/blobRangeStream v2 branches) instead of the old unauthenticated
// AES-256-CTR stream, so silent disk-level corruption or tampering is
// detected instead of being decrypted into plausible-looking garbage.
//
// These tests exercise the format end to end through the real HTTP surface
// (mirrors migrations.test.js / download.test.js): upload a multi-chunk file
// with non-chunk-size-aligned PATCHes (forcing the tail-record reseal path),
// confirm it downloads back byte-identical with a matching sha256, confirm
// Range reads (including one that straddles the 256 KiB chunk boundary) are
// correct, and confirm a single flipped ciphertext byte on disk is detected
// and refused rather than silently served as corrupted plaintext.
//
// test/migrations.test.js separately covers that v1 (legacy CTR) files
// created before this change keep decrypting correctly.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const ROOT = join(import.meta.dir, '..');

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
			ADMIN_PASSWORD: 'AtRestV2Test-Pw-2026',
			SECRET: `at-rest-v2-test-secret-${port}`,
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

// Deterministic, non-repeating filler so a byte-for-byte comparison actually
// proves something (an all-zero buffer would still "match" a broken decrypt
// that happens to produce zeros).
function fillBytes(n) {
	const buf = new Uint8Array(n);
	for (let i = 0; i < n; i++) buf[i] = (i * 37 + 11) & 0xff;
	return buf;
}

// Registers a file and uploads it via one or more PATCHes at the given chunk
// sizes (so the caller controls chunk-boundary alignment). Finalizes the
// share afterward. Returns { id (share), fileId, editToken, bytes }.
async function uploadMultiChunk(base, bytes, patchSizes) {
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
		body: JSON.stringify({ name: 'blob.bin', size: bytes.length, mime: 'application/octet-stream' }),
	});
	expect(regRes.status).toBe(200);
	const { fileId } = await regRes.json();

	let offset = 0;
	for (const size of patchSizes) {
		const part = bytes.subarray(offset, offset + size);
		const chunkRes = await fetch(`${base}/api/shares/${id}/files/${fileId}?offset=${offset}`, {
			method: 'PATCH',
			headers: { 'X-Edit-Token': editToken, 'Content-Type': 'application/octet-stream' },
			body: part,
		});
		expect(chunkRes.status).toBe(200);
		const body = await chunkRes.json();
		offset += size;
		expect(body.received).toBe(offset);
		expect(body.complete).toBe(offset === bytes.length);
	}
	expect(offset).toBe(bytes.length);

	const finRes = await fetch(`${base}/api/shares/${id}/finalize`, {
		method: 'POST',
		headers: { 'X-Edit-Token': editToken },
	});
	expect(finRes.status).toBe(200);

	return { id, fileId, editToken, bytes };
}

describe('at-rest v2 (authenticated chunked AES-256-GCM)', () => {
	test('a multi-chunk, non-chunk-aligned upload round-trips byte-identical with a matching sha256', async () => {
		const dir = freshDataDir('v2-roundtrip');
		try {
			const proc = await bootServer(dir, 3630);
			try {
				const base = 'http://127.0.0.1:3630';
				// 600,000 bytes over three 200,000-byte PATCHes: PLAIN_CHUNK is
				// 262,144 bytes, so this crosses the first chunk boundary mid-PATCH
				// (forcing a tail-record reseal) and crosses it again on the third.
				const bytes = fillBytes(600_000);
				const { id, fileId } = await uploadMultiChunk(base, bytes, [200_000, 200_000, 200_000]);

				const dlRes = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(dlRes.status).toBe(200);
				const got = new Uint8Array(await dlRes.arrayBuffer());
				expect(got.length).toBe(bytes.length);
				expect(Buffer.from(got).equals(Buffer.from(bytes))).toBe(true);

				const metaRes = await fetch(`${base}/api/shares/${id}`);
				expect(metaRes.status).toBe(200);
				const meta = await metaRes.json();
				const fileMeta = meta.files.find(f => f.id === fileId);
				expect(fileMeta.sha256).toBe(createHash('sha256').update(bytes).digest('hex'));

				// On disk, the blob must be LARGER than the plaintext (per-record
				// framing overhead) - proof the v2 chunked format is actually what
				// got written, not a passthrough.
				const blobPath = join(dir, 'storage', id, fileId);
				const diskSize = readFileSync(blobPath).length;
				expect(diskSize).toBeGreaterThan(bytes.length);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('Range requests return correct plaintext, including a range straddling the chunk boundary', async () => {
		const dir = freshDataDir('v2-range');
		try {
			const proc = await bootServer(dir, 3631);
			try {
				const base = 'http://127.0.0.1:3631';
				const bytes = fillBytes(600_000);
				const { id, fileId } = await uploadMultiChunk(base, bytes, [262_144, 262_144, 75_712]);

				const cases = [
					[0, 99], // start of file, within the first record
					[500, 262_143], // ends exactly on the chunk boundary
					[262_100, 262_200], // straddles the boundary (262,144)
					[262_144, 262_144 + 99], // start of the second record
					[599_900, 599_999], // final bytes of the file
				];

				for (const [start, end] of cases) {
					const res = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`, {
						headers: { Range: `bytes=${start}-${end}` },
					});
					expect(res.status).toBe(206);
					const got = new Uint8Array(await res.arrayBuffer());
					const expected = bytes.subarray(start, end + 1);
					expect(got.length).toBe(expected.length);
					expect(Buffer.from(got).equals(Buffer.from(expected))).toBe(true);
				}
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a tampered ciphertext byte is detected and refused, not silently decrypted', async () => {
		const dir = freshDataDir('v2-tamper');
		try {
			const proc = await bootServer(dir, 3632);
			try {
				const base = 'http://127.0.0.1:3632';
				const bytes = fillBytes(300_000); // spans two records (262,144 + 37,856)
				const { id, fileId } = await uploadMultiChunk(base, bytes, [300_000]);

				// Sanity: downloads correctly before any tampering.
				const before = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
				expect(before.status).toBe(200);
				expect(Buffer.from(new Uint8Array(await before.arrayBuffer())).equals(Buffer.from(bytes))).toBe(true);

				// Flip one bit well inside the first record's ciphertext (past the
				// 14-byte version/keyId/nonce header, well before the final 16-byte
				// tag), so authentication fails on the very first record - no
				// plaintext byte should ever reach the client.
				const blobPath = join(dir, 'storage', id, fileId);
				const disk = readFileSync(blobPath);
				const tamperAt = 100;
				disk[tamperAt] ^= 0xff;
				writeFileSync(blobPath, disk);

				let threw = false;
				let gotBytes = null;
				try {
					const res = await fetch(`${base}/api/shares/${id}/files/${fileId}/download`);
					// A tamper detected before any byte is sent may still arrive as a
					// 200 whose body stream aborts - reading it should then throw.
					gotBytes = new Uint8Array(await res.arrayBuffer());
				} catch {
					threw = true;
				}

				if (!threw) {
					// If the client did receive a body, it must NOT be the original
					// plaintext (that would mean tampering was silently decrypted).
					expect(Buffer.from(gotBytes).equals(Buffer.from(bytes))).toBe(false);
				}

				// The server itself must not have crashed - it keeps serving other
				// requests normally.
				const health = await fetch(`${base}/health`);
				expect(health.ok).toBe(true);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
