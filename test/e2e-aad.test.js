// H-1: E2E encryption AAD binding.
//
// Part 1 (unit) exercises public/js/e2e.js's crypto helpers directly - Bun's
// runtime provides the same WebCrypto/btoa/atob globals a browser does, so
// this module is importable as-is, no DOM needed. Covers:
//   (1) a fresh (aadVersion 1) file round-trips through encrypt -> decrypt.
//   (2) a simulated legacy (aadVersion 0, no AAD) file still decrypts via the
//       untouched no-AAD path - proving old E2E shares are unaffected.
//   (3) swapping two same-length aadVersion-1 records (two chunks of the same
//       file, and a 'name' record standing in for a 'chunk' record) now fails
//       to decrypt - proving the fix actually closes the splicing gap.
//   (4) resume-after-refresh: chunks encrypted in two separate "sessions"
//       under the same fileId/aadVersion still assemble and decrypt correctly.
//
// Part 2 (HTTP) boots the real server (mirrors download.test.js) and checks
// the server-side wiring: POST /api/shares/:id/files honors a client-supplied
// id/aadVersion only for an e2e share, rejects a bad id, 409s on an id
// collision, and GET /api/shares/:id echoes aadVersion back per file.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	generateKey, encryptBytes, decryptBytes, decryptFile, encryptString, decryptString,
	recordAad, toB64u, ENC_OVERHEAD, CURRENT_AAD_VERSION,
} from '../public/js/e2e.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

function concatRecords(records) {
	const total = records.reduce((n, r) => n + r.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const r of records) { out.set(r, off); off += r.length; }
	return out;
}

describe('e2e.js: AAD binding (unit)', () => {
	test('a fresh (aadVersion 1) file round-trips through encrypt -> decrypt', async () => {
		const { key } = await generateKey();
		const fileId = toB64u(crypto.getRandomValues(new Uint8Array(16)));
		const chunkSize = 8;
		const plain = enc.encode('the quick brown fox jumps over the lazy dog'); // 44 bytes -> 6 chunks
		const numChunks = Math.ceil(plain.length / chunkSize);

		const records = [];
		for (let i = 0; i < numChunks; i++) {
			const chunk = plain.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, plain.length));
			records.push(await encryptBytes(key, chunk, recordAad('chunk', fileId, i, chunk.length)));
		}
		const cipher = concatRecords(records);

		const roundtrip = await decryptFile(key, cipher, chunkSize, fileId, 1);
		expect(dec.decode(roundtrip)).toBe(dec.decode(plain));

		// The encrypted-filename record round-trips through the same scheme.
		const metaJson = JSON.stringify({ name: 'video.mp4', mime: 'video/mp4', cs: chunkSize });
		const metaCt = await encryptString(key, metaJson, recordAad('name', fileId, 0, enc.encode(metaJson).length));
		const metaPlain = await decryptString(key, metaCt, recordAad('name', fileId, 0, enc.encode(metaJson).length));
		expect(metaPlain).toBe(metaJson);
	});

	test('a simulated legacy (aadVersion 0, no AAD) file still decrypts via the no-AAD path', async () => {
		const { key } = await generateKey();
		const chunkSize = 8;
		const plain = enc.encode('legacy pre-H1 file, no AAD ever bound to its records here');
		const numChunks = Math.ceil(plain.length / chunkSize);

		const records = [];
		for (let i = 0; i < numChunks; i++) {
			const chunk = plain.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, plain.length));
			records.push(await encryptBytes(key, chunk)); // no aad argument at all - exactly what pre-H1 encryptBytes did
		}
		const cipher = concatRecords(records);

		// aadVersion 0 (or omitted) must decrypt this exactly as before.
		const roundtrip = await decryptFile(key, cipher, chunkSize, 'irrelevant-legacy-file-id', 0);
		expect(dec.decode(roundtrip)).toBe(dec.decode(plain));
	});

	test('swapping two same-length aadVersion-1 chunk records now fails to decrypt', async () => {
		const { key } = await generateKey();
		const fileId = toB64u(crypto.getRandomValues(new Uint8Array(16)));
		const chunkSize = 8;
		// Two same-length (8-byte) chunks so the swap is not caught by length alone.
		const chunk0 = enc.encode('AAAAAAAA');
		const chunk1 = enc.encode('BBBBBBBB');

		const rec0 = await encryptBytes(key, chunk0, recordAad('chunk', fileId, 0, chunk0.length));
		const rec1 = await encryptBytes(key, chunk1, recordAad('chunk', fileId, 1, chunk1.length));

		// Splice: put record 1's ciphertext at position 0 and vice versa. Each
		// record is still individually well-formed AES-GCM ciphertext (its own
		// tag still verifies against its own bytes) - only the AAD (which binds
		// chunkIndex) can catch that it is now in the wrong slot.
		const splicedCipher = concatRecords([rec1, rec0]);

		await expect(decryptFile(key, splicedCipher, chunkSize, fileId, 1)).rejects.toThrow();
	});

	test('a "name" record cannot be swapped in for a "chunk" record (purpose binding)', async () => {
		const { key } = await generateKey();
		const fileId = toB64u(crypto.getRandomValues(new Uint8Array(16)));
		const payload = enc.encode('12345678'); // 8 bytes, same shape as a chunk record's plaintext

		// Sealed as a 'name' record (chunkIndex fixed at 0, per the design).
		const asName = await encryptBytes(key, payload, recordAad('name', fileId, 0, payload.length));

		// Attempting to open it as chunk 0 of the same file must fail: the AAD
		// (purpose='chunk' vs the 'name' it was actually sealed under) does not match.
		await expect(decryptBytes(key, asName, recordAad('chunk', fileId, 0, payload.length))).rejects.toThrow();

		// It does still open correctly under the AAD it was actually sealed with.
		const opened = await decryptBytes(key, asName, recordAad('name', fileId, 0, payload.length));
		expect(dec.decode(opened)).toBe(dec.decode(payload));
	});

	test('a record cannot be spliced in from a different file under the same key', async () => {
		const { key } = await generateKey();
		const fileA = toB64u(crypto.getRandomValues(new Uint8Array(16)));
		const fileB = toB64u(crypto.getRandomValues(new Uint8Array(16)));
		const chunk = enc.encode('shared-key cross-file splice attempt');

		const recA = await encryptBytes(key, chunk, recordAad('chunk', fileA, 0, chunk.length));

		// Same key, same chunkIndex, same plaintext length - only fileId differs.
		await expect(decryptBytes(key, recA, recordAad('chunk', fileB, 0, chunk.length))).rejects.toThrow();
	});

	test('resume-after-refresh: chunks encrypted across two sessions still assemble and decrypt', async () => {
		const { key } = await generateKey();
		const fileId = toB64u(crypto.getRandomValues(new Uint8Array(16)));
		const chunkSize = 8;
		const plain = enc.encode('resume-after-refresh keeps using AAD for the remaining chunks!!');
		const numChunks = Math.ceil(plain.length / chunkSize);
		const splitAt = Math.floor(numChunks / 2); // pretend the tab was refreshed here

		// "First session": encrypt and upload chunks [0, splitAt).
		const firstHalf = [];
		for (let i = 0; i < splitAt; i++) {
			const c = plain.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, plain.length));
			firstHalf.push(await encryptBytes(key, c, recordAad('chunk', fileId, i, c.length)));
		}

		// "Second session" (after a refresh): a fresh key import (simulated by
		// reusing the same CryptoKey object here - importKey/exportKey round-trip
		// is covered separately by generateKey/importKey), continuing from the
		// server-reported offset with the SAME fileId/aadVersion the file was
		// registered under - never guessed, always carried from server metadata
		// (see startResume in upload.js).
		const secondHalf = [];
		for (let i = splitAt; i < numChunks; i++) {
			const c = plain.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, plain.length));
			secondHalf.push(await encryptBytes(key, c, recordAad('chunk', fileId, i, c.length)));
		}

		const cipher = concatRecords([...firstHalf, ...secondHalf]);
		const roundtrip = await decryptFile(key, cipher, chunkSize, fileId, 1);
		expect(dec.decode(roundtrip)).toBe(dec.decode(plain));
	});

	test('CURRENT_AAD_VERSION is 1', () => {
		expect(CURRENT_AAD_VERSION).toBe(1);
	});
});

// ---- Part 2: server-side registration wiring (HTTP) ------------------------

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
			ADMIN_PASSWORD: 'E2eAadTest-Pw-2026',
			SECRET: `e2e-aad-test-secret-${port}`,
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

async function createShare(base, body) {
	const res = await fetch(`${base}/api/shares`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
	});
	expect(res.status).toBe(201);
	return res.json();
}

describe('POST /api/shares/:id/files: client-supplied id/aadVersion (H-1)', () => {
	test('an e2e share honors a client-supplied id + aadVersion, and GET echoes aadVersion back', async () => {
		const dir = freshDataDir('e2e-aad-reg');
		try {
			const proc = await bootServer(dir, 3598);
			try {
				const base = 'http://127.0.0.1:3598';
				const { id, editToken } = await createShare(base, { e2e: true });

				const clientId = toB64u(crypto.getRandomValues(new Uint8Array(16)));
				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'ZW5jcnlwdGVkLW5hbWU', size: 100, mime: 'application/octet-stream', id: clientId, aadVersion: 1 }),
				});
				expect(regRes.status).toBe(200);
				const reg = await regRes.json();
				expect(reg.fileId).toBe(clientId); // server used the client-supplied id verbatim

				// A second file on the same share, registered the old way (no id/aadVersion).
				const reg2Res = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'other.bin', size: 10, mime: 'application/octet-stream' }),
				});
				expect(reg2Res.status).toBe(200);
				const reg2 = await reg2Res.json();
				expect(reg2.fileId).not.toBe(clientId);

				const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				expect(metaRes.status).toBe(200);
				const meta = await metaRes.json();
				const f1 = meta.files.find(f => f.id === clientId);
				const f2 = meta.files.find(f => f.id === reg2.fileId);
				expect(f1.aadVersion).toBe(1);
				expect(f2.aadVersion).toBe(0); // old-style registration stays on the legacy scheme
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a duplicate client-supplied id is rejected with 409', async () => {
		const dir = freshDataDir('e2e-aad-collision');
		try {
			const proc = await bootServer(dir, 3599);
			try {
				const base = 'http://127.0.0.1:3599';
				const { id, editToken } = await createShare(base, { e2e: true });
				const clientId = toB64u(crypto.getRandomValues(new Uint8Array(16)));

				const first = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'a.bin', size: 10, mime: 'application/octet-stream', id: clientId, aadVersion: 1 }),
				});
				expect(first.status).toBe(200);

				const second = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'b.bin', size: 10, mime: 'application/octet-stream', id: clientId, aadVersion: 1 }),
				});
				expect(second.status).toBe(409);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a malformed client-supplied id is rejected with 400', async () => {
		const dir = freshDataDir('e2e-aad-badid');
		try {
			const proc = await bootServer(dir, 3600);
			try {
				const base = 'http://127.0.0.1:3600';
				const { id, editToken } = await createShare(base, { e2e: true });

				const res = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'a.bin', size: 10, mime: 'application/octet-stream', id: 'not/a valid id!', aadVersion: 1 }),
				});
				expect(res.status).toBe(400);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a non-e2e share ignores a client-supplied id and stays on aadVersion 0', async () => {
		const dir = freshDataDir('e2e-aad-non-e2e');
		try {
			const proc = await bootServer(dir, 3601);
			try {
				const base = 'http://127.0.0.1:3601';
				const { id, editToken } = await createShare(base, { e2e: false });
				const clientId = toB64u(crypto.getRandomValues(new Uint8Array(16)));

				const regRes = await fetch(`${base}/api/shares/${id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': editToken },
					body: JSON.stringify({ name: 'plain.bin', size: 10, mime: 'application/octet-stream', id: clientId, aadVersion: 1 }),
				});
				expect(regRes.status).toBe(200);
				const reg = await regRes.json();
				expect(reg.fileId).not.toBe(clientId); // ignored: server minted its own id

				const metaRes = await fetch(`${base}/api/shares/${id}`, { headers: { 'X-Edit-Token': editToken } });
				const meta = await metaRes.json();
				const f = meta.files.find(f => f.id === reg.fileId);
				expect(f.aadVersion).toBe(0);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
