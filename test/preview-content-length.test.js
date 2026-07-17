// F-XX regression: Bun (1.3.14, this repo's pinned Dockerfile version) drops
// Content-Length and forces chunked framing for any streamed Response body
// over ~255 bytes. That silently broke every embeddable image/gif/mp4
// preview - both the bare-bytes bot path (/s/:id, pages.js) and the
// /preview endpoint itself - since a video player (Discord's inline embed
// included) needs a correct Content-Length/Range contract to render at all.
// servePreview now buffers any response bounded by PREVIEW_BUFFER_CAP
// (download.js) into a Uint8Array instead of streaming it, which keeps the
// header. This locks in that fix for both routes, plain and ranged.
//
// Exercises:
//   - a small gif and a multi-MB mp4, each fetched via the Discordbot-UA
//     bare-bytes path AND the /preview endpoint directly: both must carry a
//     Content-Length that matches the delivered byte count, and bytes must
//     be diff-identical to what was uploaded
//   - a Range request against the mp4 returns 206 with BOTH Content-Range
//     and Content-Length, and the correct byte slice

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'PreviewContentLengthTest-Pw-2026';
const DISCORDBOT_UA = 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)';

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
			SECRET: `preview-clen-secret-${port}`,
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

async function makeKey(base) {
	const cookieRes = await fetch(`${base}/api/admin/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Origin: base },
		body: JSON.stringify({ password: ADMIN_PASSWORD }),
	});
	const cookie = cookieRes.headers.get('set-cookie').split(';')[0];
	const res = await fetch(`${base}/api/admin/api-keys`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
		body: JSON.stringify({ name: 'preview-clen-key' }),
	});
	const key = await res.json();
	return { Authorization: `Bearer ${key.token}` };
}

async function upload(base, auth, { filename, mime, bytes, title }) {
	const res = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=${encodeURIComponent(mime)}&title=${encodeURIComponent(title)}`, {
		method: 'POST',
		headers: { ...auth, 'X-Filename': filename },
		body: bytes,
	});
	expect(res.status).toBe(201);
	return res.json();
}

describe('preview Content-Length (Bun chunked-streaming bug fix)', () => {
	test('a small gif and a multi-MB mp4 both carry a matching Content-Length on the bot bare-bytes path and on /preview; bytes are diff-identical', async () => {
		const dir = freshDataDir('preview-clen-basic');
		try {
			const proc = await bootServer(dir, 3775);
			try {
				const base = 'http://127.0.0.1:3775';
				const auth = await makeKey(base);

				const gifBytes = new Uint8Array([71, 73, 70, 56, 57, 97, ...Array.from({ length: 250 }, (_, i) => i % 256)]);
				const gif = await upload(base, auth, { filename: 'g.gif', mime: 'image/gif', bytes: gifBytes, title: 'ClenGif' });

				const mp4Bytes = new Uint8Array(3 * 1024 * 1024);
				crypto.getRandomValues(mp4Bytes.subarray(0, 65536));
				for (let i = 65536; i < mp4Bytes.length; i++) mp4Bytes[i] = mp4Bytes[i % 65536];
				const mp4 = await upload(base, auth, { filename: 'c.mp4', mime: 'video/mp4', bytes: mp4Bytes, title: 'ClenClip' });

				for (const { file, bytes, mime } of [
					{ file: gif, bytes: gifBytes, mime: 'image/gif' },
					{ file: mp4, bytes: mp4Bytes, mime: 'video/mp4' },
				]) {
					// Bot bare-bytes path: GET /s/:id.
					const botRes = await fetch(`${base}/s/${file.id}`, { headers: { 'User-Agent': DISCORDBOT_UA } });
					expect(botRes.status).toBe(200);
					expect(botRes.headers.get('content-type')).toContain(mime);
					expect(botRes.headers.get('content-length')).toBe(String(bytes.length));
					const botBody = new Uint8Array(await botRes.arrayBuffer());
					expect(botBody).toEqual(bytes);

					// /preview endpoint directly.
					const prevRes = await fetch(`${base}/api/shares/${file.id}/files/${file.fileId}/preview`);
					expect(prevRes.status).toBe(200);
					expect(prevRes.headers.get('content-length')).toBe(String(bytes.length));
					const prevBody = new Uint8Array(await prevRes.arrayBuffer());
					expect(prevBody).toEqual(bytes);
				}
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('a Range request against a multi-MB mp4 returns 206 with both Content-Range and Content-Length, and the correct byte slice', async () => {
		const dir = freshDataDir('preview-clen-range');
		try {
			const proc = await bootServer(dir, 3776);
			try {
				const base = 'http://127.0.0.1:3776';
				const auth = await makeKey(base);

				const mp4Bytes = new Uint8Array(3 * 1024 * 1024);
				crypto.getRandomValues(mp4Bytes.subarray(0, 65536));
				for (let i = 65536; i < mp4Bytes.length; i++) mp4Bytes[i] = mp4Bytes[i % 65536];
				const mp4 = await upload(base, auth, { filename: 'r.mp4', mime: 'video/mp4', bytes: mp4Bytes, title: 'ClenRange' });

				const rangeRes = await fetch(`${base}/api/shares/${mp4.id}/files/${mp4.fileId}/preview`, {
					headers: { Range: 'bytes=0-1023' },
				});
				expect(rangeRes.status).toBe(206);
				expect(rangeRes.headers.get('content-range')).toBe(`bytes 0-1023/${mp4Bytes.length}`);
				expect(rangeRes.headers.get('content-length')).toBe('1024');
				const rangeBody = new Uint8Array(await rangeRes.arrayBuffer());
				expect(rangeBody).toEqual(mp4Bytes.slice(0, 1024));

				// Same, through the bot bare-bytes path (/s/:id).
				const botRangeRes = await fetch(`${base}/s/${mp4.id}`, {
					headers: { 'User-Agent': DISCORDBOT_UA, Range: 'bytes=0-1023' },
				});
				expect(botRangeRes.status).toBe(206);
				expect(botRangeRes.headers.get('content-range')).toBe(`bytes 0-1023/${mp4Bytes.length}`);
				expect(botRangeRes.headers.get('content-length')).toBe('1024');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
