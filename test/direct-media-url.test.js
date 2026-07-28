// Direct-media share URLs: /<id>.<ext> (and /s/<id>.<ext>) serve the share's
// own bytes to EVERY caller - no User-Agent branching - so a chat app's media
// proxy can read the format off the extension (an animated GIF unfurled from
// an extensionless URL comes back from Discord's proxy as a static first
// frame; from a .gif URL it comes back animated) and so a CDN that ignores
// `Vary: User-Agent` can safely cache the one representation that exists.
//
// Exercises:
//   - the one-shot upload's returned `url` carries the extension for an
//     embeddable image/video share and stays extensionless for anything else
//   - /<id>.<ext> and /s/<id>.<ext> return bytes identical to /preview, to a
//     browser UA and a crawler UA alike, with no Vary and a cacheable
//     Cache-Control
//   - the extension must match a file the share actually has: a wrong-type
//     extension, a non-media share, a password/one-time/capped/E2E share and
//     an unknown id all answer with ONE byte-identical, no-store 404
//   - a non-media extension is not treated as a share lookup at all
//   - Range and HEAD still work (the video player's contract)
//   - the extensionless URL's existing behaviour is completely unchanged

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'DirectMediaTest-Pw-2026';
const DISCORDBOT_UA = 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)';
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';

// A real (tiny) animated GIF: two 1x1 frames. Content does not matter to any
// assertion here, but keeping it a valid GIF keeps the fixture honest.
const GIF_BYTES = new Uint8Array([
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
	0xff, 0x0b, 0x4e, 0x45, 0x54, 0x53, 0x43, 0x41, 0x50, 0x45, 0x32, 0x2e, 0x30, 0x03, 0x01, 0x00, 0x00, 0x00, 0x21, 0xf9,
	0x04, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01,
	0x00, 0x21, 0xf9, 0x04, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02,
	0x02, 0x44, 0x01, 0x00, 0x3b,
]);
const MP4_BYTES = new Uint8Array(2048).fill(7);

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
			SECRET: `direct-media-secret-${port}`,
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
	expect(res.status).toBe(200);
	return res.headers.get('set-cookie').split(';')[0];
}

async function makeKey(base, cookie, name) {
	const res = await fetch(`${base}/api/admin/api-keys`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: base },
		body: JSON.stringify({ name }),
	});
	expect(res.status).toBe(201);
	return res.json();
}

// One-shot upload helper: `query` carries any extra share options, `headers`
// any extra request headers (the share password is header-only, M-01).
async function upload(base, auth, { mime, filename, body, query = '', headers = {} }) {
	const res = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=${encodeURIComponent(mime)}${query}`, {
		method: 'POST',
		headers: { ...auth, 'X-Filename': filename, ...headers },
		body,
	});
	expect(res.status).toBe(201);
	return res.json();
}

describe('direct-media share URLs', () => {
	test('the API advertises the extensioned link, which serves identical bytes to every UA with no Vary and a cacheable Cache-Control', async () => {
		const dir = freshDataDir('direct-media-serve');
		try {
			const proc = await bootServer(dir, 3778);
			try {
				const base = 'http://127.0.0.1:3778';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'direct-media-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const gif = await upload(base, auth, { mime: 'image/gif', filename: 'anim.gif', body: GIF_BYTES });
				const mp4 = await upload(base, auth, { mime: 'video/mp4', filename: 'clip.mp4', body: MP4_BYTES });
				const txt = await upload(base, auth, { mime: 'text/plain', filename: 'notes.txt', body: new Uint8Array([1, 2]) });

				// The link the caller is told to publish carries the extension for a
				// media share (this is the whole fix - RoeSnip pastes this verbatim)
				// and stays extensionless for anything with nothing to embed.
				expect(gif.url).toBe(`${base}/${gif.id}.gif`);
				expect(mp4.url).toBe(`${base}/${mp4.id}.mp4`);
				expect(txt.url).toBe(`${base}/${txt.id}`);

				const previewBytes = new Uint8Array(await (await fetch(`${base}/api/shares/${gif.id}/files/${gif.fileId}/preview`)).arrayBuffer());

				for (const path of [`/${gif.id}.gif`, `/s/${gif.id}.gif`]) {
					for (const ua of [BROWSER_UA, DISCORDBOT_UA]) {
						const res = await fetch(`${base}${path}`, { headers: { 'User-Agent': ua } });
						expect(res.status).toBe(200);
						expect(res.headers.get('content-type')).toContain('image/gif');
						expect(res.headers.get('content-length')).toBe(String(GIF_BYTES.length));
						expect(res.headers.get('content-disposition')).toContain('inline');
						// The point of this URL shape: ONE representation, so a CDN that
						// ignores Vary: User-Agent cannot hand the wrong one to anybody.
						expect(res.headers.get('vary')).toBe(null);
						expect(res.headers.get('cache-control')).toBe('public, max-age=300');
						expect(new Uint8Array(await res.arrayBuffer())).toEqual(previewBytes);
					}
				}

				// Same for the video, including the Range/HEAD contract a player needs.
				const ranged = await fetch(`${base}/${mp4.id}.mp4`, { headers: { Range: 'bytes=0-99' } });
				expect(ranged.status).toBe(206);
				expect(ranged.headers.get('content-range')).toBe(`bytes 0-99/${MP4_BYTES.length}`);
				expect((await ranged.arrayBuffer()).byteLength).toBe(100);

				const head = await fetch(`${base}/${mp4.id}.mp4`, { method: 'HEAD' });
				expect(head.status).toBe(200);
				expect(head.headers.get('content-type')).toContain('video/mp4');
				expect(head.headers.get('content-length')).toBe(String(MP4_BYTES.length));
				expect(head.headers.get('accept-ranges')).toBe('bytes');

				// The extension is matched case-insensitively (a link pasted through
				// something that upper-cased it still resolves).
				const upper = await fetch(`${base}/${gif.id}.GIF`);
				expect(upper.status).toBe(200);
				expect(upper.headers.get('content-type')).toContain('image/gif');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('every miss - wrong extension, non-media, password/one-time/capped/E2E, unknown id - is one byte-identical no-store 404, and a non-media extension is not a share lookup at all', async () => {
		const dir = freshDataDir('direct-media-misses');
		try {
			const proc = await bootServer(dir, 3779);
			try {
				const base = 'http://127.0.0.1:3779';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'direct-media-miss-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const gif = await upload(base, auth, { mime: 'image/gif', filename: 'a.gif', body: GIF_BYTES });
				const txt = await upload(base, auth, { mime: 'text/plain', filename: 'n.txt', body: new Uint8Array([1]) });
				const pw = await upload(base, auth, {
					mime: 'image/gif',
					filename: 'p.gif',
					body: GIF_BYTES,
					headers: { 'X-Upload-Password': 'hunter2' },
				});
				const oneTime = await upload(base, auth, { mime: 'image/gif', filename: 'o.gif', body: GIF_BYTES, query: '&oneTime=1' });
				const capped = await upload(base, auth, { mime: 'image/gif', filename: 'c.gif', body: GIF_BYTES, query: '&maxDownloads=3' });

				// E2E share (not reachable through the API-key one-shot path).
				const draft = await (
					await fetch(`${base}/api/shares`, {
						method: 'POST',
						headers: { 'Content-Type': 'application/json', Origin: base },
						body: JSON.stringify({ expiresIn: 0, e2e: true }),
					})
				).json();
				const reg = await (
					await fetch(`${base}/api/shares/${draft.id}/files`, {
						method: 'POST',
						headers: { 'Content-Type': 'application/json', 'X-Edit-Token': draft.editToken, Origin: base },
						body: JSON.stringify({ name: 'enc.gif', size: GIF_BYTES.length, mime: 'image/gif' }),
					})
				).json();
				await fetch(`${base}/api/shares/${draft.id}/files/${reg.fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/octet-stream', 'X-Edit-Token': draft.editToken, Origin: base },
					body: GIF_BYTES,
				});
				await fetch(`${base}/api/shares/${draft.id}/finalize`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': draft.editToken, Origin: base },
				});

				const misses = {
					wrongType: `/${gif.id}.mp4`, // real, embeddable share - but not an mp4
					nonMedia: `/${txt.id}.gif`,
					password: `/${pw.id}.gif`,
					oneTime: `/${oneTime.id}.gif`,
					capped: `/${capped.id}.gif`,
					e2e: `/${draft.id}.gif`,
					unknown: `/no-such-share-xyz.gif`,
				};
				const bodies = [];
				for (const [label, path] of Object.entries(misses)) {
					const res = await fetch(`${base}${path}`, { headers: { 'User-Agent': DISCORDBOT_UA } });
					expect(res.status, label).toBe(404);
					// Never cached at an edge: a share can become resolvable later
					// (finalize, rename) and an ephemeral 404 must not be pinned.
					expect(res.headers.get('cache-control'), label).toBe('no-store');
					bodies.push(await res.text());
				}
				// Byte-identical across all of them: the 404 itself must not reveal
				// which of "no such share" / "private" / "wrong type" applied.
				for (const body of bodies) expect(body).toBe(bodies[0]);

				// An extension that is not a media extension is never treated as a
				// share lookup - it falls through to the ordinary 404 handling, so a
				// probe like /<id>.php cannot be used to enumerate share ids either.
				const php = await fetch(`${base}/${gif.id}.php`);
				expect(php.status).toBe(404);
				const missingPhp = await fetch(`${base}/no-such-share-xyz.php`);
				expect(missingPhp.status).toBe(404);
				expect(await php.text()).toBe(await missingPhp.text());
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('the extensionless share URL is unchanged, and .<ext> picks the matching file even when another file would win the bare-bot path', async () => {
		const dir = freshDataDir('direct-media-unchanged');
		try {
			const proc = await bootServer(dir, 3780);
			try {
				const base = 'http://127.0.0.1:3780';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'direct-media-mixed-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const gif = await upload(base, auth, { mime: 'image/gif', filename: 'a.gif', body: GIF_BYTES });

				// Unchanged: a browser gets the HTML view page (with its OG meta), a
				// crawler gets bare bytes, and both still carry Vary: User-Agent.
				const human = await fetch(`${base}/${gif.id}`, { headers: { 'User-Agent': BROWSER_UA } });
				expect(human.status).toBe(200);
				expect(human.headers.get('content-type')).toContain('text/html');
				expect(human.headers.get('vary')).toContain('User-Agent');
				expect(await human.text()).toContain('property="og:image:type" content="image/gif"');

				const bot = await fetch(`${base}/${gif.id}`, { headers: { 'User-Agent': DISCORDBOT_UA } });
				expect(bot.status).toBe(200);
				expect(bot.headers.get('content-type')).toContain('image/gif');
				expect(bot.headers.get('vary')).toContain('User-Agent');
				// Still no-store: that URL has two representations, so it must never
				// be cached by an intermediary that ignores Vary.
				expect(bot.headers.get('cache-control')).toBe('no-store');

				// A share carrying BOTH an image and an mp4: the bare-bot path prefers
				// the image (unchanged), but /<id>.mp4 resolves the video.
				const mixed = await (
					await fetch(`${base}/api/shares`, {
						method: 'POST',
						headers: { 'Content-Type': 'application/json', Origin: base },
						body: JSON.stringify({ expiresIn: 0 }),
					})
				).json();
				for (const f of [
					{ name: 'shot.gif', mime: 'image/gif', body: GIF_BYTES },
					{ name: 'clip.mp4', mime: 'video/mp4', body: MP4_BYTES },
				]) {
					const reg = await (
						await fetch(`${base}/api/shares/${mixed.id}/files`, {
							method: 'POST',
							headers: { 'Content-Type': 'application/json', 'X-Edit-Token': mixed.editToken, Origin: base },
							body: JSON.stringify({ name: f.name, size: f.body.length, mime: f.mime }),
						})
					).json();
					await fetch(`${base}/api/shares/${mixed.id}/files/${reg.fileId}?offset=0`, {
						method: 'PATCH',
						headers: { 'Content-Type': 'application/octet-stream', 'X-Edit-Token': mixed.editToken, Origin: base },
						body: f.body,
					});
				}
				const fin = await fetch(`${base}/api/shares/${mixed.id}/finalize`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': mixed.editToken, Origin: base },
				});
				expect(fin.status).toBe(200);

				const asImage = await fetch(`${base}/${mixed.id}.gif`);
				expect(asImage.status).toBe(200);
				expect(asImage.headers.get('content-type')).toContain('image/gif');
				const asVideo = await fetch(`${base}/${mixed.id}.mp4`);
				expect(asVideo.status).toBe(200);
				expect(asVideo.headers.get('content-type')).toContain('video/mp4');
				expect((await asVideo.arrayBuffer()).byteLength).toBe(MP4_BYTES.length);

				// The bare-bot path's image-wins-over-video preference is untouched.
				const mixedBot = await fetch(`${base}/${mixed.id}`, { headers: { 'User-Agent': DISCORDBOT_UA } });
				expect(mixedBot.headers.get('content-type')).toContain('image/gif');
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
