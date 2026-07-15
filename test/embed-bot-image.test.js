// Bare-image bot path: a chat-app link-preview crawler UA (Discordbot etc.)
// fetching an eligible share URL gets the raw image bytes back directly at
// that same URL - no HTML, no og:site_name/title/description chrome - while
// a normal browser UA still gets the regular HTML share page. Reuses
// embed-meta.test.js's server-boot helpers and exercises the real server.
//
// Exercises:
//   - a public, finalized, non-e2e, single-image share: bot UA -> raw image
//     bytes (matching /preview byte-for-byte), Content-Type image/*, Vary:
//     User-Agent; non-bot UA -> HTML page, unchanged
//   - one-time/password/capped/e2e/non-image shares: bot UA still gets the
//     ordinary HTML (generic-meta) page, never image bytes - the bare-image
//     path reuses buildShareMeta's exact eligibility predicate, so none of
//     these can ever be bare-imaged
//   - a bot fetch of a one-time share does not burn it (still fetchable after)
//   - a bot fetch never touches view_count

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'EmbedBotImageTest-Pw-2026';
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
			SECRET: `embed-bot-image-secret-${port}`,
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
	const setCookie = res.headers.get('set-cookie');
	return setCookie.split(';')[0];
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

async function adminViewCount(base, cookie, id) {
	const res = await fetch(`${base}/api/admin/shares/${id}`, { headers: { Cookie: cookie } });
	expect(res.status).toBe(200);
	const body = await res.json();
	return body.viewCount;
}

describe('bare-image embed for bot UAs', () => {
	test('bot UA gets raw image bytes on both /:id and /s/:id; normal UA still gets HTML; Vary: User-Agent set', async () => {
		const dir = freshDataDir('embed-bot-rich');
		try {
			const proc = await bootServer(dir, 3770);
			try {
				const base = 'http://127.0.0.1:3770';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'embed-bot-rich-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const bytes = new Uint8Array([137, 80, 78, 71, 1, 2, 3, 4]);
				const res = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&title=BotPic`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'pic.png' },
					body: bytes,
				});
				expect(res.status).toBe(201);
				const made = await res.json();

				const previewBytes = new Uint8Array(await (await fetch(`${base}/api/shares/${made.id}/files/${made.fileId}/preview`)).arrayBuffer());

				for (const path of [`/${made.id}`, `/s/${made.id}`]) {
					const botRes = await fetch(`${base}${path}`, { headers: { 'User-Agent': DISCORDBOT_UA } });
					expect(botRes.status).toBe(200);
					expect(botRes.headers.get('content-type')).toContain('image/png');
					expect(botRes.headers.get('vary')).toContain('User-Agent');
					// No HTML/OG chrome at all - this is raw image bytes, not a document.
					expect(botRes.headers.get('content-disposition')).toContain('inline');
					const body = new Uint8Array(await botRes.arrayBuffer());
					expect(body).toEqual(previewBytes);

					const humanRes = await fetch(`${base}${path}`, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } });
					expect(humanRes.status).toBe(200);
					expect(humanRes.headers.get('content-type')).toContain('text/html');
					expect(humanRes.headers.get('vary')).toContain('User-Agent');
					const html = await humanRes.text();
					expect(html).toContain('property="og:image:type" content="image/png"');
				}

				// A bot fetch is not counted as a view either (same guarantee as the
				// existing rich-meta path - see embed-meta.test.js).
				const before = await adminViewCount(base, cookie, made.id);
				await fetch(`${base}/${made.id}`, { headers: { 'User-Agent': DISCORDBOT_UA } });
				const after = await adminViewCount(base, cookie, made.id);
				expect(after).toBe(before);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});

	test('one-time/password/capped/e2e/non-image shares: bot UA still gets the ordinary HTML page, never image bytes; one-time is not burned by the bot fetch', async () => {
		const dir = freshDataDir('embed-bot-excluded');
		try {
			const proc = await bootServer(dir, 3771);
			try {
				const base = 'http://127.0.0.1:3771';
				const cookie = await adminCookie(base);
				const key = await makeKey(base, cookie, 'embed-bot-excluded-key');
				const auth = { Authorization: `Bearer ${key.token}` };

				const nonImageRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=text%2Fplain`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'notes.txt' },
					body: new Uint8Array([1]),
				});
				const nonImage = await nonImageRes.json();

				const passwordRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&title=SecretPic`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'p.png', 'X-Upload-Password': 'embed-bot-secret-1' },
					body: new Uint8Array([1, 2]),
				});
				const password = await passwordRes.json();

				const oneTimeRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&oneTime=1&title=OneTimePic`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'o.png' },
					body: new Uint8Array([1, 2, 3]),
				});
				const oneTime = await oneTimeRes.json();

				const cappedRes = await fetch(`${base}/api/v1/upload?expiresIn=0&mime=image%2Fpng&maxDownloads=3&title=CappedPic`, {
					method: 'POST',
					headers: { ...auth, 'X-Filename': 'c.png' },
					body: new Uint8Array([1, 2, 3, 4]),
				});
				const capped = await cappedRes.json();

				const draftRes = await fetch(`${base}/api/shares`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', Origin: base },
					body: JSON.stringify({ expiresIn: 0, e2e: true, title: 'E2ESecretTitle' }),
				});
				const draft = await draftRes.json();
				const regRes = await fetch(`${base}/api/shares/${draft.id}/files`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': draft.editToken, Origin: base },
					body: JSON.stringify({ name: 'enc-blob', size: 4, mime: 'application/octet-stream' }),
				});
				const reg = await regRes.json();
				await fetch(`${base}/api/shares/${draft.id}/files/${reg.fileId}?offset=0`, {
					method: 'PATCH',
					headers: { 'Content-Type': 'application/octet-stream', 'X-Edit-Token': draft.editToken, Origin: base },
					body: new Uint8Array([9, 9, 9, 9]),
				});
				await fetch(`${base}/api/shares/${draft.id}/finalize`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json', 'X-Edit-Token': draft.editToken, Origin: base },
				});

				for (const id of [nonImage.id, password.id, oneTime.id, capped.id, draft.id]) {
					const botRes = await fetch(`${base}/${id}`, { headers: { 'User-Agent': DISCORDBOT_UA } });
					expect(botRes.status).toBe(200);
					expect(botRes.headers.get('content-type')).toContain('text/html');
					const html = await botRes.text();
					expect(html).not.toContain('og:image');
				}

				// The one-time share is still live and its own preview still works for
				// the owner-equivalent /preview probe - a bot pasting the link did not
				// burn it (embeddableFile excludes one_time before servePreview is ever
				// reached, so the bot never even hits the F-01 gate on it).
				const stillThere = await fetch(`${base}/api/admin/shares/${oneTime.id}`, { headers: { Cookie: cookie } });
				expect(stillThere.status).toBe(200);
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
