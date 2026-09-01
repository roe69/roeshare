// Bun (1.3.14, this repo's pinned Dockerfile version) strips Content-Length off
// any streamed Response body over ~255 bytes and frames it chunked. Previews
// under PREVIEW_BUFFER_CAP are buffered to keep the header
// (preview-content-length.test.js); a real download is never buffered, so its
// byte count travels in X-Content-Length instead - the byte count of THIS
// response body (the range length on a 206), exactly what Content-Length would
// have said. The RoeLite launcher reads it to draw a progress bar while it
// fetches the RoeProx recorder from here. This locks that header in for the
// plain download, the ranged download and the preview.

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const ADMIN_PASSWORD = 'DownloadContentLengthTest-Pw-2026';

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
			SECRET: `download-clen-secret-${port}`,
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
		body: JSON.stringify({ name: 'download-clen-key' }),
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

describe('X-Content-Length on file responses (Bun chunked-streaming workaround)', () => {
	test('a multi-MB download carries X-Content-Length equal to the delivered byte count, plain and ranged, and so does its preview', async () => {
		const dir = freshDataDir('download-clen');
		try {
			const proc = await bootServer(dir, 3993);
			try {
				const base = 'http://127.0.0.1:3993';
				const auth = await makeKey(base);

				// Well above the preview buffer cap's neighbourhood of "streamed", and
				// above anything Bun would frame with a Content-Length: this is the
				// download path the launcher's progress bar depends on.
				const jarBytes = new Uint8Array(3 * 1024 * 1024);
				crypto.getRandomValues(jarBytes.subarray(0, 65536));
				for (let i = 65536; i < jarBytes.length; i++) jarBytes[i] = jarBytes[i % 65536];
				const jar = await upload(base, auth, { filename: 'r.jar', mime: 'application/java-archive', bytes: jarBytes, title: 'ClenJar' });

				const full = await fetch(`${base}/api/shares/${jar.id}/files/${jar.fileId}/download`);
				expect(full.status).toBe(200);
				expect(full.headers.get('x-content-length')).toBe(String(jarBytes.length));
				const fullBody = new Uint8Array(await full.arrayBuffer());
				expect(fullBody.length).toBe(jarBytes.length);
				expect(fullBody).toEqual(jarBytes);

				const ranged = await fetch(`${base}/api/shares/${jar.id}/files/${jar.fileId}/download`, {
					headers: { Range: 'bytes=0-1023' },
				});
				expect(ranged.status).toBe(206);
				expect(ranged.headers.get('content-range')).toBe(`bytes 0-1023/${jarBytes.length}`);
				expect(ranged.headers.get('x-content-length')).toBe('1024');
				const rangedBody = new Uint8Array(await ranged.arrayBuffer());
				expect(rangedBody).toEqual(jarBytes.slice(0, 1024));

				const preview = await fetch(`${base}/api/shares/${jar.id}/files/${jar.fileId}/preview`);
				expect(preview.status).toBe(200);
				expect(preview.headers.get('x-content-length')).toBe(String(jarBytes.length));
				await preview.arrayBuffer();
			} finally {
				await stopServer(proc);
			}
		} finally {
			cleanupDir(dir);
		}
	});
});
