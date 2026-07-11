// RoeShare end-to-end streaming Service Worker.
//
// Problem: an E2E share's files are stored on the server as ciphertext only -
// a concatenation of AES-256-GCM records, one per upload chunk:
//   record i = [12B IV][ciphertext(plaintext<=cs)][16B GCM tag]   (ENC_OVERHEAD = 28)
// Record i sits at ciphertext offset i*(cs+28) and covers plaintext bytes
// [i*cs, (i+1)*cs). Only the last record may be shorter. Because the server
// never sees the key, /preview and /download already serve arbitrary
// ciphertext byte Ranges (206) unchanged - which is exactly what lets us seek.
//
// Before this worker, the view page decrypted an entire file into memory to
// play or download it (see public/js/e2e.js decryptFile + public/js/view.js
// e2eFetch), which OOMs on multi-GB video and can't seek at all.
//
// This worker instead exposes two *virtual* same-origin URLs per registered
// file:
//   /_e2e/<token>      - a plaintext resource that answers Range requests
//                        (bound to a <video>/<audio> element for seekable
//                        playback). Backed by GET .../preview, uncounted.
//   /_e2e-dl/<token>   - the full plaintext file, streamed straight to the
//                        browser's save-to-disk machinery. Backed by a SINGLE
//                        GET .../download so the server's download counters /
//                        one-time burn only fire once. The page NAVIGATES to
//                        this URL (location.assign) rather than clicking an
//                        <a download> anchor: an anchor download hands the
//                        URL to the browser's download manager, whose
//                        browser-process request bypasses Service Workers and
//                        404s against the real server. A navigation is always
//                        matched against the worker's scope; the attachment
//                        disposition (with the decrypted filename) turns it
//                        into a save-to-disk without leaving the page.
//
// For either URL, this worker maps the *plaintext* byte range the browser
// asked for onto the *ciphertext* records that cover it, fetches only those
// ciphertext bytes (via HTTP Range on the real endpoint), decrypts each
// record with WebCrypto AES-GCM, and streams the decrypted plaintext back.
// Memory use is bounded by one batch of records at a time, never the whole
// file.
//
// The page registers a file by posting an { AES key (raw, imported here),
// fileBase, cipherSize, cs, mime } record keyed by an opaque per-request
// token; this worker acks with 'e2e-ready' once the key import succeeds. The
// key material never leaves the browser - it arrives already as raw bytes
// from the URL fragment (which is never sent to any server).
//
// Registrations are held in memory AND persisted to IndexedDB (a CryptoKey
// survives structured clone, so the key stays non-extractable). Persistence
// lets the virtual URLs survive this worker being terminated: the browser
// kills idle Service Workers at will, so a seek in a long-paused video or a
// download navigation issued after the worker died must be servable by a
// fresh worker instance hydrating from IDB. It does NOT rescue the downloads
// bar's own Retry/Resume: those are issued by the browser's download manager,
// whose requests never route through Service Workers - a recipient retries by
// pressing Download on the share page again. The key already lives in the
// recipient's history (it is part of the share link), so the IDB copy adds no
// new exposure; entries are swept after IDB_TTL regardless.

const IV_LEN = 12;
const ENC_OVERHEAD = 28; // IV_LEN + 16-byte GCM tag

// token -> { key, name, fileBase, cipherSize, cs, mime, plainTotal, numChunks, authHeaders, createdAt }
const files = new Map();

// Same encoding as the server's contentDisposition (src/lib/http.js): an
// ASCII-safe quoted fallback plus RFC 5987 filename* for the real name.
function attachmentDisposition(filename) {
	const fallback = String(filename).replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
	return `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

// A GET on /_e2e-dl is a top-level navigation, so an error response would
// COMMIT that navigation and strand the visitor on a bare error body. Serve a
// small page that walks itself back to the share instead - history.back()
// restores the URL fragment (the key), which a redirect could not carry. The
// view page pre-flights a HEAD before navigating, so this only surfaces when
// the share's state changed in the race between probe and click.
function failPage(status, message) {
	const html = '<!doctype html><meta charset="utf-8"><title>Download failed</title>'
		+ '<body style="margin:0;height:100vh;display:grid;place-items:center;background:#000000;color:#ededf0;font:15px system-ui">'
		+ '<div style="text-align:center"><p>' + message + '</p>'
		+ '<p><a href="#" onclick="history.back();return false" style="color:#ff6b35">Go back</a></p></div>'
		+ '<script>setTimeout(function () { history.back(); }, 2500)</scr' + 'ipt>';
	return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ---- IndexedDB persistence ---------------------------------------------------

const IDB_NAME = 'roeshare-e2e';
const IDB_STORE = 'files';
const IDB_TTL = 7 * 24 * 60 * 60 * 1000; // sweep registrations older than 7 days

let idbPromise = null;
function idb() {
	if (!idbPromise) {
		idbPromise = new Promise((resolve, reject) => {
			const req = indexedDB.open(IDB_NAME, 1);
			req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE, { keyPath: 'token' });
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		// A failed open (private mode, storage pressure) must not poison every
		// later attempt; the worker just runs memory-only.
		idbPromise.catch(() => { idbPromise = null; });
	}
	return idbPromise;
}

async function idbPut(entry) {
	try {
		const db = await idb();
		await new Promise((resolve, reject) => {
			const tx = db.transaction(IDB_STORE, 'readwrite');
			tx.objectStore(IDB_STORE).put(entry);
			tx.oncomplete = resolve;
			tx.onerror = () => reject(tx.error);
		});
	} catch { /* IDB unavailable: memory-only, same behavior as before */ }
}

async function idbGet(token) {
	try {
		const db = await idb();
		return await new Promise((resolve, reject) => {
			const req = db.transaction(IDB_STORE).objectStore(IDB_STORE).get(token);
			req.onsuccess = () => resolve(req.result || null);
			req.onerror = () => reject(req.error);
		});
	} catch {
		return null;
	}
}

async function idbSweep() {
	try {
		const db = await idb();
		const cutoff = Date.now() - IDB_TTL;
		await new Promise((resolve, reject) => {
			const tx = db.transaction(IDB_STORE, 'readwrite');
			const cur = tx.objectStore(IDB_STORE).openCursor();
			cur.onsuccess = () => {
				const c = cur.result;
				if (!c) return;
				if (!c.value.createdAt || c.value.createdAt < cutoff) c.delete();
				c.continue();
			};
			tx.oncomplete = resolve;
			tx.onerror = () => reject(tx.error);
		});
	} catch { /* best-effort */ }
}

// Resolve a token from memory first, then IndexedDB (a fresh worker instance
// hydrating a registration made by a previous one).
async function getEntry(token) {
	let entry = files.get(token);
	if (entry) return entry;
	entry = await idbGet(token);
	if (entry) files.set(token, entry);
	return entry;
}

self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(Promise.all([self.clients.claim(), idbSweep()])));

function fromB64u(str) {
	const b = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
	const out = new Uint8Array(b.length);
	for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
	return out;
}

self.addEventListener('message', async e => {
	const m = e.data;
	// 'e2e-ping' needs no handling: the message event itself resets the
	// browser's Service Worker idle timer, which is the whole point (the view
	// page pings while E2E streams are in use so a long download/playback is
	// not killed mid-stream).
	if (!m || m.type !== 'e2e-register') return;
	try {
		const key = await crypto.subtle.importKey('raw', fromB64u(m.keyB64), { name: 'AES-GCM' }, false, ['decrypt']);
		const recordSize = m.cs + ENC_OVERHEAD;
		const numChunks = Math.max(1, Math.ceil(m.cipherSize / recordSize));
		const plainTotal = m.cipherSize - numChunks * ENC_OVERHEAD;
		const entry = {
			token: m.token,
			key,
			name: m.name,
			fileBase: m.fileBase,
			cipherSize: m.cipherSize,
			cs: m.cs,
			mime: m.mime,
			plainTotal,
			numChunks,
			authHeaders: m.authHeaders || {},
			createdAt: Date.now(),
		};
		files.set(m.token, entry);
		// Persist before acking so a Retry/Resume that lands on a future worker
		// instance can always rehydrate this registration.
		await idbPut(entry);
		e.source && e.source.postMessage({ type: 'e2e-ready', token: m.token });
	} catch (err) {
		e.source && e.source.postMessage({ type: 'e2e-error', token: m.token, message: String(err) });
	}
});

async function decryptRecord(key, record) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: record.subarray(0, IV_LEN) }, key, record.subarray(IV_LEN)));
}

// Lazy, backpressure-friendly plaintext stream for the inclusive plaintext
// byte range [start,end]. Fetches ciphertext in batches of records (~4MB of
// plaintext per network round-trip) so memory stays bounded regardless of
// file size, and only pulls more once the consumer (the <video> element / a
// disk write) asks for more.
function plainStream(entry, start, end, endpoint) {
	const { key, fileBase, cipherSize, cs, plainTotal, authHeaders } = entry;
	const recordSize = cs + ENC_OVERHEAD;
	const BATCH = Math.max(1, Math.floor((4 * 1024 * 1024) / cs)); // ~4MB plaintext per fetch
	let rec = Math.floor(start / cs);
	const lastRec = Math.floor(end / cs);
	return new ReadableStream({
		async pull(controller) {
			if (rec > lastRec) {
				controller.close();
				return;
			}
			const bStart = rec, bEnd = Math.min(rec + BATCH - 1, lastRec);
			const cipherA = bStart * recordSize;
			const cipherB = Math.min((bEnd + 1) * recordSize, cipherSize) - 1;
			let res;
			try {
				res = await fetch(fileBase + endpoint, { cache: 'no-store', headers: { ...authHeaders, Range: `bytes=${cipherA}-${cipherB}` } });
			} catch (err) {
				controller.error(err);
				return;
			}
			if (res.status !== 206 && res.status !== 200) {
				controller.error(new Error('cipher fetch failed: ' + res.status));
				return;
			}
			let buf = new Uint8Array(await res.arrayBuffer());
			// A 200 means the Range was ignored somewhere (a cache, a proxy) and
			// buf is the whole ciphertext; slice out the records we asked for.
			// Anything else that isn't the exact requested window would silently
			// misframe every record, so fail loudly instead of corrupting.
			if (res.status === 200 && buf.length === cipherSize) buf = buf.subarray(cipherA, cipherB + 1);
			if (buf.length !== cipherB - cipherA + 1) {
				controller.error(new Error(`cipher fetch returned ${buf.length} bytes, expected ${cipherB - cipherA + 1}`));
				return;
			}
			let pos = 0;
			for (let i = bStart; i <= bEnd; i++) {
				const cStart = i * cs;
				const cEnd = Math.min(cStart + cs, plainTotal);
				const recLen = (cEnd - cStart) + ENC_OVERHEAD;
				const record = buf.subarray(pos, pos + recLen);
				pos += recLen;
				let plain;
				try {
					plain = await decryptRecord(key, record);
				} catch (err) {
					controller.error(err);
					return;
				}
				const sliceStart = Math.max(start, cStart) - cStart;
				const sliceEnd = Math.min(end, cEnd - 1) - cStart + 1;
				controller.enqueue(plain.subarray(sliceStart, sliceEnd));
			}
			rec = bEnd + 1;
		},
	});
}

self.addEventListener('fetch', event => {
	const url = new URL(event.request.url);
	let m = url.pathname.match(/^\/_e2e\/([^/]+)$/);
	if (m) {
		event.respondWith(handleRange(m[1], event.request, '/preview'));
		return;
	}
	m = url.pathname.match(/^\/_e2e-dl\/([^/]+)$/);
	if (m) {
		event.respondWith(handleDownload(m[1], event.request, '/download'));
		return;
	}
	// everything else: default network handling.
});

// Serves /_e2e/<token>: a Range-aware plaintext view of the file, used as a
// <video>/<audio> src so the element can seek. Backed by .../preview, which
// never counts toward download limits or burns a one-time share.
async function handleRange(token, req, endpoint) {
	const entry = await getEntry(token);
	if (!entry) return new Response('not found', { status: 404 });
	const total = entry.plainTotal;
	const rangeHdr = req.headers.get('range');
	let start = 0, end = total - 1, partial = false;
	if (rangeHdr) {
		const mm = /^bytes=(\d*)-(\d*)$/.exec(rangeHdr.trim());
		if (mm) {
			partial = true;
			if (mm[1] === '') {
				const n = Number(mm[2]);
				start = Math.max(0, total - n);
				end = total - 1;
			} else {
				start = Number(mm[1]);
				end = mm[2] === '' ? total - 1 : Math.min(Number(mm[2]), total - 1);
			}
		}
	}
	if (start > end || start >= total) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${total}` } });
	const body = plainStream(entry, start, end, endpoint);
	const headers = {
		'Content-Type': entry.mime || 'application/octet-stream',
		'Content-Length': String(end - start + 1),
		'Accept-Ranges': 'bytes',
		'Cache-Control': 'no-store',
	};
	if (partial) headers['Content-Range'] = `bytes ${start}-${end}/${total}`;
	return new Response(body, { status: partial ? 206 : 200, headers });
}

// Serves /_e2e-dl/<token>: the whole plaintext file, for a real browser
// "save to disk" download. Fetches the ciphertext in ONE request (so the
// server's download counters / one-time burn fire exactly once) and decrypts
// it record-by-record as bytes arrive, so memory stays bounded even for a
// multi-GB file.
async function handleDownload(token, req, endpoint) {
	const entry = await getEntry(token);
	if (!entry) {
		if (req.method === 'HEAD') return new Response(null, { status: 404 });
		return failPage(404, 'This download link is stale. Go back and press Download again.');
	}

	// Pre-flight from the view page: relay the server gate's verdict (live?
	// unlocked? limit reached?) so the page only commits the navigation when
	// the download will actually stream. The server never treats HEAD as a
	// full delivery, so a probe cannot count a download or burn a one-time
	// share.
	if (req.method === 'HEAD') {
		try {
			const res = await fetch(entry.fileBase + endpoint, { method: 'HEAD', headers: { ...entry.authHeaders } });
			return new Response(null, { status: res.status });
		} catch {
			return new Response(null, { status: 502 });
		}
	}

	// Ranged re-request of the plaintext: serve the requested tail via ranged
	// ciphertext fetches. Chrome's downloads-bar Resume does NOT reach this
	// handler (the download manager bypasses Service Workers), but a ranged
	// caller that does route through the worker gets a correct partial.
	const rangeHdr = req && req.headers.get('range');
	if (rangeHdr) {
		const total = entry.plainTotal;
		const mm = /^bytes=(\d+)-(\d*)$/.exec(rangeHdr.trim());
		if (mm) {
			const start = Number(mm[1]);
			const end = mm[2] === '' ? total - 1 : Math.min(Number(mm[2]), total - 1);
			if (start > end || start >= total) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${total}` } });
			return new Response(plainStream(entry, start, end, endpoint), {
				status: 206,
				headers: {
					'Content-Type': 'application/octet-stream',
					'Content-Length': String(end - start + 1),
					'Content-Range': `bytes ${start}-${end}/${total}`,
					'Accept-Ranges': 'bytes',
					'Content-Disposition': attachmentDisposition(entry.name || token),
					'Cache-Control': 'no-store',
				},
			});
		}
	}

	let res;
	try {
		res = await fetch(entry.fileBase + endpoint, { headers: { ...entry.authHeaders } });
	} catch (err) {
		return failPage(502, 'The download could not be started. Check your connection, then go back and try again.');
	}
	if (!res.ok) {
		return failPage(res.status, res.status === 410
			? 'This share’s download limit has been reached.'
			: 'This share is no longer available.');
	}
	const { cs, key, plainTotal } = entry;
	const numChunks = Math.ceil(plainTotal / cs) || 1;
	// Reassemble fixed-size ciphertext records from arbitrarily-sized network
	// chunks by copying each byte exactly once into the record it belongs to
	// (a queue), rather than repeatedly concatenating a growing leftover buffer -
	// the latter is O(recordSize) per network chunk, a large copy amplification
	// on a big download with the default multi-MB chunk size.
	const pending = []; // queue of Uint8Array
	let pendingLen = 0, recIndex = 0;
	const dec = new TransformStream({
		async transform(chunk, controller) {
			pending.push(chunk);
			pendingLen += chunk.length;
			while (true) {
				const isLast = recIndex === numChunks - 1;
				const thisPlain = isLast ? (plainTotal - recIndex * cs) : cs;
				const recLen = thisPlain + ENC_OVERHEAD;
				if (pendingLen < recLen) break;
				const record = new Uint8Array(recLen);
				let off = 0;
				while (off < recLen) {
					const head = pending[0];
					const take = Math.min(head.length, recLen - off);
					record.set(head.subarray(0, take), off);
					off += take;
					if (take === head.length) pending.shift();
					else pending[0] = head.subarray(take);
				}
				pendingLen -= recLen;
				let plain;
				try {
					plain = await decryptRecord(key, record);
				} catch (err) {
					controller.error(err);
					return;
				}
				controller.enqueue(plain);
				recIndex++;
			}
		},
	});
	return new Response(res.body.pipeThrough(dec), {
		headers: {
			'Content-Type': 'application/octet-stream',
			'Content-Length': String(entry.plainTotal),
			// Advertise ranges so an interrupted download offers Resume (handled
			// above) instead of only Retry-from-zero.
			'Accept-Ranges': 'bytes',
			// The filename must come from this header: a navigation download has
			// no <a download> attribute to name the file.
			'Content-Disposition': attachmentDisposition(entry.name || token),
			'Cache-Control': 'no-store',
		},
	});
}
