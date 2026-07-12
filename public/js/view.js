// RoeShare view page: render a share's metadata and files with inline previews,
// password unlock for protected shares, and owner delete controls.

import {
	el, $, api, ApiError, toastErr, openModal, copyText,
	formatBytes, timeUntil, fileGlyph, previewKind, migrateLegacyOwnerTokens,
} from './shared.js';
import { importKey, decryptFile, decryptString, recordAad, fromB64u, IV_LEN, TAG_LEN } from './e2e.js';
import { mountSidebar } from '/js/sidebar.js';

mountSidebar();

const root = $('#view');

// End-to-end key (only present for E2E shares). Read from the URL fragment, which
// the browser never sends to the server.
let e2eKey = null;
const e2eKeyB64 = location.hash ? decodeURIComponent(location.hash.slice(1)) : '';

// Share id comes from the path /s/:id.
const shareId = decodeURIComponent(location.pathname.split('/').filter(Boolean).pop() || '');

// Access token: set once the share metadata loads, either because a visitor
// unlocked a password-protected share, or - M-05 - because the server
// recognized us as the owner via the ambient owner-session cookie (see
// load() below; GET /api/shares/:id hands owners a fresh accessToken
// regardless of password, so this alone drives every owner-only UI/URL below
// once loaded - there is no separate editToken read from localStorage
// anymore).
let accessToken = null;

// Append ?access= to URLs that auth via query (media element src, links).
function withAccess(path) {
	return accessToken ? `${path}?access=${encodeURIComponent(accessToken)}` : path;
}

const fileBase = id => `/api/shares/${encodeURIComponent(shareId)}/files/${encodeURIComponent(id)}`;

// ---- Streamed E2E playback/download (Service Worker) -----------------------
// A whole-file fetch+decrypt (e2eFetch below) OOMs on multi-GB video and can't
// seek. Instead we hand the file's key + location to a Service Worker, which
// exposes a virtual same-origin URL that answers Range requests by decrypting
// only the ciphertext records a <video>/<audio> element (or a download) needs.
// See public/sw.js for the streaming implementation.
const SW_OK = 'serviceWorker' in navigator && self.isSecureContext;
const swReadyPromise = SW_OK
	? navigator.serviceWorker.register('/sw.js').then(() => navigator.serviceWorker.ready).catch(() => null)
	: null;

// The browser terminates an idle Service Worker after ~30s, which kills a
// long-running decryption stream (a multi-GB download, a paused video) mid-
// flight. Once any E2E stream has been registered, ping the worker on an
// interval for as long as this page is open - each message event resets the
// worker's idle timer.
let swKeepalive = null;
function startSwKeepalive() {
	if (swKeepalive) return;
	swKeepalive = setInterval(() => {
		try {
			navigator.serviceWorker.controller?.postMessage({ type: 'e2e-ping' });
		} catch { /* controller gone: nothing to keep alive */ }
	}, 10_000);
}

// Registers `file` with the Service Worker and resolves to a virtual URL once
// it acks readiness - '/_e2e-dl/<token>' for a full counted download,
// '/_e2e/<token>' for an uncounted, seekable preview. Resolves to null if the
// SW path is unavailable or registration fails for any reason, so the caller
// can fall back to the existing whole-file Blob path.
async function ensureE2eStream(file, count) {
	if (!SW_OK || !e2eKeyB64) return null;
	try {
		const reg = await swReadyPromise;
		if (!reg) return null;
		let controller = navigator.serviceWorker.controller;
		if (!controller) {
			// First-ever load: the page may not be controlled yet even though the
			// worker is active. Give clients.claim() a moment to take effect.
			controller = await new Promise(resolve => {
				if (navigator.serviceWorker.controller) return resolve(navigator.serviceWorker.controller);
				const onChange = () => {
					navigator.serviceWorker.removeEventListener('controllerchange', onChange);
					resolve(navigator.serviceWorker.controller);
				};
				navigator.serviceWorker.addEventListener('controllerchange', onChange);
				setTimeout(() => {
					navigator.serviceWorker.removeEventListener('controllerchange', onChange);
					resolve(navigator.serviceWorker.controller);
				}, 2000);
			});
		}
		if (!controller) return null;

		const token = crypto.randomUUID();
		// M-05: no X-Edit-Token here - the Service Worker's own fetch() to the
		// real server is a normal same-origin request and so already carries the
		// owner-session cookie automatically; an owner also always holds an
		// accessToken (see load()) as a fallback/for password-protected shares.
		const authHeaders = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
		const ready = new Promise((resolve, reject) => {
			const onMessage = e => {
				const m = e.data;
				if (!m || m.token !== token) return;
				navigator.serviceWorker.removeEventListener('message', onMessage);
				clearTimeout(timer);
				if (m.type === 'e2e-ready') resolve();
				else reject(new Error(m.message || 'registration failed'));
			};
			navigator.serviceWorker.addEventListener('message', onMessage);
			const timer = setTimeout(() => {
				navigator.serviceWorker.removeEventListener('message', onMessage);
				reject(new Error('registration timed out'));
			}, 8000);
		});
		controller.postMessage({
			type: 'e2e-register',
			token,
			keyB64: e2eKeyB64,
			// Decrypted basename: the worker needs it to name the saved file via
			// Content-Disposition (a download triggered by navigating to the
			// virtual URL cannot get its name from an <a download> attribute).
			// It never reaches the server - the virtual URL is answered entirely
			// inside the Service Worker.
			name: file.name.split('/').pop() || file.name,
			fileBase: fileBase(file.id),
			// file.size is the CIPHERTEXT size from share metadata; load() never
			// overwrites it (only name/mime/cs come from the decrypted meta), so
			// this is safe to read here regardless of call order.
			cipherSize: file.size,
			cs: file.cs,
			mime: file.mime,
			// H-1: lets the worker build matching per-record AAD (see e2e.js's
			// recordAad, duplicated in sw.js since it is a classic script).
			fileId: file.id,
			aadVersion: file.aadVersion,
			authHeaders,
		});
		await ready;
		startSwKeepalive();
		return (count ? '/_e2e-dl/' : '/_e2e/') + token;
	} catch {
		return null;
	}
}

// The decrypted per-file mime is chosen by the uploader and must never be
// trusted to pick how we render inline content. Derive the Blob type from the
// classified preview `kind` instead, so a mislabeled file (e.g. text/html named
// "x.pdf") can never be interpreted as an active document in our origin.
function safeBlobType(kind, mime) {
	const m = String(mime || '').toLowerCase().split(';')[0].trim();
	if (kind === 'image') return m.startsWith('image/') ? m : 'application/octet-stream';
	if (kind === 'video') return m.startsWith('video/') ? m : 'application/octet-stream';
	if (kind === 'audio') return m.startsWith('audio/') ? m : 'application/octet-stream';
	if (kind === 'pdf') return 'application/pdf';
	return 'application/octet-stream';
}

function clear() {
	root.replaceChildren();
}

// Split "src/lib/http.js" into a dim directory prefix and the bold basename so a
// long path stays readable in a single row.
function splitPath(p) {
	const i = String(p).lastIndexOf('/');
	return i < 0 ? { dir: '', base: p } : { dir: p.slice(0, i + 1), base: p.slice(i + 1) };
}

// M-1 defense-in-depth: sanitizeName (src/lib/names.js) already strips bidi-
// control/zero-width characters server-side, but isolate the rendered name's
// text direction anyway so an unanticipated bidi character in an older/
// external file record can never visually escape this element and relabel
// neighboring UI (e.g. the download button next to it).
function fileNameNode(name) {
	const { dir, base } = splitPath(name);
	return el('div', { class: 'rl-file-name', title: name, style: 'unicode-bidi: isolate;' },
		dir ? el('span', { class: 'rl-file-dir' }, dir) : null,
		base,
	);
}

// A small pill summarizing one share stat (file count, size, expiry, downloads).
function statChip(text) {
	return el('span', { class: 'rl-stat' }, text);
}

// ---- States ----------------------------------------------------------------

function renderMissing() {
	clear();
	root.append(
		el('div', { class: 'rl-card' },
			el('div', { class: 'rl-empty' },
				el('div', { class: 'rl-empty-icon' }, '\u{1F50D}'),
				el('div', { class: 'rl-h2' }, 'Share not found'),
				el('p', { class: 'rl-muted' }, 'This share does not exist or has expired.'),
				el('a', { class: 'rl-btn rl-btn-secondary', href: '/', style: 'margin-top:var(--rl-space-4)' }, 'Go to the home page'),
			),
		),
	);
}

function renderPasswordForm(title) {
	clear();
	const input = el('input', {
		class: 'rl-input', type: 'password', placeholder: 'Password',
		autocomplete: 'current-password', autofocus: true,
	});
	const btn = el('button', { class: 'rl-btn rl-btn-primary' }, 'Unlock');

	const submit = async () => {
		const password = input.value;
		if (!password) {
			input.focus();
			return;
		}
		btn.disabled = true;
		try {
			const res = await api.post(`/api/shares/${encodeURIComponent(shareId)}/unlock`, { password });
			accessToken = res.accessToken;
			await load();
		} catch (err) {
			if (err instanceof ApiError && err.status === 403) toastErr('Wrong password');
			else toastErr(err);
			btn.disabled = false;
			input.focus();
			input.select();
		}
	};

	input.addEventListener('keydown', e => {
		if (e.key === 'Enter') submit();
	});
	btn.addEventListener('click', submit);

	root.append(
		el('div', { class: 'rl-card', style: 'max-width:420px;margin:var(--rl-space-6) auto' },
			el('div', { class: 'rl-stack' },
				el('div', null,
					el('div', { class: 'rl-eyebrow' }, 'Protected'),
					el('h1', { class: 'rl-h2', style: 'margin-top:var(--rl-space-2)' }, title || 'This share is locked'),
					el('p', { class: 'rl-muted' }, 'Enter the password to view the files.'),
				),
				el('div', { class: 'rl-field' },
					el('label', { class: 'rl-label' }, 'Password'),
					input,
				),
				btn,
			),
		),
	);
	input.focus();
}

// ---- Preview ---------------------------------------------------------------

function buildPreview(file, host) {
	const kind = previewKind(file.mime, file.name);
	const previewUrl = withAccess(`${fileBase(file.id)}/preview`);

	if (kind === 'image') {
		host.append(el('div', { class: 'rl-preview' }, el('img', { src: previewUrl, alt: file.name, loading: 'lazy' })));
	} else if (kind === 'video') {
		host.append(el('div', { class: 'rl-preview' }, el('video', { src: previewUrl, controls: true, preload: 'metadata' })));
	} else if (kind === 'audio') {
		host.append(el('div', { class: 'rl-preview' }, el('audio', { src: previewUrl, controls: true, preload: 'metadata' })));
	} else if (kind === 'pdf') {
		// L-04: an empty sandbox lets the browser's built-in PDF viewer still
		// render the framed document (that's native rendering, not script in the
		// frame) while denying it script execution, form submission, popups, and
		// top-level navigation - defense in depth against a MIME-confused or
		// parser-exploited upload framed on our own origin.
		const frame = el('iframe', { src: previewUrl, title: file.name });
		frame.setAttribute('sandbox', '');
		host.append(el('div', { class: 'rl-preview' }, frame));
	} else if (kind === 'text') {
		const pre = el('pre', { class: 'rl-preview-text' }, 'Loading...');
		host.append(pre);
		loadText(file, pre);
	}
}

async function loadText(file, pre) {
	try {
		const headers = { Range: 'bytes=0-204799' };
		if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
		const res = await fetch(`${fileBase(file.id)}/preview`, { headers });
		if (!res.ok && res.status !== 206) throw new Error('Preview failed');
		let body = await res.text();
		if (body.length > 200000) body = body.slice(0, 200000) + '\n...';
		pre.textContent = body;
	} catch {
		pre.textContent = 'Could not load preview.';
	}
}

function fileCard(file, canPreview) {
	if (e2eKey) return e2eFileCard(file, canPreview);
	const kind = previewKind(file.mime, file.name);
	const previewHost = el('div', { class: 'rl-file-preview rl-hidden' });
	let expanded = false;

	const toggle = kind === 'none' || !canPreview ? null : el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm' }, 'Preview');
	if (toggle) {
		toggle.addEventListener('click', () => {
			expanded = !expanded;
			toggle.textContent = expanded ? 'Hide' : 'Preview';
			previewHost.classList.toggle('rl-hidden', !expanded);
			if (expanded) buildPreview(file, previewHost);
			else previewHost.replaceChildren();
		});
	}

	const download = el('a', {
		class: 'rl-btn rl-btn-primary rl-btn-sm',
		href: withAccess(`${fileBase(file.id)}/download`),
	}, 'Download');

	return el('div', { class: 'rl-file' },
		el('div', { class: 'rl-file-main' },
			el('div', { class: 'rl-file-icon' }, fileGlyph(file.mime, file.name)),
			el('div', { class: 'rl-file-info' },
				fileNameNode(file.name),
				el('div', { class: 'rl-file-sub' }, formatBytes(file.size)),
			),
			el('div', { class: 'rl-file-actions' }, toggle, download),
		),
		previewHost,
	);
}

// ---- End-to-end (client-side decryption) -----------------------------------

function renderE2eError(title, msg) {
	clear();
	root.append(
		el('div', { class: 'rl-card' },
			el('div', { class: 'rl-empty' },
				el('div', { class: 'rl-empty-icon' }, '\u{1F510}'),
				el('div', { class: 'rl-h2' }, title),
				el('p', { class: 'rl-muted' }, msg),
				el('a', { class: 'rl-btn rl-btn-secondary', href: '/', style: 'margin-top:var(--rl-space-4)' }, 'Go to the home page'),
			),
		),
	);
}

// Fetch a file's ciphertext and decrypt it in the browser. `count=true` uses the
// download endpoint (counts toward limits / burns one-time); `false` uses preview
// (no count), used for in-page previews.
async function e2eFetch(file, count) {
	const headers = {};
	if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
	const res = await fetch(`${fileBase(file.id)}/${count ? 'download' : 'preview'}`, { headers });
	if (!res.ok && res.status !== 206) throw new ApiError(res.status, 'fetch failed');
	const cipher = new Uint8Array(await res.arrayBuffer());
	return decryptFile(e2eKey, cipher, file.cs, file.id, file.aadVersion);
}

// A whole-file download's object URL used to be revoked on a fixed 30s timer,
// which could cut off a slow write of a large file to disk. Revoke on page
// unload instead, once it's no longer possible for a still-running save to
// need the URL.
function saveBytes(bytes, name, mime) {
	const url = URL.createObjectURL(new Blob([bytes], { type: mime || 'application/octet-stream' }));
	const a = el('a', { href: url, download: name });
	document.body.append(a);
	a.click();
	a.remove();
	window.addEventListener('pagehide', () => URL.revokeObjectURL(url), { once: true });
}

async function e2ePreview(file, host) {
	host.replaceChildren(el('div', { class: 'rl-center', style: 'padding:var(--rl-space-4)' }, el('span', { class: 'rl-spinner' })));
	const kind = previewKind(file.mime, file.name);

	// Video/audio: stream via the Service Worker so playback seeks and never
	// loads the whole file into memory. Falls through to the whole-file Blob
	// path below if the SW is unavailable.
	if (kind === 'video' || kind === 'audio') {
		const url = await ensureE2eStream(file, false);
		if (url) {
			const node = el(kind, { src: url, controls: true, preload: 'metadata' });
			node.addEventListener('error', () => {
				host.replaceChildren(el('p', { class: 'rl-dim', style: 'padding:var(--rl-space-2)' },
					'This video could not be streamed in the browser; use Download.'));
			});
			host.replaceChildren(el('div', { class: 'rl-preview' }, node));
			return node;
		}
	}

	try {
		const plain = await e2eFetch(file, false);
		if (kind === 'text') {
			host.replaceChildren(el('pre', { class: 'rl-preview-text' }, new TextDecoder().decode(plain)));
			return null;
		}
		const url = URL.createObjectURL(new Blob([plain], { type: safeBlobType(kind, file.mime) }));
		let node;
		if (kind === 'image') node = el('img', { src: url, alt: file.name, loading: 'lazy' });
		else if (kind === 'video') node = el('video', { src: url, controls: true });
		else if (kind === 'audio') node = el('audio', { src: url, controls: true });
		else if (kind === 'pdf') {
			// L-04: same empty-sandbox hardening as the non-E2E PDF preview above.
			node = el('iframe', { src: url, title: file.name });
			node.setAttribute('sandbox', '');
		}
		else node = el('p', { class: 'rl-dim' }, 'No preview for this type.');
		host.replaceChildren(el('div', { class: 'rl-preview' }, node));
		return node;
	} catch (e) {
		const msg = e instanceof ApiError && e.status === 403 ? 'Preview is not available for one-time shares - use Download.' : 'Could not decrypt the preview.';
		host.replaceChildren(el('p', { class: 'rl-dim', style: 'padding:var(--rl-space-2)' }, msg));
		return null;
	}
}

// file.size is the ciphertext (on-disk) size; derive the true plaintext size
// for display by subtracting the per-record IV+tag overhead.
function e2ePlainSize(file) {
	if (!file.cs) return file.size;
	const recordSize = file.cs + 28;
	return file.size - 28 * Math.ceil(file.size / recordSize);
}

function e2eFileCard(file, canPreview) {
	const kind = previewKind(file.mime, file.name);
	const previewHost = el('div', { class: 'rl-file-preview rl-hidden' });
	const base = file.name.split('/').pop() || file.name;
	const sizeText = formatBytes(e2ePlainSize(file));
	const sub = el('div', { class: 'rl-file-sub' }, sizeText);

	let toggle = null;
	if (kind !== 'none' && canPreview) {
		let shown = false;
		toggle = el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm' }, 'Preview');
		toggle.addEventListener('click', async () => {
			shown = !shown;
			toggle.textContent = shown ? 'Hide' : 'Preview';
			previewHost.classList.toggle('rl-hidden', !shown);
			if (shown) {
				const media = await e2ePreview(file, previewHost);
				// Nice-to-have: once the browser has read the container, show the
				// duration alongside the size.
				if (media && (kind === 'video' || kind === 'audio')) {
					media.addEventListener('loadedmetadata', () => {
						if (Number.isFinite(media.duration) && media.duration > 0) {
							const mm = Math.floor(media.duration / 60);
							const ss = Math.floor(media.duration % 60).toString().padStart(2, '0');
							sub.textContent = `${sizeText} · ${mm}:${ss}`;
						}
					}, { once: true });
				}
			} else previewHost.replaceChildren();
		});
	}

	const download = el('button', { class: 'rl-btn rl-btn-primary rl-btn-sm' }, 'Download');
	download.addEventListener('click', async () => {
		const label = download.textContent;
		download.disabled = true;
		// Streamed path: the Service Worker decrypts on the fly straight to the
		// browser's save-to-disk, with one server-side download count and
		// bounded memory even for multi-GB files.
		const url = await ensureE2eStream(file, true);
		if (url) {
			// Must be a NAVIGATION, not an <a download> click: the download
			// attribute hands the URL to the browser's download manager, whose
			// browser-process request bypasses Service Workers entirely - it hit
			// the real server, 404'd, and the recipient saw "file wasn't
			// available on site". A top-level navigation IS matched against the
			// worker's scope; the worker replies with Content-Disposition:
			// attachment, so the browser starts saving and the page stays put.
			//
			// Pre-flight with HEAD first (relayed by the worker; never counted
			// as a delivery server-side): a navigation to a share that just
			// died (expired, deleted, limit reached) would COMMIT and replace
			// this page with the worker's error response. On a failed probe,
			// fall through to the blob path below for its precise error toasts.
			try {
				const probe = await fetch(url, { method: 'HEAD' });
				if (probe.ok) {
					location.assign(url);
					download.disabled = false;
					return;
				}
			} catch { /* worker unreachable: the blob path reports the real error */ }
		}
		download.textContent = 'Decrypting...';
		try {
			saveBytes(await e2eFetch(file, true), base, file.mime);
		} catch (e) {
			toastErr(e instanceof ApiError && e.status === 410 ? 'Download limit reached' : 'Could not download');
		}
		download.disabled = false;
		download.textContent = label;
	});

	return el('div', { class: 'rl-file' },
		el('div', { class: 'rl-file-main' },
			el('div', { class: 'rl-file-icon' }, fileGlyph(file.mime, file.name)),
			el('div', { class: 'rl-file-info' },
				fileNameNode(file.name),
				sub,
			),
			el('div', { class: 'rl-file-actions' }, toggle, download),
		),
		previewHost,
	);
}

// ---- Owner controls --------------------------------------------------------

function ownerDeleteButton() {
	const del = el('button', { class: 'rl-btn rl-btn-danger rl-btn-sm' }, 'Delete share');
	del.addEventListener('click', () => {
		openModal({
			title: 'Delete this share?',
			body: 'This permanently removes the files and the link. This cannot be undone.',
			actions: [
				{ label: 'Cancel', variant: 'ghost' },
				{
					label: 'Delete', variant: 'danger', onClick: async () => {
						try {
							// M-05: no X-Edit-Token header - ownership is proven by the
							// ambient owner-session cookie; this is a same-origin fetch
							// from our own page, so the server's requireSameOrigin()
							// check on the cookie path passes automatically.
							await api.del(`/api/shares/${encodeURIComponent(shareId)}`);
							location.href = '/';
						} catch (err) {
							toastErr(err);
						}
					},
				},
			],
		});
	});
	return del;
}

// ---- QR code ---------------------------------------------------------------

// Show a modal with a scannable QR for the given share URL. The QR renders dark
// modules on a white card so a phone camera can read it on this dark theme.
async function openQrModal(url) {
	const qrHost = el('div', {
		style: 'width:240px;max-width:100%;aspect-ratio:1;margin:0 auto;background:#fff;'
			+ 'border-radius:var(--rl-radius-md);padding:var(--rl-space-4);box-sizing:border-box',
	});
	const link = el('div', {
		class: 'rl-muted',
		style: 'font-family:var(--rl-font-mono,monospace);word-break:break-all;text-align:center;'
			+ 'user-select:all;font-size:var(--rl-text-sm)',
	}, url);
	const body = el('div', { class: 'rl-stack', style: 'align-items:center' },
		qrHost,
		link,
		el('button', { class: 'rl-btn rl-btn-secondary', onClick: () => copyText(url) }, 'Copy link'),
	);

	openModal({ title: 'Scan to open', body });

	try {
		const { makeQrSvg } = await import('/js/qrcode.js');
		qrHost.innerHTML = makeQrSvg(url, { border: 2 });
	} catch (err) {
		toastErr('Could not generate QR code');
		qrHost.remove();
	}
}

// ---- Main render -----------------------------------------------------------

function renderShare(share) {
	clear();
	const files = share.files || [];
	const count = files.length;
	// The server rejects non-owner preview requests on any controlled share (a
	// one-time share, or one with a download cap). Owners may always preview
	// (share.owner, resolved server-side from either the X-Edit-Token header
	// or - M-05 - the owner-session cookie); hide the Preview toggle otherwise
	// so we never show a control that would just 403.
	const canPreview = share.owner || !share.oneTime;
	const totalSize = share.totalSize != null ? share.totalSize : files.reduce((s, f) => s + (f.size || 0), 0);

	const downloads = share.maxDownloads
		? `${share.downloadCount} / ${share.maxDownloads} downloads`
		: `${share.downloadCount} download${share.downloadCount === 1 ? '' : 's'}`;
	let expiry = 'Never expires';
	if (share.expiresAt) {
		const t = timeUntil(share.expiresAt);
		expiry = t === 'Expired' ? 'Expired' : `Expires in ${t}`;
	}

	// Top-right badges: encryption + ownership.
	const badges = el('div', { class: 'rl-row rl-row-wrap', style: 'gap:var(--rl-space-2)' },
		share.e2e ? el('span', { class: 'rl-badge rl-badge-gold' }, 'End-to-end encrypted') : null,
		share.owner ? el('span', { class: 'rl-badge rl-badge-success' }, 'You own this share') : null,
	);

	const views = share.viewCount || 0;
	const stats = el('div', { class: 'rl-share-stats' },
		statChip(`${count} ${count === 1 ? 'file' : 'files'}`),
		statChip(formatBytes(totalSize)),
		statChip(expiry),
		statChip(`${views} view${views === 1 ? '' : 's'}`),
		statChip(downloads),
	);

	// Actions: copy link, QR, zip-all (multi-file), and owner delete (right-aligned).
	const actions = el('div', { class: 'rl-row rl-row-wrap' },
		el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm', onClick: () => copyText(location.href) }, 'Copy link'),
		el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm', onClick: () => openQrModal(location.href) }, 'QR code'),
		count > 1 && !share.e2e
			? el('a', { class: 'rl-btn rl-btn-accent rl-btn-sm', href: withAccess(`/api/shares/${encodeURIComponent(shareId)}/download-all`) }, 'Download all (zip)')
			: null,
		share.owner ? el('span', { class: 'rl-spacer' }) : null,
		share.owner ? ownerDeleteButton() : null,
	);

	const summary = el('section', { class: 'rl-card' },
		el('div', { class: 'rl-stack' },
			el('div', { class: 'rl-row rl-row-wrap', style: 'justify-content:space-between;align-items:flex-start' },
				el('h1', { class: 'rl-h1 rl-truncate', style: 'margin:0;min-width:0', title: share.title || 'Shared files' }, share.title || 'Shared files'),
				badges,
			),
			stats,
			share.oneTime ? el('div', { class: 'rl-alert rl-alert-warning' }, 'One-time share - the first download removes it for everyone.') : null,
			actions,
		),
	);
	root.append(summary);

	if (!count) {
		root.append(el('div', { class: 'rl-card' },
			el('div', { class: 'rl-empty' },
				el('div', { class: 'rl-empty-icon' }, '\u{1F4ED}'),
				el('p', { class: 'rl-muted' }, 'No files in this share.'),
			),
		));
		return;
	}

	// One framed card holding a tight list of file rows (previews expand inline).
	const list = el('div', { class: 'rl-files' });
	for (const f of files) list.append(fileCard(f, canPreview));
	root.append(el('section', { class: 'rl-card rl-files-card' }, list));
}

// ---- Load ------------------------------------------------------------------

async function load() {
	try {
		// M-05: no X-Edit-Token header - ownership is now resolved server-side
		// from the ambient owner-session cookie (sent automatically on this
		// same-origin fetch), not a token read out of localStorage. The access
		// token, once known (a visitor who just unlocked a password share),
		// still needs to be sent explicitly since it is only ever held in memory.
		const opts = accessToken ? { headers: { Authorization: `Bearer ${accessToken}` } } : undefined;
		const share = await api.get(`/api/shares/${encodeURIComponent(shareId)}`, opts);
		// Owners receive a read access token so element-src previews and download
		// links work without unlocking.
		if (share.accessToken) accessToken = share.accessToken;

		// E2E: import the key from the link fragment and decrypt the file metadata
		// (names/types) before rendering. Everything else stays encrypted until a
		// preview or download decrypts it in the browser.
		if (share.e2e) {
			if (!e2eKeyB64) return renderE2eError('This link is missing its key', 'The part after the # in the original link is required to open an end-to-end encrypted share.');
			try {
				e2eKey = await importKey(e2eKeyB64);
			} catch {
				return renderE2eError('Invalid key', 'The decryption key in this link is not valid.');
			}
			try {
				for (const f of share.files) {
					// H-1: f.aadVersion comes straight from the (unencrypted) share
					// metadata, so there is no ordering problem reading it before
					// decrypting - only aadVersion 1 records were sealed with AAD.
					const plainLen = fromB64u(f.name).length - IV_LEN - TAG_LEN;
					const aad = f.aadVersion === 1 ? recordAad('name', f.id, 0, plainLen) : undefined;
					const meta = JSON.parse(await decryptString(e2eKey, f.name, aad));
					f.name = meta.name;
					f.mime = meta.mime;
					f.cs = meta.cs;
				}
			} catch {
				// Not overclaiming precision: for an aadVersion 1 file this failure
				// really does mean a wrong key or a tampered/spliced record, but for
				// a legacy aadVersion 0 file a GCM failure can equally be ordinary
				// unauthenticated-position corruption - this message covers both
				// without claiming splice-detection that doesn't exist for legacy.
				return renderE2eError('Could not decrypt this share', 'The key may be wrong, or the data was tampered with or corrupted.');
			}
		}
		renderShare(share);
	} catch (err) {
		if (err instanceof ApiError && err.status === 404) {
			renderMissing();
		} else if (err instanceof ApiError && err.status === 401 && err.data && err.data.protected) {
			// The server no longer includes the share's title in this response (it
			// could leak sensitive names before the password is proven), so the
			// unlock prompt always shows the generic label.
			renderPasswordForm();
		} else {
			clear();
			renderMissing();
			toastErr(err);
		}
	}
}

// One-release migration (M-05): exchange any legacy `roeshare:edit:<id>` raw
// token for the new owner-session cookie before the metadata fetch below, so
// an owner who used this browser before the change is still recognized as one.
if (!shareId) renderMissing();
else migrateLegacyOwnerTokens().then(load);
