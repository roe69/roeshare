// RoeShare view page: render a share's metadata and files with inline previews,
// password unlock for protected shares, and owner delete controls.

import {
	el, $, api, ApiError, toastErr, openModal, copyText,
	formatBytes, timeUntil, fileGlyph, previewKind,
} from './shared.js';
import { importKey, decryptFile, decryptString } from './e2e.js';

const root = $('#view');

// End-to-end key (only present for E2E shares). Read from the URL fragment, which
// the browser never sends to the server.
let e2eKey = null;
const e2eKeyB64 = location.hash ? decodeURIComponent(location.hash.slice(1)) : '';

// Share id comes from the path /s/:id.
const shareId = decodeURIComponent(location.pathname.split('/').filter(Boolean).pop() || '');

// Access token (only set when a password share is unlocked). Kept in memory.
let accessToken = null;
// Edit token (owner) persisted by the upload page.
const editToken = localStorage.getItem('roeshare:edit:' + shareId);

// Append ?access= to URLs that auth via query (media element src, links).
function withAccess(path) {
	return accessToken ? `${path}?access=${encodeURIComponent(accessToken)}` : path;
}

const fileBase = id => `/api/shares/${encodeURIComponent(shareId)}/files/${encodeURIComponent(id)}`;

function clear() {
	root.replaceChildren();
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
				el('a', { class: 'rl-btn rl-btn-secondary', href: '/', style: 'margin-top:var(--rl-space-4)' }, 'Go to RoeShare'),
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
		host.append(el('div', { class: 'rl-preview' }, el('iframe', { src: previewUrl, title: file.name })));
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

function fileCard(file) {
	if (e2eKey) return e2eFileCard(file);
	const kind = previewKind(file.mime, file.name);
	const previewHost = el('div', { class: 'rl-stack' });
	let expanded = false;

	const toggle = kind === 'none' ? null : el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm' }, 'Preview');
	if (toggle) {
		toggle.addEventListener('click', () => {
			expanded = !expanded;
			if (expanded) {
				toggle.textContent = 'Hide';
				buildPreview(file, previewHost);
			} else {
				toggle.textContent = 'Preview';
				previewHost.replaceChildren();
			}
		});
	}

	const download = el('a', {
		class: 'rl-btn rl-btn-primary rl-btn-sm',
		href: withAccess(`${fileBase(file.id)}/download`),
	}, 'Download');

	return el('div', { class: 'rl-card rl-card-pad-sm' },
		el('div', { class: 'rl-stack' },
			el('div', { class: 'rl-row rl-row-wrap' },
				el('div', { class: 'rl-filerow-icon' }, fileGlyph(file.mime, file.name)),
				el('div', { class: 'rl-filerow-meta' },
					el('div', { class: 'rl-filerow-name rl-truncate', title: file.name }, file.name),
					el('div', { class: 'rl-muted', style: 'font-size:var(--rl-text-sm)' }, formatBytes(file.size)),
				),
				toggle,
				download,
			),
			previewHost,
		),
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
				el('a', { class: 'rl-btn rl-btn-secondary', href: '/', style: 'margin-top:var(--rl-space-4)' }, 'Go to RoeShare'),
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
	return decryptFile(e2eKey, cipher, file.cs);
}

function saveBytes(bytes, name, mime) {
	const url = URL.createObjectURL(new Blob([bytes], { type: mime || 'application/octet-stream' }));
	const a = el('a', { href: url, download: name });
	document.body.append(a);
	a.click();
	a.remove();
	setTimeout(() => URL.revokeObjectURL(url), 30000);
}

async function e2ePreview(file, host) {
	host.replaceChildren(el('div', { class: 'rl-center', style: 'padding:var(--rl-space-4)' }, el('span', { class: 'rl-spinner' })));
	try {
		const plain = await e2eFetch(file, false);
		const kind = previewKind(file.mime, file.name);
		if (kind === 'text') {
			host.replaceChildren(el('pre', { class: 'rl-preview-text' }, new TextDecoder().decode(plain)));
			return;
		}
		const url = URL.createObjectURL(new Blob([plain], { type: file.mime || 'application/octet-stream' }));
		let node;
		if (kind === 'image') node = el('img', { src: url, alt: file.name, loading: 'lazy' });
		else if (kind === 'video') node = el('video', { src: url, controls: true });
		else if (kind === 'audio') node = el('audio', { src: url, controls: true });
		else if (kind === 'pdf') node = el('iframe', { src: url, title: file.name });
		else node = el('p', { class: 'rl-dim' }, 'No preview for this type.');
		host.replaceChildren(el('div', { class: 'rl-preview' }, node));
	} catch (e) {
		const msg = e instanceof ApiError && e.status === 403 ? 'Preview is not available for one-time shares - use Download.' : 'Could not decrypt the preview.';
		host.replaceChildren(el('p', { class: 'rl-dim', style: 'padding:var(--rl-space-2)' }, msg));
	}
}

function e2eFileCard(file) {
	const kind = previewKind(file.mime, file.name);
	const previewHost = el('div', { class: 'rl-stack' });
	const base = file.name.split('/').pop() || file.name;

	let toggle = null;
	if (kind !== 'none') {
		let shown = false;
		toggle = el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm' }, 'Preview');
		toggle.addEventListener('click', async () => {
			shown = !shown;
			toggle.textContent = shown ? 'Hide' : 'Preview';
			if (shown) await e2ePreview(file, previewHost);
			else previewHost.replaceChildren();
		});
	}

	const download = el('button', { class: 'rl-btn rl-btn-primary rl-btn-sm' }, 'Download');
	download.addEventListener('click', async () => {
		const label = download.textContent;
		download.disabled = true;
		download.textContent = 'Decrypting...';
		try {
			saveBytes(await e2eFetch(file, true), base, file.mime);
		} catch (e) {
			toastErr(e instanceof ApiError && e.status === 410 ? 'Download limit reached' : 'Could not download');
		}
		download.disabled = false;
		download.textContent = label;
	});

	return el('div', { class: 'rl-card rl-card-pad-sm' },
		el('div', { class: 'rl-stack' },
			el('div', { class: 'rl-row rl-row-wrap' },
				el('div', { class: 'rl-filerow-icon' }, fileGlyph(file.mime, file.name)),
				el('div', { class: 'rl-filerow-meta' },
					el('div', { class: 'rl-filerow-name rl-truncate', title: file.name }, file.name),
					el('div', { class: 'rl-muted', style: 'font-size:var(--rl-text-sm)' }, formatBytes(file.size)),
				),
				toggle,
				download,
			),
			previewHost,
		),
	);
}

// ---- Owner controls --------------------------------------------------------

function ownerBar() {
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
							await api.del(`/api/shares/${encodeURIComponent(shareId)}`, { headers: { 'X-Edit-Token': editToken } });
							location.href = '/';
						} catch (err) {
							toastErr(err);
						}
					},
				},
			],
		});
	});

	return el('div', { class: 'rl-row rl-row-wrap' },
		el('span', { class: 'rl-badge rl-badge-gold' }, 'You own this share'),
		el('span', { class: 'rl-spacer' }),
		del,
	);
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
	const totalSize = share.totalSize != null ? share.totalSize : files.reduce((s, f) => s + (f.size || 0), 0);
	const limit = share.maxDownloads ? `${share.downloadCount}/${share.maxDownloads}` : `${share.downloadCount}`;

	const head = el('div', { class: 'rl-stack' },
		el('div', { class: 'rl-row rl-row-wrap' },
			el('h1', { class: 'rl-h1', style: 'margin:0' }, share.title || 'Shared files'),
			share.e2e ? el('span', { class: 'rl-badge rl-badge-gold' }, 'End-to-end encrypted') : null,
		),
		el('div', { class: 'rl-row rl-row-wrap rl-muted', style: 'font-size:var(--rl-text-sm)' },
			el('span', null, `${count} ${count === 1 ? 'file' : 'files'}`),
			el('span', { class: 'rl-dim' }, '•'),
			el('span', null, formatBytes(totalSize)),
			el('span', { class: 'rl-dim' }, '•'),
			el('span', null, `Expires in ${timeUntil(share.expiresAt)}`),
			el('span', { class: 'rl-dim' }, '•'),
			el('span', null, `Downloads ${limit}`),
		),
	);

	if (editToken) head.append(ownerBar());

	// Actions: copy link always; QR code; download-all for multi-file shares.
	const actions = el('div', { class: 'rl-row rl-row-wrap' },
		el('button', { class: 'rl-btn rl-btn-secondary', onClick: () => copyText(location.href) }, 'Copy link'),
		el('button', { class: 'rl-btn rl-btn-secondary', onClick: () => openQrModal(location.href) }, 'QR code'),
		count > 1 && !share.e2e
			? el('a', { class: 'rl-btn rl-btn-accent', href: withAccess(`/api/shares/${encodeURIComponent(shareId)}/download-all`) }, 'Download all (zip)')
			: null,
	);
	head.append(actions);

	if (share.oneTime) {
		head.append(el('div', { class: 'rl-alert rl-alert-warning' }, 'This is a one-time share - the first download removes it for everyone.'));
	}

	root.append(head);

	if (!count) {
		root.append(el('div', { class: 'rl-card' }, el('div', { class: 'rl-empty' }, 'No files in this share.')));
		return;
	}

	const list = el('div', { class: 'rl-stack' });
	for (const f of files) list.append(fileCard(f));
	root.append(list);
}

// ---- Load ------------------------------------------------------------------

async function load() {
	try {
		// Send both tokens: a valid edit token identifies the owner (so an owner of
		// a protected share is not forced through the password gate), and the
		// access token unlocks a password share for a visitor.
		const headers = {};
		if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
		if (editToken) headers['X-Edit-Token'] = editToken;
		const opts = Object.keys(headers).length ? { headers } : undefined;
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
					const meta = JSON.parse(await decryptString(e2eKey, f.name));
					f.name = meta.name;
					f.mime = meta.mime;
					f.cs = meta.cs;
				}
			} catch {
				return renderE2eError('Could not decrypt this share', 'The key may be wrong, or the data was tampered with.');
			}
		}
		renderShare(share);
	} catch (err) {
		if (err instanceof ApiError && err.status === 404) {
			renderMissing();
		} else if (err instanceof ApiError && err.status === 401 && err.data && err.data.protected) {
			renderPasswordForm(err.data.title);
		} else {
			clear();
			renderMissing();
			toastErr(err);
		}
	}
}

if (!shareId) renderMissing();
else load();
