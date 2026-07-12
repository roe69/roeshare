// Shared frontend utilities for every RoeShare page: a tiny DOM helper, an API
// client, toasts, a modal, and formatting helpers. No build step - imported as
// an ES module via <script type="module">.

// ---- DOM -------------------------------------------------------------------

export function el(tag, props = {}, ...children) {
	const node = document.createElement(tag);
	for (const [k, v] of Object.entries(props || {})) {
		if (v == null || v === false) continue;
		if (k === 'class') node.className = v;
		else if (k === 'html') node.innerHTML = v;
		else if (k === 'dataset') Object.assign(node.dataset, v);
		else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
		else if (k in node && k !== 'list') node[k] = v;
		else node.setAttribute(k, v);
	}
	for (const c of children.flat()) {
		if (c == null || c === false) continue;
		node.append(c.nodeType ? c : document.createTextNode(String(c)));
	}
	return node;
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function escapeHtml(s) {
	return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

// ---- API client ------------------------------------------------------------

export class ApiError extends Error {
	constructor(status, message, data) {
		super(message);
		this.status = status;
		this.data = data;
	}
}

async function request(method, url, body, opts = {}) {
	const headers = { ...(opts.headers || {}) };
	let payload = body;
	if (body !== undefined && !(body instanceof Blob) && !(body instanceof ArrayBuffer) && !(body instanceof FormData) && !(body instanceof Uint8Array)) {
		headers['Content-Type'] = 'application/json';
		payload = JSON.stringify(body);
	}
	const res = await fetch(url, { method, headers, body: payload, ...opts.fetch });
	const ct = res.headers.get('content-type') || '';
	const data = ct.includes('application/json') ? await res.json().catch(() => null) : await res.text();
	if (!res.ok) throw new ApiError(res.status, (data && data.error) || res.statusText, data);
	return data;
}

export const api = {
	get: (url, opts) => request('GET', url, undefined, opts),
	post: (url, body, opts) => request('POST', url, body, opts),
	put: (url, body, opts) => request('PUT', url, body, opts),
	patch: (url, body, opts) => request('PATCH', url, body, opts),
	del: (url, opts) => request('DELETE', url, undefined, opts),
	raw: request,
};

// ---- Toasts ----------------------------------------------------------------

let toastHost;
function toastContainer() {
	if (!toastHost) {
		toastHost = el('div', { class: 'rl-toasts', role: 'status', 'aria-live': 'polite' });
		document.body.append(toastHost);
	}
	return toastHost;
}

export function toast(message, type = 'info', ms = 4000) {
	const node = el('div', { class: `rl-toast rl-toast-${type}` }, message);
	toastContainer().append(node);
	setTimeout(() => {
		node.style.opacity = '0';
		node.style.transition = 'opacity .3s';
		setTimeout(() => node.remove(), 300);
	}, ms);
	return node;
}
export const toastOk = m => toast(m, 'success');
export const toastErr = m => toast(describeError(m), 'error');

// Turn any thrown value into a friendly message. A 429 ApiError carrying a
// retryAfter (seconds, from the server body) becomes a precise retry hint.
export function describeError(err) {
	if (typeof err === 'string') return err;
	if (err && err.status === 429) {
		const ra = Number(err.data && err.data.retryAfter);
		if (Number.isFinite(ra) && ra > 0) return `Too many requests. Try again in ${formatDuration(ra)}.`;
		return 'Too many requests. Please slow down.';
	}
	return (err && err.message) || 'Something went wrong';
}

// ---- Modal -----------------------------------------------------------------

// open({ title, body, actions }) -> { close }. `body` and each action label may
// be a string or a DOM node. Actions: [{ label, variant, onClick }].
let modalSeq = 0;
const FOCUSABLE = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

export function openModal({ title = '', body, actions = [], onClose } = {}) {
	const titleId = `rl-modal-title-${++modalSeq}`;
	const prevFocus = document.activeElement;
	const content = el('div', { class: 'rl-modal', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, tabindex: '-1' });
	const close = () => {
		overlay.remove();
		document.removeEventListener('keydown', onKey);
		try {
			prevFocus?.focus?.();
		} catch {}
		onClose?.();
	};
	const onKey = e => {
		if (e.key === 'Escape') {
			close();
			return;
		}
		if (e.key !== 'Tab') return;
		// Trap focus inside the dialog.
		const items = [...content.querySelectorAll(FOCUSABLE)].filter(n => !n.disabled && n.offsetParent !== null);
		if (!items.length) return;
		const first = items[0];
		const last = items[items.length - 1];
		if (e.shiftKey && document.activeElement === first) {
			e.preventDefault();
			last.focus();
		} else if (!e.shiftKey && document.activeElement === last) {
			e.preventDefault();
			first.focus();
		}
	};
	content.append(
		el('div', { class: 'rl-modal-header' }, el('h2', { class: 'rl-h2', id: titleId, style: 'margin:0' }, title), el('button', { class: 'rl-btn rl-btn-ghost rl-icon-btn', onClick: close, 'aria-label': 'Close' }, '✕')),
	);
	if (body) content.append(body.nodeType ? body : el('div', { html: body }));
	if (actions.length) {
		const footer = el('div', { class: 'rl-row', style: 'justify-content:flex-end;margin-top:var(--rl-space-6)' });
		for (const a of actions) {
			footer.append(
				el('button', {
					class: `rl-btn rl-btn-${a.variant || 'secondary'}`,
					onClick: async () => {
						const keep = await a.onClick?.();
						if (keep !== true) close();
					},
				}, a.label),
			);
		}
		content.append(footer);
	}
	const overlay = el('div', { class: 'rl-modal-overlay', onClick: e => e.target === overlay && close() }, content);
	document.body.append(overlay);
	document.addEventListener('keydown', onKey);
	// Move focus into the dialog (first field if any, else the dialog itself).
	const firstField = content.querySelector('input, select, textarea, button.rl-btn-primary');
	(firstField || content).focus();
	return { close, content };
}

// ---- Formatting ------------------------------------------------------------

export function formatBytes(bytes) {
	if (!bytes && bytes !== 0) return '-';
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	let n = bytes;
	let i = 0;
	while (n >= 1024 && i < units.length - 1) {
		n /= 1024;
		i++;
	}
	return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

export function formatDate(ts) {
	if (!ts) return '-';
	return new Date(ts * 1000).toLocaleString();
}

// Human "time until" for an epoch-seconds timestamp; null/0 -> "Never".
export function timeUntil(ts) {
	if (!ts) return 'Never';
	let s = ts - Math.floor(Date.now() / 1000);
	if (s <= 0) return 'Expired';
	const d = Math.floor(s / 86400);
	if (d >= 1) return `${d}d`;
	const h = Math.floor(s / 3600);
	if (h >= 1) return `${h}h`;
	const m = Math.floor(s / 60);
	if (m >= 1) return `${m}m`;
	return `${s}s`;
}

// Compact, human "time remaining" from a number of seconds: "45s", "4m 12s",
// "1h 5m". Rounds up and floors at 1s so it never reads "0". Used for retry-after.
export function formatDuration(seconds) {
	const s = Math.max(1, Math.ceil(Number(seconds) || 0));
	const h = Math.floor(s / 3600);
	const m = Math.floor((s % 3600) / 60);
	const sec = s % 60;
	if (h >= 1) return m ? `${h}h ${m}m` : `${h}h`;
	if (m >= 1) return sec ? `${m}m ${sec}s` : `${m}m`;
	return `${sec}s`;
}

export async function copyText(text) {
	try {
		await navigator.clipboard.writeText(text);
		toastOk('Copied to clipboard');
	} catch {
		toastErr('Copy failed');
	}
}

// Map a mime/extension to a representative emoji glyph for file rows.
export function fileGlyph(mime = '', name = '') {
	const m = mime.toLowerCase();
	const ext = name.split('.').pop().toLowerCase();
	if (m.startsWith('image/')) return '\u{1F5BC}';
	if (m.startsWith('video/')) return '\u{1F3AC}';
	if (m.startsWith('audio/')) return '\u{1F3B5}';
	if (m === 'application/pdf' || ext === 'pdf') return '\u{1F4C4}';
	if (/zip|tar|gz|rar|7z/.test(m) || /zip|tar|gz|rar|7z/.test(ext)) return '\u{1F5DC}';
	if (m.startsWith('text/') || /json|js|ts|css|html|md|xml|csv|log/.test(ext)) return '\u{1F4DD}';
	return '\u{1F4E6}';
}

// ---- Owned shares (M-05) -----------------------------------------------------
// Shares this browser created, tracked by id only - share ids are not secret,
// unlike the raw edit token the old `roeshare:edit:<id>` localStorage map used
// to hold. Ownership itself now lives in an HttpOnly, per-share cookie minted
// by POST /api/shares/:id/owner-session, which page script (and so an XSS
// payload) can never read - this list is only a "which ids might be mine"
// index so my-shares/sidebar can enumerate what to ask the server about.

const OWNED_KEY = 'roeshare:owned';

export function readOwnedShares() {
	try {
		const ids = JSON.parse(localStorage.getItem(OWNED_KEY) || '[]');
		return Array.isArray(ids) ? ids.filter(id => typeof id === 'string') : [];
	} catch {
		return [];
	}
}

export function addOwnedShare(id) {
	try {
		const ids = readOwnedShares();
		if (!ids.includes(id)) {
			ids.push(id);
			localStorage.setItem(OWNED_KEY, JSON.stringify(ids));
		}
	} catch {
		/* quota/private mode: the share still works, just won't list on this device */
	}
}

export function removeOwnedShare(id) {
	try {
		localStorage.setItem(OWNED_KEY, JSON.stringify(readOwnedShares().filter(x => x !== id)));
	} catch {
		/* ignore */
	}
}

// One-release migration from the pre-M-05 `roeshare:edit:<id>` -> raw edit
// token localStorage entries to the owner-session cookie + owned-ids list
// above. For each legacy entry: exchange the token once (best effort - an
// expired/dead share's exchange simply fails and is dropped anyway), add the
// id to the owned list, and remove the legacy entry regardless of outcome, so
// a stale raw token never lingers in localStorage. Call once on page load
// (view.js / myshares.js); delete this after one release.
const LEGACY_EDIT_PREFIX = 'roeshare:edit:';
export async function migrateLegacyOwnerTokens() {
	let legacy = [];
	try {
		for (let i = 0; i < localStorage.length; i++) {
			const k = localStorage.key(i);
			if (k && k.startsWith(LEGACY_EDIT_PREFIX)) legacy.push({ id: k.slice(LEGACY_EDIT_PREFIX.length), key: k, token: localStorage.getItem(k) });
		}
	} catch {
		return;
	}
	for (const { id, key, token } of legacy) {
		if (token) {
			try {
				await fetch(`/api/shares/${encodeURIComponent(id)}/owner-session`, { method: 'POST', headers: { 'X-Edit-Token': token } });
			} catch {
				/* best effort - the id still gets carried forward below */
			}
		}
		addOwnedShare(id);
		try {
			localStorage.removeItem(key);
		} catch {
			/* ignore */
		}
	}
}

// What kind of inline preview a file supports.
export function previewKind(mime = '', name = '') {
	const m = mime.toLowerCase();
	const ext = name.split('.').pop().toLowerCase();
	if (m.startsWith('image/')) return 'image';
	if (m.startsWith('video/')) return 'video';
	if (m.startsWith('audio/')) return 'audio';
	if (m === 'application/pdf' || ext === 'pdf') return 'pdf';
	if (m.startsWith('text/') || /^(txt|md|markdown|json|js|mjs|ts|jsx|tsx|css|html|xml|csv|log|yml|yaml|ini|sh|py|java|c|cpp|h|go|rs|rb|php|sql)$/.test(ext)) return 'text';
	return 'none';
}
