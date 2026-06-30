// API-key portal (/api). Sign in with a key name + its token to manage the
// shares that key created - list, download (restore), and delete (rotate) - the
// same things the programmatic API offers, from the browser. The session is a
// cookie set by /api/v1/login; all data comes from the cookie-authenticated
// /api/v1 endpoints, so this script holds no secrets.

import { el, $, api, ApiError, toastOk, toastErr, openModal, formatBytes, timeUntil } from '/js/shared.js';
import { mountSidebar } from '/js/sidebar.js';

mountSidebar({ active: 'api' });

const root = $('#api');
const shareUrl = id => `${location.origin}/${id}`;

// ---- Login -----------------------------------------------------------------

function renderLogin() {
	const name = el('input', { class: 'rl-input', type: 'text', placeholder: 'Key name', autocomplete: 'username', autofocus: true });
	const token = el('input', { class: 'rl-input', type: 'password', placeholder: 'rsk_...', autocomplete: 'current-password', spellcheck: false });
	const btn = el('button', { class: 'rl-btn rl-btn-primary rl-btn-block', type: 'submit' }, 'Sign in');

	const form = el('form', { class: 'rl-card rl-stack' },
		el('div', { class: 'rl-center' },
			el('h1', { class: 'rl-h2' }, 'API portal'),
			el('p', { class: 'rl-muted' }, 'Sign in with a key name and its token to manage that key\'s shares.'),
		),
		el('div', { class: 'rl-field' }, el('label', { class: 'rl-label' }, 'Key name'), name),
		el('div', { class: 'rl-field' }, el('label', { class: 'rl-label' }, 'Token'), token),
		btn,
	);
	form.addEventListener('submit', async e => {
		e.preventDefault();
		if (!name.value.trim() || !token.value.trim()) return;
		btn.disabled = true;
		try {
			const session = await api.post('/api/v1/login', { name: name.value.trim(), token: token.value.trim() });
			renderPortal(session);
		} catch (err) {
			if (err instanceof ApiError && err.status === 403) toastErr('That name and token do not match an active key');
			else toastErr(err);
			btn.disabled = false;
			token.focus();
			token.select();
		}
	});

	root.replaceChildren(el('div', { style: 'max-width:420px;margin:var(--rl-space-12) auto 0' }, form));
	name.focus();
}

async function logout() {
	try {
		await api.post('/api/v1/logout', {});
	} catch {
		/* clear the view anyway */
	}
	renderLogin();
}

// ---- Portal ----------------------------------------------------------------

function renderPortal(session) {
	const header = el('div', { class: 'rl-row rl-row-wrap', style: 'justify-content:space-between;align-items:flex-end' },
		el('div', {},
			el('h1', { class: 'rl-h1', style: 'margin:0' }, 'API portal'),
			el('p', { class: 'rl-muted', style: 'margin:var(--rl-space-1) 0 0' }, 'Signed in as ', el('strong', {}, session.name)),
		),
		el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm', onClick: logout }, 'Sign out'),
	);
	const listHost = el('div', { class: 'rl-files' });
	root.replaceChildren(header, el('section', { class: 'rl-card rl-files-card', style: 'margin-top:var(--rl-space-4)' }, listHost));
	loadShares(listHost);
}

async function loadShares(host) {
	host.replaceChildren(el('div', { class: 'rl-center', style: 'padding:var(--rl-space-6)' }, el('span', { class: 'rl-spinner' })));
	try {
		const { shares } = await api.get('/api/v1/shares?limit=500');
		if (!shares || !shares.length) {
			host.replaceChildren(el('div', { class: 'rl-empty' },
				el('div', { class: 'rl-empty-icon' }, '\u{1F4E6}'),
				el('p', {}, 'This key has not created any shares yet.'),
			));
			return;
		}
		host.replaceChildren(...shares.map(s => shareRow(s, host)));
	} catch (err) {
		if (err instanceof ApiError && err.status === 401) return renderLogin(); // session lapsed
		toastErr(err);
		host.replaceChildren(el('p', { class: 'rl-dim rl-center', style: 'padding:var(--rl-space-4)' }, 'Could not load shares.'));
	}
}

function shareRow(s, host) {
	const sub = `${s.fileCount} ${s.fileCount === 1 ? 'file' : 'files'} · ${formatBytes(s.totalSize)} · ${s.downloadCount} dl · ${s.expiresAt ? 'expires ' + timeUntil(s.expiresAt) : 'never expires'}`;

	// Files are loaded on demand into a collapsible panel, each with a direct
	// download link (the session cookie authorizes the download).
	const filesBox = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1);margin-top:var(--rl-space-2)', hidden: true });
	let loaded = false;
	const filesBtn = el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm' }, 'Files');
	filesBtn.addEventListener('click', async () => {
		filesBox.hidden = !filesBox.hidden;
		if (loaded || filesBox.hidden) return;
		loaded = true;
		filesBox.replaceChildren(el('span', { class: 'rl-spinner' }));
		try {
			const d = await api.get(`/api/v1/shares/${encodeURIComponent(s.id)}`);
			const files = d.files || [];
			filesBox.replaceChildren(...(files.length
				? files.map(f => el('div', { class: 'rl-row', style: 'justify-content:space-between;gap:var(--rl-space-3);font-size:var(--rl-text-sm)' },
						el('span', { class: 'rl-truncate' }, f.name),
						el('a', { class: 'rl-btn rl-btn-ghost rl-btn-sm', href: f.download, download: '' }, `Download ${formatBytes(f.size)}`),
					))
				: [el('p', { class: 'rl-dim' }, 'No files.')]));
		} catch {
			loaded = false;
			filesBox.replaceChildren(el('p', { class: 'rl-dim' }, 'Could not load files.'));
		}
	});

	const open = el('a', { class: 'rl-btn rl-btn-secondary rl-btn-sm', href: shareUrl(s.id), target: '_blank', rel: 'noopener' }, 'Open');
	const del = el('button', { class: 'rl-btn rl-btn-danger rl-btn-sm' }, 'Delete');

	const row = el('div', { class: 'rl-file', style: 'flex-direction:column;align-items:stretch' },
		el('div', { class: 'rl-file-main' },
			el('div', { class: 'rl-file-icon' }, '\u{1F4E6}'),
			el('div', { class: 'rl-file-info' },
				el('div', { class: 'rl-file-name', title: s.title || s.id }, s.title || s.id),
				el('div', { class: 'rl-file-sub' }, sub),
			),
			el('div', { class: 'rl-file-actions' }, filesBtn, open, del),
		),
		filesBox,
	);

	del.addEventListener('click', () => {
		openModal({
			title: 'Delete this share?',
			body: `Permanently delete "${s.title || s.id}" and its files? This cannot be undone.`,
			actions: [
				{ label: 'Cancel', variant: 'ghost' },
				{
					label: 'Delete', variant: 'danger',
					onClick: async () => {
						try {
							await api.del(`/api/v1/shares/${encodeURIComponent(s.id)}`);
							row.remove();
							toastOk('Share deleted');
							if (!host.querySelector('.rl-file')) loadShares(host);
						} catch (err) {
							toastErr(err);
						}
					},
				},
			],
		});
	});
	return row;
}

// ---- Boot ------------------------------------------------------------------

(async () => {
	let session = null;
	try {
		const r = await api.get('/api/v1/session');
		session = r && r.session;
	} catch {
		/* fall through to login */
	}
	if (session) renderPortal(session);
	else renderLogin();
})();
