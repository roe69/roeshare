// "My shares" page: lists the shares this browser created, tracked by the edit
// tokens saved in localStorage at upload time. Everything is resolved live from
// the server (so counts/expiry are current); stale entries whose share is gone
// are pruned automatically. Sending the edit token also identifies us as the
// owner, so password-protected shares resolve without the password and these
// views never inflate the share's view count.

import { el, $, api, ApiError, toastErr, toastOk, copyText, openModal, formatBytes, timeUntil } from '/js/shared.js';
import { mountSidebar } from '/js/sidebar.js';

mountSidebar({ active: 'mine' });

const root = $('#mine');
const EDIT_PREFIX = 'roeshare:edit:';

function ownedEntries() {
	const out = [];
	for (let i = 0; i < localStorage.length; i++) {
		const k = localStorage.key(i);
		if (k && k.startsWith(EDIT_PREFIX)) out.push({ id: k.slice(EDIT_PREFIX.length), token: localStorage.getItem(k) });
	}
	return out;
}

function forget(id) {
	try { localStorage.removeItem(EDIT_PREFIX + id); } catch {}
}

const shareUrl = id => `${location.origin}/${id}`;

function renderEmpty() {
	root.replaceChildren(
		el('div', { class: 'rl-card' },
			el('div', { class: 'rl-empty' },
				el('div', { class: 'rl-empty-icon' }, '\u{1F4E6}'),
				el('div', { class: 'rl-h2' }, 'No shares yet'),
				el('p', { class: 'rl-muted' }, 'Shares you create on this device show up here.'),
				el('a', { class: 'rl-btn rl-btn-primary', href: '/', style: 'margin-top:var(--rl-space-4)' }, 'Create a share'),
			),
		),
	);
}

function shareRow(entry) {
	const { id, token, share } = entry;
	const count = (share.files || []).length;
	const totalSize = share.totalSize != null ? share.totalSize : (share.files || []).reduce((s, f) => s + (f.size || 0), 0);
	const views = share.viewCount || 0;
	const downloads = share.maxDownloads ? `${share.downloadCount}/${share.maxDownloads} dl` : `${share.downloadCount} dl`;
	let expiry = 'never expires';
	if (share.expiresAt) {
		const t = timeUntil(share.expiresAt);
		expiry = t === 'Expired' ? 'expired' : `expires in ${t}`;
	}
	const sub = `${count} ${count === 1 ? 'file' : 'files'} · ${formatBytes(totalSize)} · ${views} view${views === 1 ? '' : 's'} · ${downloads} · ${expiry}`;

	const open = el('a', { class: 'rl-btn rl-btn-secondary rl-btn-sm', href: shareUrl(id), target: '_blank', rel: 'noopener' }, 'Open');
	const copy = el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm', onClick: () => copyText(shareUrl(id)) }, 'Copy');
	const del = el('button', { class: 'rl-btn rl-btn-danger rl-btn-sm' }, 'Delete');

	const row = el('div', { class: 'rl-file' },
		el('div', { class: 'rl-file-main' },
			el('div', { class: 'rl-file-icon' }, '\u{1F4E6}'),
			el('div', { class: 'rl-file-info' },
				el('div', { class: 'rl-file-name', title: share.title || id },
					share.title || id,
					share.e2e ? el('span', { class: 'rl-badge rl-badge-gold', style: 'margin-left:var(--rl-space-2)' }, 'E2E') : null,
				),
				el('div', { class: 'rl-file-sub' }, sub),
			),
			el('div', { class: 'rl-file-actions' }, open, copy, del),
		),
	);

	del.addEventListener('click', () => {
		openModal({
			title: 'Delete this share?',
			body: el('p', {}, 'Permanently delete "', share.title || id, '" and its files? This cannot be undone.'),
			actions: [
				{ label: 'Cancel', variant: 'ghost' },
				{
					label: 'Delete', variant: 'danger', onClick: async () => {
						try {
							await api.del(`/api/shares/${encodeURIComponent(id)}`, { headers: { 'X-Edit-Token': token } });
							forget(id);
							row.remove();
							toastOk('Share deleted');
							if (!root.querySelector('.rl-file')) renderEmpty();
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

async function load() {
	const entries = ownedEntries();
	if (!entries.length) return renderEmpty();

	const results = await Promise.all(entries.map(async e => {
		try {
			const share = await api.get(`/api/shares/${encodeURIComponent(e.id)}`, { headers: { 'X-Edit-Token': e.token } });
			return { ...e, share };
		} catch (err) {
			// 404 = gone for good: drop the stale token. Other errors: skip this round.
			if (err instanceof ApiError && err.status === 404) forget(e.id);
			return null;
		}
	}));

	const live = results.filter(r => r && r.share);
	if (!live.length) return renderEmpty();
	live.sort((a, b) => (b.share.createdAt || 0) - (a.share.createdAt || 0));

	const header = el('div', { class: 'rl-row rl-row-wrap', style: 'justify-content:space-between;align-items:flex-end' },
		el('div', null,
			el('h1', { class: 'rl-h1', style: 'margin:0' }, 'My shares'),
			el('p', { class: 'rl-muted', style: 'margin:var(--rl-space-1) 0 0' }, `${live.length} share${live.length === 1 ? '' : 's'} created on this device.`),
		),
		el('a', { class: 'rl-btn rl-btn-primary rl-btn-sm', href: '/' }, 'New share'),
	);

	const list = el('div', { class: 'rl-files' });
	for (const e of live) list.append(shareRow(e));

	root.replaceChildren(header, el('section', { class: 'rl-card rl-files-card' }, list));
}

load();
