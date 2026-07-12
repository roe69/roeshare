// "My shares" page: lists the shares this browser created, tracked by the
// owned-share id list in localStorage (see shared.js's readOwnedShares). M-05:
// ownership itself is proven server-side by each share's own HttpOnly
// owner-session cookie (path/name-scoped per share id), not by a raw edit
// token this page used to hold - sending the request is enough, the browser
// attaches whichever share's cookie matches automatically. Everything is
// resolved live from the server (so counts/expiry are current); ids whose
// share is gone, or that the cookie no longer proves ownership of, are pruned
// automatically.

import { el, $, api, ApiError, toastErr, toastOk, copyText, openModal, formatBytes, timeUntil, readOwnedShares, removeOwnedShare, migrateLegacyOwnerTokens } from '/js/shared.js';
import { mountSidebar } from '/js/sidebar.js';

mountSidebar({ active: 'mine' });

const root = $('#mine');

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
	const { id, share } = entry;
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
					// No X-Edit-Token header: ownership is proven by this share's
					// owner-session cookie, sent automatically.
					label: 'Delete', variant: 'danger', onClick: async () => {
						try {
							await api.del(`/api/shares/${encodeURIComponent(id)}`);
							removeOwnedShare(id);
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
	// One-release migration (M-05): carry forward any pre-M-05 raw edit tokens
	// into owner-session cookies + the owned-ids list before reading the list.
	await migrateLegacyOwnerTokens();

	const ids = readOwnedShares();
	if (!ids.length) return renderEmpty();

	const results = await Promise.all(ids.map(async id => {
		try {
			const share = await api.get(`/api/shares/${encodeURIComponent(id)}`);
			// The cookie no longer proves ownership (expired, cleared, or this
			// browser never actually owned it) - prune it, same as a 404.
			if (!share.owner) {
				removeOwnedShare(id);
				return null;
			}
			return { id, share };
		} catch (err) {
			// 404 = gone for good: drop the stale id. Other errors: skip this round.
			if (err instanceof ApiError && err.status === 404) removeOwnedShare(id);
			return null;
		}
	}));

	const live = results.filter(Boolean);
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
