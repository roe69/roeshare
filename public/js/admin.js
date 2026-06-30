// RoeShare admin dashboard. A fixed sidebar rail switches between four views -
// Overview, Shares, Server, and Logs - each rendered into the main column. This
// script is served ONLY to an authenticated admin (the server 404s it
// otherwise), so the management markup and logic never leak.

import {
	el, $, $$, api, ApiError,
	toast, toastOk, toastErr, openModal,
	formatBytes, formatDate, timeUntil, copyText,
} from '/js/shared.js';
import { mountSidebar } from '/js/sidebar.js';

const view = $('#view');
let sidebar; // rail handle from mountSidebar()

// Current shares-table query state.
const state = {
	search: '',
	sort: 'created',
	order: 'desc',
};

const SORTS = {
	newest: { sort: 'created', order: 'desc', label: 'Newest' },
	largest: { sort: 'size', order: 'desc', label: 'Largest' },
	downloads: { sort: 'downloads', order: 'desc', label: 'Most downloaded' },
};

function shareUrl(id) {
	return `${location.origin}/${id}`;
}

// epoch seconds -> value for a datetime-local input (browser local time).
function epochToLocalInput(ts) {
	const d = new Date(ts * 1000);
	const pad = n => String(n).padStart(2, '0');
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// Small labelled field wrapper for the edit form.
function editField(label, control, help) {
	return el('div', { class: 'rl-field' },
		el('label', { class: 'rl-label' }, label),
		control,
		help ? el('p', { class: 'rl-help' }, help) : false,
	);
}

// A view header: big title, optional subtitle, optional actions on the right.
function viewHead(title, subtitle, actions) {
	return el('div', { class: 'rl-view-head' },
		el('div', {},
			el('h1', { class: 'rl-view-title' }, title),
			subtitle ? el('p', { class: 'rl-view-sub' }, subtitle) : false,
		),
		actions ? el('div', { class: 'rl-row rl-row-wrap' }, ...[].concat(actions)) : false,
	);
}

// ---- Sidebar / routing -----------------------------------------------------

const VIEWS = { overview: renderOverview, shares: renderShares, server: renderServer, logs: renderLogs };

// Per-view teardown (e.g. stop the logs poll) run before switching away.
let cleanup = null;

function currentView() {
	const v = location.hash.replace(/^#\/?/, '');
	return VIEWS[v] ? v : 'overview';
}

function navigate() {
	if (cleanup) { cleanup(); cleanup = null; }
	const name = currentView();
	if (sidebar) sidebar.setActive(name);
	view.scrollTop = 0;
	window.scrollTo(0, 0);
	VIEWS[name]();
}

async function logout() {
	try {
		await api.post('/api/admin/logout', {});
	} catch (err) {
		toastErr(err);
	}
	location.href = '/admin';
}

// ---- Boot ------------------------------------------------------------------

async function boot() {
	// The server already gated this page, but the cookie could have lapsed
	// between the page load and now; bounce to the login page if so.
	try {
		const me = await api.get('/api/admin/me');
		if (!me || !me.admin) { location.href = '/admin'; return; }
	} catch {
		/* network hiccup: fall through and let the views surface the error */
	}

	// The shared rail, with the dashboard sections on top and an account footer.
	const go = id => () => { location.hash = `#/${id}`; };
	sidebar = mountSidebar({
		active: currentView(),
		groups: [
			{ label: 'Dashboard', items: [
				{ id: 'overview', label: 'Overview', icon: 'overview', onClick: go('overview') },
				{ id: 'shares', label: 'Shares', icon: 'shares', onClick: go('shares') },
				{ id: 'server', label: 'Server', icon: 'server', onClick: go('server') },
				{ id: 'logs', label: 'Logs', icon: 'logs', onClick: go('logs') },
			] },
			{ label: 'Browse', items: [
				{ id: 'upload', label: 'Upload', icon: 'upload', href: '/' },
				{ id: 'mine', label: 'My shares', icon: 'files', href: '/mine' },
			] },
		],
		account: { name: 'Admin', onLogout: logout },
	});

	window.addEventListener('hashchange', navigate);
	navigate();
}

// ===========================================================================
// Overview
// ===========================================================================

function statCard(label, value, extra) {
	return el('div', { class: 'rl-card rl-card-pad-sm' },
		el('div', { class: 'rl-eyebrow', style: 'margin-bottom:var(--rl-space-2)' }, label),
		el('div', { style: 'font-size:var(--rl-text-3xl);font-weight:var(--rl-weight-bold);line-height:1.1' }, value),
		extra ? el('div', { style: 'margin-top:var(--rl-space-3)' }, extra) : false,
	);
}

function infoRow(label, value) {
	return el('div', { class: 'rl-row', style: 'justify-content:space-between;gap:var(--rl-space-4);font-size:var(--rl-text-sm)' },
		el('span', { class: 'rl-muted' }, label),
		el('span', { class: 'rl-mono rl-truncate', style: 'max-width:60%;text-align:right' }, value),
	);
}

function renderOverview() {
	const statsRow = el('div', {
		id: 'stats',
		style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:var(--rl-space-4)',
	});
	const instanceHost = el('div', { class: 'rl-card rl-stack', style: 'gap:var(--rl-space-2)' },
		el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Instance'),
		el('div', { class: 'rl-center', style: 'padding:var(--rl-space-4)' }, el('span', { class: 'rl-spinner' })),
	);
	const recentHost = el('div', { class: 'rl-card rl-stack', style: 'gap:var(--rl-space-2)' },
		el('div', { class: 'rl-row', style: 'justify-content:space-between' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg);margin:0' }, 'Recent shares'),
			el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm', onclick: () => { location.hash = '#/shares'; } }, 'View all'),
		),
		el('div', { class: 'rl-center', style: 'padding:var(--rl-space-4)' }, el('span', { class: 'rl-spinner' })),
	);

	view.replaceChildren(
		viewHead('Overview', 'A snapshot of this RoeShare instance.'),
		statsRow,
		el('div', { style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:var(--rl-space-4);margin-top:var(--rl-space-4)' },
			instanceHost,
			recentHost,
		),
	);

	loadStats();
	loadInstance(instanceHost);
	loadRecent(recentHost);
}

async function loadStats() {
	const host = $('#stats');
	if (!host) return;
	try {
		const s = await api.get('/api/admin/stats');
		let storageExtra = false;
		if (s.maxTotalSize > 0) {
			const pct = Math.min(100, Math.round((s.storageUsed / s.maxTotalSize) * 100));
			storageExtra = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1)' },
				el('div', { class: 'rl-progress' },
					el('div', { class: 'rl-progress-bar', style: `width:${pct}%` }),
				),
				el('div', { class: 'rl-help' }, `${formatBytes(s.storageUsed)} of ${formatBytes(s.maxTotalSize)}`),
			);
		}
		host.replaceChildren(
			statCard('Shares', String(s.shareCount ?? 0)),
			statCard('Files', String(s.fileCount ?? 0)),
			statCard('Storage used', formatBytes(s.storageUsed ?? 0), storageExtra),
			statCard('Total views', String(s.viewTotal ?? 0)),
			statCard('Total downloads', String(s.downloadTotal ?? 0)),
		);
	} catch (err) {
		toastErr(err);
		host.replaceChildren(el('p', { class: 'rl-dim' }, 'Stats unavailable.'));
	}
}

async function loadInstance(host) {
	const body = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' });
	try {
		const [settings, health] = await Promise.all([
			api.get('/api/admin/settings'),
			fetch('/healthz', { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(() => null),
		]);
		const ro = settings.readOnly || {};
		const up = health && Number.isFinite(health.uptime) ? formatUptime(health.uptime) : '-';
		body.append(
			infoRow('Status', 'Online'),
			infoRow('Uptime', up),
			infoRow('Host', `${ro.HOST || '-'}:${ro.PORT || '-'}`),
			infoRow('Data dir', ro.DATA_DIR || '-'),
		);
		if (settings.ephemeralSecret) {
			body.append(el('div', { class: 'rl-alert rl-alert-warning', style: 'font-size:var(--rl-text-xs)' },
				'SECRET is unset: sessions and encrypted uploads will not survive a restart. Set one in Server settings.'));
		}
	} catch {
		body.append(el('p', { class: 'rl-dim' }, 'Instance info unavailable.'));
	}
	host.replaceChildren(
		el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Instance'),
		body,
	);
}

function formatUptime(s) {
	const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
	if (d) return `${d}d ${h}h`;
	if (h) return `${h}h ${m}m`;
	if (m) return `${m}m`;
	return `${Math.floor(s)}s`;
}

async function loadRecent(host) {
	const list = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1)' });
	try {
		const data = await api.get('/api/admin/shares?sort=created&order=desc&limit=6');
		const shares = (data && data.shares) || [];
		if (!shares.length) {
			list.append(el('p', { class: 'rl-dim' }, 'No shares yet.'));
		} else {
			for (const s of shares) {
				list.append(el('button', {
					class: 'rl-row', style: 'justify-content:space-between;gap:var(--rl-space-3);width:100%;background:transparent;border:0;padding:var(--rl-space-2);border-radius:var(--rl-radius-sm);cursor:pointer;text-align:left;color:inherit',
					onclick: () => openDetail(s.id),
				},
					el('span', { class: 'rl-truncate', style: 'font-weight:var(--rl-weight-semibold)' }, s.title || s.id),
					el('span', { class: 'rl-dim', style: 'font-size:var(--rl-text-xs);flex-shrink:0' }, `${formatBytes(s.totalSize ?? 0)} - ${timeUntil(s.expiresAt)}`),
				));
			}
		}
	} catch {
		list.append(el('p', { class: 'rl-dim' }, 'Could not load recent shares.'));
	}
	host.replaceChildren(
		el('div', { class: 'rl-row', style: 'justify-content:space-between' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg);margin:0' }, 'Recent shares'),
			el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm', onclick: () => { location.hash = '#/shares'; } }, 'View all'),
		),
		list,
	);
}

// ===========================================================================
// Shares
// ===========================================================================

let tbody;
let headerCheckbox;
let rowsById = new Map();

function renderShares() {
	rowsById = new Map();

	const searchInput = el('input', {
		class: 'rl-input', type: 'search', placeholder: 'Search shares...',
		style: 'max-width:320px',
	});
	searchInput.value = state.search;
	let debounce;
	searchInput.addEventListener('input', () => {
		clearTimeout(debounce);
		debounce = setTimeout(() => {
			state.search = searchInput.value.trim();
			loadShares();
		}, 250);
	});

	const sortSelect = el('select', { class: 'rl-select', style: 'max-width:200px' },
		...Object.entries(SORTS).map(([key, v]) => el('option', { value: key }, v.label)),
	);
	sortSelect.addEventListener('change', () => {
		const s = SORTS[sortSelect.value];
		state.sort = s.sort;
		state.order = s.order;
		loadShares();
	});

	const bulkBtn = el('button', {
		id: 'bulk-delete', class: 'rl-btn rl-btn-danger rl-btn-sm', disabled: true,
		onclick: bulkDelete,
	}, 'Delete selected');

	const toolbar = el('div', { class: 'rl-row rl-row-wrap', style: 'margin-bottom:var(--rl-space-4)' },
		searchInput,
		sortSelect,
		el('span', { class: 'rl-spacer' }),
		bulkBtn,
	);

	headerCheckbox = el('input', {
		type: 'checkbox', 'aria-label': 'Select all',
		onchange: () => {
			$$('.row-check', tbody).forEach(c => { c.checked = headerCheckbox.checked; });
			updateBulkState();
		},
	});

	tbody = el('tbody');

	const table = el('div', { style: 'overflow-x:auto' },
		el('table', { class: 'rl-table' },
			el('thead', {},
				el('tr', {},
					el('th', { style: 'width:36px' }, headerCheckbox),
					el('th', {}, 'Share'),
					el('th', { class: 'rl-col-num' }, 'Files'),
					el('th', { class: 'rl-col-num' }, 'Size'),
					el('th', { class: 'rl-col-num' }, 'Views'),
					el('th', { class: 'rl-col-num' }, 'Downloads'),
					el('th', { class: 'rl-col-w' }, 'Created'),
					el('th', { class: 'rl-col-w' }, 'Expires'),
					el('th', {}, 'Flags'),
					el('th', { style: 'text-align:right' }, 'Actions'),
				),
			),
			tbody,
		),
	);

	view.replaceChildren(
		viewHead('Shares', 'Browse, edit, and delete every share on this instance.'),
		toolbar,
		el('div', { class: 'rl-card', style: 'padding:0;overflow:hidden' }, table),
	);

	loadShares();
}

function colspanRow(content) {
	return el('tr', {}, el('td', { colspan: 10 }, content));
}

async function loadShares() {
	if (!tbody) return;
	tbody.replaceChildren(colspanRow(
		el('div', { class: 'rl-center', style: 'padding:var(--rl-space-6)' }, el('span', { class: 'rl-spinner' })),
	));
	rowsById = new Map();
	if (headerCheckbox) headerCheckbox.checked = false;

	const params = new URLSearchParams({
		sort: state.sort,
		order: state.order,
		limit: '200',
		offset: '0',
	});
	if (state.search) params.set('search', state.search);

	try {
		const data = await api.get(`/api/admin/shares?${params}`);
		const shares = (data && data.shares) || [];
		if (!shares.length) {
			tbody.replaceChildren(colspanRow(
				el('div', { class: 'rl-empty' },
					el('div', { class: 'rl-empty-icon' }, '\u{1F4ED}'),
					el('p', {}, state.search ? 'No shares match your search.' : 'No shares yet.'),
				),
			));
			updateBulkState();
			return;
		}
		tbody.replaceChildren(...shares.map(renderRow));
		updateBulkState();
	} catch (err) {
		toastErr(err);
		tbody.replaceChildren(colspanRow(el('p', { class: 'rl-dim rl-center' }, 'Could not load shares.')));
	}
}

function renderRow(s) {
	const check = el('input', { type: 'checkbox', class: 'row-check', 'aria-label': 'Select share' });
	check.addEventListener('change', updateBulkState);
	check.addEventListener('click', e => e.stopPropagation());

	const link = el('a', {
		href: shareUrl(s.id), target: '_blank', rel: 'noopener',
		style: 'font-weight:var(--rl-weight-semibold);text-decoration:none;color:var(--rl-primary)',
		onclick: e => e.stopPropagation(),
	}, s.title || s.id);

	const idLine = el('div', { class: 'rl-mono rl-dim', style: 'font-size:var(--rl-text-xs)' }, s.id);

	const dl = s.maxDownloads > 0 ? `${s.downloadCount} / ${s.maxDownloads}` : String(s.downloadCount);

	const flags = el('div', { class: 'rl-row', style: 'gap:var(--rl-space-1);flex-wrap:wrap' });
	if (s.protected) flags.append(el('span', { class: 'rl-badge rl-badge-gold' }, 'Locked'));
	if (s.oneTime) flags.append(el('span', { class: 'rl-badge rl-badge-warning' }, 'One-time'));
	if (!s.finalized) flags.append(el('span', { class: 'rl-badge rl-badge-neutral' }, 'Draft'));

	const actions = el('div', { class: 'rl-row', style: 'gap:var(--rl-space-1);justify-content:flex-end' },
		el('button', {
			class: 'rl-btn rl-btn-ghost rl-btn-sm', title: 'Copy link',
			onclick: e => { e.stopPropagation(); copyText(shareUrl(s.id)); },
		}, 'Copy'),
		el('a', {
			class: 'rl-btn rl-btn-ghost rl-btn-sm', href: shareUrl(s.id), target: '_blank', rel: 'noopener',
			onclick: e => e.stopPropagation(),
		}, 'Open'),
		el('button', {
			class: 'rl-btn rl-btn-danger rl-btn-sm',
			onclick: e => { e.stopPropagation(); confirmDelete(s); },
		}, 'Delete'),
	);

	const tr = el('tr', { class: 'rl-card-interactive', style: 'cursor:pointer' },
		el('td', { onclick: e => e.stopPropagation() }, check),
		el('td', {}, link, idLine),
		el('td', { class: 'rl-col-num' }, String(s.fileCount ?? 0)),
		el('td', { class: 'rl-col-num' }, formatBytes(s.totalSize ?? 0)),
		el('td', { class: 'rl-col-num' }, String(s.viewCount ?? 0)),
		el('td', { class: 'rl-col-num' }, dl),
		el('td', { class: 'rl-col-w' }, formatDate(s.createdAt)),
		el('td', { class: 'rl-col-w' }, timeUntil(s.expiresAt)),
		el('td', {}, flags),
		el('td', { style: 'text-align:right' }, actions),
	);
	tr.addEventListener('click', () => openDetail(s.id));
	rowsById.set(s.id, { tr, check });
	return tr;
}

function updateBulkState() {
	if (!tbody) return;
	const checks = $$('.row-check', tbody);
	const selected = checks.filter(c => c.checked);
	const bulkBtn = $('#bulk-delete');
	if (bulkBtn) {
		bulkBtn.disabled = selected.length === 0;
		bulkBtn.textContent = selected.length ? `Delete selected (${selected.length})` : 'Delete selected';
	}
	if (headerCheckbox) {
		headerCheckbox.checked = checks.length > 0 && selected.length === checks.length;
		headerCheckbox.indeterminate = selected.length > 0 && selected.length < checks.length;
	}
}

function confirmDelete(s) {
	openModal({
		title: 'Delete share',
		body: el('p', {}, `Delete "${s.title || s.id}" and all of its files? This cannot be undone.`),
		actions: [
			{ label: 'Cancel', variant: 'ghost' },
			{
				label: 'Delete', variant: 'danger',
				onClick: async () => {
					try {
						await api.del(`/api/admin/shares/${encodeURIComponent(s.id)}`);
						removeRow(s.id);
						toastOk('Share deleted');
						loadStats();
					} catch (err) {
						toastErr(err);
					}
				},
			},
		],
	});
}

function removeRow(id) {
	const entry = rowsById.get(id);
	if (entry) entry.tr.remove();
	rowsById.delete(id);
	if (!rowsById.size && tbody) {
		tbody.replaceChildren(colspanRow(
			el('div', { class: 'rl-empty' },
				el('div', { class: 'rl-empty-icon' }, '\u{1F4ED}'),
				el('p', {}, 'No shares yet.'),
			),
		));
	}
	updateBulkState();
}

async function bulkDelete() {
	const ids = [...rowsById.entries()].filter(([, v]) => v.check.checked).map(([id]) => id);
	if (!ids.length) return;

	openModal({
		title: 'Delete shares',
		body: el('p', {}, `Delete ${ids.length} selected share${ids.length === 1 ? '' : 's'}? This cannot be undone.`),
		actions: [
			{ label: 'Cancel', variant: 'ghost' },
			{
				label: `Delete ${ids.length}`, variant: 'danger',
				onClick: async () => {
					let ok = 0, fail = 0;
					for (const id of ids) {
						try {
							await api.del(`/api/admin/shares/${encodeURIComponent(id)}`);
							removeRow(id);
							ok++;
						} catch {
							fail++;
						}
					}
					if (ok) toastOk(`Deleted ${ok} share${ok === 1 ? '' : 's'}`);
					if (fail) toastErr(`Failed to delete ${fail}`);
					loadStats();
				},
			},
		],
	});
}

// ---- Detail view (modal) ---------------------------------------------------

async function openDetail(id) {
	const bodyHost = el('div', { class: 'rl-center', style: 'padding:var(--rl-space-6)' }, el('span', { class: 'rl-spinner' }));
	const modal = openModal({ title: 'Share detail', body: bodyHost });

	try {
		const d = await api.get(`/api/admin/shares/${encodeURIComponent(id)}`);
		renderDetail(modal, d, id);
	} catch (err) {
		bodyHost.replaceChildren(el('p', { class: 'rl-dim' }, (err && err.message) || 'Could not load detail.'));
	}
}

function renderDetail(modal, d, id) {
	const host = modal.content;
	const header = $('.rl-modal-header', host);
	host.replaceChildren(header);

	const meta = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1);margin-bottom:var(--rl-space-4)' },
		el('div', { class: 'rl-row', style: 'justify-content:space-between' },
			el('strong', {}, d.title || id),
			el('a', {
				class: 'rl-btn rl-btn-ghost rl-btn-sm', href: shareUrl(id), target: '_blank', rel: 'noopener',
			}, 'Open'),
		),
		el('div', { class: 'rl-mono rl-dim', style: 'font-size:var(--rl-text-xs)' }, id),
		el('div', { class: 'rl-muted', style: 'font-size:var(--rl-text-sm)' },
			`Created ${formatDate(d.createdAt)} - Expires ${timeUntil(d.expiresAt)} - ${d.viewCount ?? 0} views - ${d.downloadCount} downloads`,
		),
		el('div', { class: 'rl-dim rl-truncate', style: 'font-size:var(--rl-text-xs)', title: `${d.creatorIp || 'unknown IP'}${d.creatorUa ? ' - ' + d.creatorUa : ''}` },
			`Uploaded from ${d.creatorIp || 'unknown IP'}${d.creatorUa ? ' - ' + d.creatorUa : ''}`,
		),
	);

	const filesHost = el('div', { class: 'rl-stack' });
	const files = d.files || [];
	if (!files.length) {
		filesHost.append(el('p', { class: 'rl-dim' }, 'No files.'));
	} else {
		for (const f of files) filesHost.append(fileRow(modal, id, f, filesHost));
	}

	const events = d.downloadEvents || d.events || d.download_events || [];
	const eventsHost = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' });
	if (!events.length) {
		eventsHost.append(el('p', { class: 'rl-dim' }, 'No downloads yet.'));
	} else {
		for (const ev of events) {
			eventsHost.append(el('div', { class: 'rl-row', style: 'justify-content:space-between;font-size:var(--rl-text-sm)' },
				el('span', { class: 'rl-muted' }, formatDate(ev.ts)),
				el('span', { class: 'rl-mono rl-dim rl-truncate', style: 'max-width:60%' }, ev.ip || '-'),
			));
		}
	}

	host.append(
		meta,
		el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Edit'),
		editForm(modal, d, id),
		el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg);margin-top:var(--rl-space-6)' }, `Files (${files.length})`),
		filesHost,
		el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg);margin-top:var(--rl-space-6)' }, 'Recent downloads'),
		eventsHost,
	);
}

function editForm(modal, d, id) {
	const title = el('input', { class: 'rl-input', type: 'text', value: d.title || '', maxlength: 200, placeholder: 'Untitled' });

	const slug = el('input', { class: 'rl-input', type: 'text', value: id, maxlength: 64, spellcheck: false, autocomplete: 'off' });
	const slugWrap = el('div', { class: 'rl-input-affix' }, el('span', { class: 'rl-affix' }, '/'), slug);

	const password = el('input', { class: 'rl-input', type: 'password', placeholder: d.protected ? 'Set a new password' : 'Add a password', autocomplete: 'new-password' });
	const removePw = el('input', { type: 'checkbox' });
	removePw.addEventListener('change', () => {
		password.disabled = removePw.checked;
		if (removePw.checked) password.value = '';
	});
	const pwControl = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' },
		password,
		d.protected ? el('label', { class: 'rl-row', style: 'gap:var(--rl-space-2);font-size:var(--rl-text-sm)' }, removePw, el('span', {}, 'Remove password (make public)')) : false,
	);

	const never = el('input', { type: 'checkbox' });
	const expires = el('input', { class: 'rl-input', type: 'datetime-local' });
	if (d.expiresAt) expires.value = epochToLocalInput(d.expiresAt);
	else never.checked = true;
	const syncNever = () => { expires.disabled = never.checked; };
	never.addEventListener('change', syncNever);
	syncNever();
	const expControl = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' },
		expires,
		el('label', { class: 'rl-row', style: 'gap:var(--rl-space-2);font-size:var(--rl-text-sm)' }, never, el('span', {}, 'Never expires')),
	);

	const maxDl = el('input', { class: 'rl-input', type: 'number', min: 1, step: 1, placeholder: 'Unlimited', value: d.maxDownloads || '' });
	const oneTime = el('input', { type: 'checkbox' });
	oneTime.checked = !!d.oneTime;
	const limitControl = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' },
		maxDl,
		el('label', { class: 'rl-row', style: 'gap:var(--rl-space-2);font-size:var(--rl-text-sm)' }, oneTime, el('span', {}, 'One-time (delete after first download)')),
	);

	const save = el('button', { class: 'rl-btn rl-btn-primary' }, 'Save changes');
	save.addEventListener('click', async () => {
		const patch = { title: title.value.trim(), oneTime: oneTime.checked };
		if (slug.value.trim() && slug.value.trim() !== id) patch.slug = slug.value.trim();
		if (removePw.checked) patch.removePassword = true;
		else if (password.value) patch.password = password.value;
		if (never.checked) patch.expiresAt = null;
		else if (expires.value) {
			const ms = new Date(expires.value).getTime();
			if (Number.isFinite(ms)) patch.expiresAt = Math.round(ms / 1000);
		}
		const mx = parseInt(maxDl.value, 10);
		patch.maxDownloads = Number.isFinite(mx) && mx > 0 ? mx : null;

		save.disabled = true;
		try {
			const res = await api.patch(`/api/admin/shares/${encodeURIComponent(id)}`, patch);
			toastOk('Share updated');
			loadShares();
			loadStats();
			modal.close();
			openDetail(res.id || id);
		} catch (err) {
			save.disabled = false;
			if (err instanceof ApiError && err.status === 409) toastErr('That custom link is already taken');
			else toastErr(err);
		}
	});

	return el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-3)' },
		editField('Title', title),
		editField('Custom link', slugWrap, 'Changing this moves the share to a new URL.'),
		editField('Password', pwControl),
		editField('Expires', expControl),
		editField('Download limit', limitControl),
		el('div', { class: 'rl-row', style: 'justify-content:flex-end' }, save),
	);
}

function fileRow(modal, shareId, f, filesHost) {
	const row = el('div', { class: 'rl-filerow' },
		el('div', { class: 'rl-filerow-meta' },
			el('div', { class: 'rl-filerow-name rl-truncate' }, f.name),
			el('div', { class: 'rl-dim', style: 'font-size:var(--rl-text-xs)' },
				`${formatBytes(f.size)} - ${f.downloadCount ?? 0} downloads`),
		),
		el('button', {
			class: 'rl-btn rl-btn-danger rl-btn-sm',
			onclick: async () => {
				try {
					await api.del(`/api/admin/shares/${encodeURIComponent(shareId)}/files/${encodeURIComponent(f.id)}`);
					row.remove();
					toastOk('File deleted');
					loadStats();
					loadShares();
					if (!filesHost.querySelector('.rl-filerow')) {
						filesHost.append(el('p', { class: 'rl-dim' }, 'No files.'));
					}
				} catch (err) {
					toastErr(err);
				}
			},
		}, 'Delete'),
	);
	return row;
}

// ===========================================================================
// Server (quick link, settings, restart)
// ===========================================================================

function settingRow(f, inputs) {
	if (f.type === 'bool') {
		const cb = el('input', { type: 'checkbox' });
		cb.checked = String(f.value) === '1' || String(f.value).toLowerCase() === 'true';
		inputs.set(f.key, { input: cb, type: 'bool' });
		return el('div', { class: 'rl-field' },
			el('label', { class: 'rl-row', style: 'gap:var(--rl-space-2)' }, cb, el('span', { class: 'rl-label', style: 'margin:0' }, f.label)),
			f.help ? el('p', { class: 'rl-help' }, f.help) : false,
		);
	}
	if (f.secret) {
		const input = el('input', { class: 'rl-input', type: 'password', autocomplete: 'new-password', placeholder: f.set ? '(unchanged - leave blank to keep)' : '(not set)' });
		const reveal = el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm', type: 'button' }, 'Show');
		reveal.addEventListener('click', () => {
			const masked = input.type === 'password';
			input.type = masked ? 'text' : 'password';
			reveal.textContent = masked ? 'Hide' : 'Show';
		});
		const controls = [input, reveal];
		let clearBox = null;
		if (f.clearable) {
			clearBox = el('input', { type: 'checkbox' });
			controls.push(el('label', { class: 'rl-row', style: 'gap:var(--rl-space-1);font-size:var(--rl-text-sm)' }, clearBox, el('span', {}, 'Clear')));
		}
		inputs.set(f.key, { input, type: 'secret', clearBox });
		return el('div', { class: 'rl-field' },
			el('label', { class: 'rl-label' }, f.label),
			el('div', { class: 'rl-row rl-row-wrap', style: 'gap:var(--rl-space-2)' }, ...controls),
			f.danger ? el('p', { class: 'rl-help', style: 'color:var(--rl-danger)' }, f.danger) : (f.help ? el('p', { class: 'rl-help' }, f.help) : false),
		);
	}
	const input = el('input', { class: 'rl-input', type: f.type === 'int' ? 'number' : 'text', value: f.value ?? '' });
	inputs.set(f.key, { input, type: f.type });
	return el('div', { class: 'rl-field' },
		el('label', { class: 'rl-label' }, f.label),
		input,
		f.help ? el('p', { class: 'rl-help' }, f.help) : false,
	);
}

async function saveSettings(inputs, saveBtn, banner) {
	const values = {};
	const clear = [];
	let secretChange = false;
	for (const [key, meta] of inputs) {
		if (meta.type === 'bool') {
			values[key] = meta.input.checked ? '1' : '0';
		} else if (meta.type === 'secret') {
			if (meta.clearBox && meta.clearBox.checked) clear.push(key);
			else if (meta.input.value) {
				values[key] = meta.input.value;
				if (key === 'SECRET') secretChange = true;
			}
		} else if (meta.input.value !== '') {
			values[key] = meta.input.value;
		}
	}

	const send = async confirmSecretChange => {
		saveBtn.disabled = true;
		try {
			const res = await api.put('/api/admin/settings', { values, clear, confirmSecretChange });
			toastOk('Saved - restart to apply');
			banner.classList.remove('rl-hidden');
			(res.warnings || []).forEach(w => toast(w, 'error', 8000));
		} catch (err) {
			toastErr(err);
		} finally {
			saveBtn.disabled = false;
		}
	};

	if (secretChange) {
		openModal({
			title: 'Change SECRET?',
			body: el('div', { class: 'rl-stack' },
				el('p', {}, 'Changing SECRET will:'),
				el('ul', { style: 'margin:0;padding-left:var(--rl-space-5)' },
					el('li', {}, 'log out every admin session'),
					el('li', {}, 'invalidate every quick-access link'),
					el('li', {}, 'permanently break decryption of ALL existing uploads'),
				),
				el('p', { class: 'rl-text-danger' }, 'This cannot be undone.'),
			),
			actions: [
				{ label: 'Cancel', variant: 'ghost' },
				{ label: 'Change SECRET', variant: 'danger', onClick: () => send(true) },
			],
		});
	} else {
		await send(false);
	}
}

function pollHealthThenReload() {
	let tries = 0;
	const t = setInterval(async () => {
		tries++;
		try {
			const r = await fetch('/healthz', { cache: 'no-store' });
			if (r.ok) {
				clearInterval(t);
				location.reload();
				return;
			}
		} catch { /* still down */ }
		if (tries > 30) {
			clearInterval(t);
			toastErr('Server did not come back within 30s - check your host.');
		}
	}, 1000);
}

function confirmRestart() {
	openModal({
		title: 'Restart server',
		body: el('p', {}, 'Restart now to apply saved settings? The panel will be unavailable for a few seconds while the server relaunches.'),
		actions: [
			{ label: 'Cancel', variant: 'ghost' },
			{
				label: 'Restart', variant: 'danger', onClick: async () => {
					try {
						const res = await api.post('/api/admin/restart', {});
						if (res && res.willAutoRecover === false) {
							toast('Process exited, but no supervisor was detected - your host must relaunch it.', 'error', 9000);
						} else {
							toastOk('Restarting...');
							pollHealthThenReload();
						}
					} catch (err) {
						toastErr(err);
					}
				},
			},
		],
	});
}

function renderServer() {
	const quickHost = el('div', { class: 'rl-field' });
	(async () => {
		try {
			const r = await api.get('/api/admin/upload-link');
			if (r && r.enabled) {
				const btn = el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm' }, 'Copy quick-access upload link');
				btn.addEventListener('click', () => copyText(r.url));
				quickHost.replaceChildren(btn, el('p', { class: 'rl-help' }, 'Instant-login link for the upload page (uses a derived token, never the password).'));
			} else {
				quickHost.replaceChildren(el('p', { class: 'rl-help' }, 'Set an upload password to enable a quick-access link.'));
			}
		} catch {
			quickHost.replaceChildren(el('p', { class: 'rl-dim' }, 'Quick link unavailable.'));
		}
	})();

	const banner = el('div', { class: 'rl-alert rl-alert-warning rl-hidden' }, 'Saved. Restart the server to apply the changes.');
	const formHost = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-3)' });

	const inputs = new Map();
	const saveBtn = el('button', { class: 'rl-btn rl-btn-primary' }, 'Save settings');
	const restartBtn = el('button', { class: 'rl-btn rl-btn-danger' }, 'Restart server');
	saveBtn.addEventListener('click', () => saveSettings(inputs, saveBtn, banner));
	restartBtn.addEventListener('click', confirmRestart);

	const loadSettings = async () => {
		formHost.replaceChildren(el('div', { class: 'rl-center', style: 'padding:var(--rl-space-4)' }, el('span', { class: 'rl-spinner' })));
		try {
			const data = await api.get('/api/admin/settings');
			inputs.clear();
			const rows = [el('p', { class: 'rl-help' }, `Host ${data.readOnly.HOST} - Port ${data.readOnly.PORT} - Data ${data.readOnly.DATA_DIR} (fixed by the container)`)];
			for (const f of data.fields) rows.push(settingRow(f, inputs));
			formHost.replaceChildren(...rows);
		} catch (err) {
			formHost.replaceChildren(el('p', { class: 'rl-dim' }, 'Could not load settings.'));
			toastErr(err);
		}
	};

	view.replaceChildren(
		viewHead('Server', 'Quick-access link, app-managed settings, and restart.'),
		el('div', { class: 'rl-card rl-stack' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Quick access'),
			quickHost,
		),
		el('div', { class: 'rl-card rl-stack', style: 'margin-top:var(--rl-space-4)' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Settings'),
			el('p', { class: 'rl-help', style: 'margin:0' }, 'Saved to the data volume and applied on the next restart, not live.'),
			banner,
			formHost,
			el('div', { class: 'rl-row rl-row-wrap', style: 'justify-content:flex-end;gap:var(--rl-space-2)' }, restartBtn, saveBtn),
		),
	);

	loadSettings();
}

// ===========================================================================
// Logs
// ===========================================================================

let logsTimer = null;
function stopLogsPoll() {
	if (logsTimer) {
		clearInterval(logsTimer);
		logsTimer = null;
	}
}

function renderLogs() {
	const logBox = el('pre', {
		class: 'rl-mono',
		style: 'max-height:60vh;overflow:auto;font-size:var(--rl-text-xs);white-space:pre-wrap;background:var(--rl-bg-tertiary);border:var(--rl-border-thin) solid var(--rl-border);border-radius:var(--rl-radius-sm);padding:var(--rl-space-3);margin:0',
	});
	const loadLogs = async () => {
		try {
			const { logs } = await api.get('/api/admin/logs?limit=500');
			logBox.textContent = (logs || []).map(l => `${new Date(l.ts).toLocaleTimeString()} ${String(l.level).toUpperCase().padEnd(5)} ${l.msg}`).join('\n');
			logBox.scrollTop = logBox.scrollHeight;
		} catch { /* keep the last view on a transient error */ }
	};
	const refreshBtn = el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm' }, 'Refresh');
	refreshBtn.addEventListener('click', loadLogs);
	const autoBox = el('input', { type: 'checkbox' });
	autoBox.addEventListener('change', () => {
		stopLogsPoll();
		if (autoBox.checked) {
			loadLogs();
			logsTimer = setInterval(loadLogs, 3000);
		}
	});

	// Stop polling when navigating away from this view.
	cleanup = stopLogsPoll;

	view.replaceChildren(
		viewHead('Logs', 'Recent process output from the in-memory ring buffer.',
			el('div', { class: 'rl-row', style: 'gap:var(--rl-space-3)' },
				refreshBtn,
				el('label', { class: 'rl-row', style: 'gap:var(--rl-space-2);font-size:var(--rl-text-sm)' }, autoBox, el('span', {}, 'Auto-refresh')),
			),
		),
		el('div', { class: 'rl-card', style: 'padding:var(--rl-space-3)' }, logBox),
	);

	loadLogs();
}

boot();
