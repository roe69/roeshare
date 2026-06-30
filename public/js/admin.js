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

const VIEWS = { overview: renderOverview, shares: renderShares, apikeys: renderApiKeys, apidocs: renderApiDocs, server: renderServer, logs: renderLogs };

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
	location.href = '/login';
}

// ---- Boot ------------------------------------------------------------------

function boot() {
	// The shared rail, with the dashboard sections on top and an account footer.
	const go = id => () => { location.hash = `#/${id}`; };
	// Share is rendered first automatically; we just add the Admin section below.
	sidebar = mountSidebar({
		active: currentView(),
		groups: [
			{ label: 'Admin', items: [
				{ id: 'overview', label: 'Overview', icon: 'overview', onClick: go('overview') },
				{ id: 'shares', label: 'Shares', icon: 'shares', onClick: go('shares') },
				{ id: 'apikeys', label: 'API keys', icon: 'key', onClick: go('apikeys') },
				{ id: 'apidocs', label: 'API docs', icon: 'book', onClick: go('apidocs') },
				{ id: 'server', label: 'Server', icon: 'server', onClick: go('server') },
				{ id: 'logs', label: 'Logs', icon: 'logs', onClick: go('logs') },
			] },
		],
		account: { name: 'Admin', onLogout: logout },
	});

	window.addEventListener('hashchange', navigate);
	// Render the current view immediately (no spinner while we wait on the
	// network); the server already gated this page. Then confirm the session in
	// the background and bounce to /login only if the cookie has since lapsed.
	navigate();
	api.get('/api/admin/me').then(me => { if (!me || !me.admin) location.href = '/login'; }).catch(() => {});
}

// ===========================================================================
// Overview
// ===========================================================================

function statCard(label, value, extra) {
	return el('div', { class: 'rl-card rl-card-pad-sm' },
		el('div', { class: 'rl-eyebrow', style: 'margin-bottom:var(--rl-space-2)' }, label),
		el('div', { style: 'font-size:var(--rl-text-2xl);font-weight:var(--rl-weight-bold);line-height:1.1' }, value),
		extra ? el('div', { style: 'margin-top:var(--rl-space-3)' }, extra) : false,
	);
}

function infoRow(label, value) {
	return el('div', { class: 'rl-row', style: 'justify-content:space-between;gap:var(--rl-space-3);font-size:var(--rl-text-sm)' },
		el('span', { class: 'rl-muted' }, label),
		el('span', { class: 'rl-mono rl-truncate', style: 'max-width:60%;text-align:right' }, value),
	);
}

function panelSpinner() {
	return el('div', { class: 'rl-center', style: 'padding:var(--rl-space-4)' }, el('span', { class: 'rl-spinner' }));
}

// Panel header: a title and an optional "View all" link to the Shares view.
function panelHead(title, viewAll) {
	return el('div', { class: 'rl-row', style: 'justify-content:space-between;align-items:center' },
		el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg);margin:0' }, title),
		viewAll ? el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm', onclick: () => { location.hash = '#/shares'; } }, 'View all') : false,
	);
}

// A clickable share row (title on the left, a caller-supplied node on the right).
function shareRowBtn(s, right) {
	return el('button', {
		class: 'rl-row', style: 'justify-content:space-between;gap:var(--rl-space-3);width:100%;background:transparent;border:0;padding:var(--rl-space-2);border-radius:var(--rl-radius-sm);cursor:pointer;text-align:left;color:inherit',
		onclick: () => openDetail(s.id),
	},
		el('span', { class: 'rl-truncate', style: 'font-weight:var(--rl-weight-semibold)' }, s.title || s.id),
		right,
	);
}

function renderOverview() {
	const statsRow = el('div', {
		id: 'stats',
		style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:var(--rl-space-3)',
	});
	const card = () => el('div', { class: 'rl-card rl-stack', style: 'gap:var(--rl-space-2)' }, panelSpinner());
	const lifetimeHost = card(), biggestHost = card(), uploadersHost = card(), instanceHost = card(), expiringHost = card();

	view.replaceChildren(
		viewHead('Overview', 'Live instance status and current totals first; all-time figures and leaderboards (which survive deleted shares) below.'),
		statsRow,
		el('div', { style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:var(--rl-space-3);margin-top:var(--rl-space-3)' },
			instanceHost,
			lifetimeHost,
			uploadersHost,
			biggestHost,
			expiringHost,
		),
	);

	loadStats();
	loadInstance(instanceHost);
	loadOverview(biggestHost, uploadersHost, expiringHost, lifetimeHost);
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
	host.replaceChildren(panelHead('Instance'), body);
}

function formatUptime(s) {
	const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
	if (d) return `${d}d ${h}h`;
	if (h) return `${h}h ${m}m`;
	if (m) return `${m}m`;
	return `${Math.floor(s)}s`;
}

// Fill the overview panels from one request. A failure shows a per-panel notice,
// never a blank page.
async function loadOverview(biggestHost, uploadersHost, expiringHost, lifetimeHost) {
	let data;
	try {
		data = await api.get('/api/admin/overview');
	} catch {
		const fail = title => [panelHead(title), el('p', { class: 'rl-dim' }, 'Could not load.')];
		lifetimeHost.replaceChildren(...fail('All time'));
		biggestHost.replaceChildren(...fail('Biggest shares'));
		uploadersHost.replaceChildren(...fail('Top uploaders'));
		expiringHost.replaceChildren(...fail('Expiring soon'));
		return;
	}

	// All-time totals - persist past deletion.
	const lt = data.lifetime || {};
	lifetimeHost.replaceChildren(
		panelHead('All time'),
		el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1)' },
			infoRow('Shares created', String(lt.shares ?? 0)),
			infoRow('Files uploaded', String(lt.files ?? 0)),
			infoRow('Data uploaded', formatBytes(lt.bytes ?? 0)),
			infoRow('Downloads', String(lt.downloads ?? 0)),
			infoRow('Views', String(lt.views ?? 0)),
		),
	);

	// Biggest shares - clickable rows, size + downloads on the right.
	const big = data.biggestShares || [];
	const bigList = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1)' });
	if (!big.length) bigList.append(el('p', { class: 'rl-dim' }, 'No shares yet.'));
	else for (const s of big) {
		bigList.append(shareRowBtn(s, el('span', { class: 'rl-dim', style: 'font-size:var(--rl-text-xs);flex-shrink:0' }, `${formatBytes(s.size)} - ${s.downloads} dl`)));
	}
	biggestHost.replaceChildren(panelHead('Biggest shares', true), bigList);

	// Top uploaders (power users) - aggregated by creator IP. The table is
	// fixed-layout so a long IPv6 address truncates instead of forcing a scroll.
	const up = data.topUploaders || [];
	const upBody = el('tbody', {},
		...(up.length ? up.map(u => el('tr', {},
			el('td', {}, el('span', { class: 'rl-mono rl-truncate', style: 'display:block', title: u.ip || 'unknown' }, u.ip || 'unknown')),
			el('td', { class: 'rl-col-num' }, String(u.shareCount)),
			el('td', { class: 'rl-col-num' }, formatBytes(u.totalSize)),
			el('td', { class: 'rl-col-num' }, String(u.downloads)),
		)) : [el('tr', {}, el('td', { colspan: 4 }, el('p', { class: 'rl-dim' }, 'No uploads yet.')))]),
	);
	uploadersHost.replaceChildren(
		panelHead('Top uploaders'),
		el('table', { class: 'rl-table', style: 'table-layout:fixed;width:100%' },
			el('thead', {}, el('tr', {},
				el('th', {}, 'IP'),
				el('th', { class: 'rl-col-num', style: 'width:4.5rem' }, 'Shares'),
				el('th', { class: 'rl-col-num', style: 'width:5rem' }, 'Size'),
				el('th', { class: 'rl-col-num', style: 'width:3.5rem' }, 'DLs'),
			)),
			upBody,
		),
	);

	// Expiring soon - soonest first, a warning/danger badge for the time left.
	const exp = data.expiringSoon || [];
	const expList = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1)' });
	if (!exp.length) expList.append(el('p', { class: 'rl-dim' }, 'Nothing expiring soon.'));
	else for (const s of exp) {
		const closeSoon = s.expiresAt * 1000 - Date.now() < 3600 * 1000;
		expList.append(shareRowBtn(s, el('span', { class: `rl-badge ${closeSoon ? 'rl-badge-danger' : 'rl-badge-warning'}`, style: 'flex-shrink:0' }, timeUntil(s.expiresAt))));
	}
	expiringHost.replaceChildren(panelHead('Expiring soon'), expList);
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
		id: 'bulk-delete', class: 'rl-btn rl-btn-danger', disabled: true,
		onclick: bulkDelete,
	}, 'Delete selected');

	const toolbar = el('div', { class: 'rl-toolbar', style: 'margin-bottom:var(--rl-space-4)' },
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
			class: 'rl-btn rl-btn-secondary rl-btn-sm', title: 'Copy link',
			onclick: e => { e.stopPropagation(); copyText(shareUrl(s.id)); },
		}, 'Copy'),
		el('a', {
			class: 'rl-btn rl-btn-secondary rl-btn-sm', href: shareUrl(s.id), target: '_blank', rel: 'noopener',
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
				class: 'rl-btn rl-btn-secondary rl-btn-sm', href: shareUrl(id), target: '_blank', rel: 'noopener',
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
// API keys
// ===========================================================================

const KEY_EXPIRY_OPTS = [
	{ label: 'Never expires', value: '' },
	{ label: '30 days', value: String(30 * 86400) },
	{ label: '90 days', value: String(90 * 86400) },
	{ label: '1 year', value: String(365 * 86400) },
];

// Derive a key's display status from its revoke/expiry timestamps.
function keyStatus(k) {
	if (k.revokedAt) return { label: 'Revoked', cls: 'rl-badge-danger', active: false };
	if (k.expiresAt && k.expiresAt * 1000 < Date.now()) return { label: 'Expired', cls: 'rl-badge-neutral', active: false };
	return { label: 'Active', cls: 'rl-badge-success', active: true };
}

// Preset caps for a key's maximum share lifetime (seconds; '' = no cap).
const KEY_LIFETIME_OPTS = [
	{ label: 'No cap', value: '' },
	{ label: '1 hour', value: String(3600) },
	{ label: '1 day', value: String(86400) },
	{ label: '7 days', value: String(7 * 86400) },
	{ label: '30 days', value: String(30 * 86400) },
	{ label: '90 days', value: String(90 * 86400) },
];

// A bytes input (number + unit) that reads back as an integer byte count, or null
// when blank (meaning "inherit the server default"). Reuses splitBytes/BYTE_UNITS.
function byteField(initialBytes) {
	const seed = initialBytes ? splitBytes(initialBytes) : { value: '', unit: 1048576 };
	const num = el('input', { class: 'rl-input', type: 'number', min: 0, step: 'any', value: seed.value, placeholder: 'Server default', style: 'flex:1;min-width:0' });
	const unit = el('select', { class: 'rl-select', style: 'max-width:84px' }, ...BYTE_UNITS.map(([n, v]) => el('option', { value: v }, n)));
	unit.value = String(seed.unit);
	const get = () => {
		const raw = num.value.trim();
		if (raw === '') return null;
		const b = Math.round(parseFloat(raw) * Number(unit.value));
		return Number.isFinite(b) && b > 0 ? b : null;
	};
	return { node: el('div', { class: 'rl-row', style: 'gap:var(--rl-space-2)' }, num, unit), get };
}

// Build the limits/scopes form, seeded from a key's current limits. Returns the
// node plus collect(), which yields the camelCase object the API expects.
function scopeControls(initial = {}) {
	const fileCap = byteField(initial.maxFileSize);
	const shareCap = byteField(initial.maxShareSize);
	const maxShares = el('input', { class: 'rl-input', type: 'number', min: 1, step: 1, value: initial.maxShares || '', placeholder: 'Unlimited' });

	const lifetime = el('select', { class: 'rl-select' }, ...KEY_LIFETIME_OPTS.map(o => el('option', { value: o.value }, o.label)));
	// Seed to the matching preset; an off-preset value gets its own option so it is
	// never silently lost when re-saving.
	if (initial.maxExpiry) {
		if (!KEY_LIFETIME_OPTS.some(o => o.value === String(initial.maxExpiry))) {
			lifetime.append(el('option', { value: String(initial.maxExpiry) }, `${Math.round(initial.maxExpiry / 86400)} days`));
		}
		lifetime.value = String(initial.maxExpiry);
	}

	const allowSlug = el('input', { type: 'checkbox' });
	allowSlug.checked = initial.allowSlug !== false;
	const allowPassword = el('input', { type: 'checkbox' });
	allowPassword.checked = initial.allowPassword !== false;

	const node = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-3)' },
		el('div', { class: 'rl-optgrid' },
			editField('Max file size', fileCap.node, 'Per file. Blank uses the server limit.'),
			editField('Max share size', shareCap.node, 'Per share. Blank uses the server limit.'),
			editField('Max total shares', maxShares, 'Lifetime cap on shares this key can create.'),
			editField('Max share lifetime', lifetime, 'Forces shares from this key to expire within this window.'),
		),
		el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' },
			el('label', { class: 'rl-row', style: 'gap:var(--rl-space-2);font-size:var(--rl-text-sm)' }, allowSlug, el('span', {}, 'Allow custom share links (slugs)')),
			el('label', { class: 'rl-row', style: 'gap:var(--rl-space-2);font-size:var(--rl-text-sm)' }, allowPassword, el('span', {}, 'Allow setting share passwords')),
		),
	);

	const collect = () => {
		const mx = parseInt(maxShares.value, 10);
		return {
			maxFileSize: fileCap.get(),
			maxShareSize: shareCap.get(),
			maxShares: Number.isFinite(mx) && mx > 0 ? mx : null,
			maxExpiry: lifetime.value ? Number(lifetime.value) : null,
			allowSlug: allowSlug.checked,
			allowPassword: allowPassword.checked,
		};
	};

	return { node, collect };
}

// A short human summary of a key's non-default limits, for the table.
function limitsSummary(limits = {}) {
	const bits = [];
	if (limits.maxFileSize) bits.push(`file ${formatBytes(limits.maxFileSize)}`);
	if (limits.maxShareSize) bits.push(`share ${formatBytes(limits.maxShareSize)}`);
	if (limits.maxShares) bits.push(`${limits.maxShares} shares`);
	if (limits.maxExpiry) bits.push(`${timeUntil(Math.floor(Date.now() / 1000) + limits.maxExpiry)} max`);
	if (limits.allowSlug === false) bits.push('no slugs');
	if (limits.allowPassword === false) bits.push('no passwords');
	return bits;
}

let keysTbody;

function renderApiKeys() {
	const nameInput = el('input', { class: 'rl-input', type: 'text', maxlength: 100, placeholder: 'e.g. backup-server', style: 'flex:1;min-width:160px' });
	const expirySelect = el('select', { class: 'rl-select', style: 'max-width:180px' },
		...KEY_EXPIRY_OPTS.map(o => el('option', { value: o.value }, o.label)),
	);
	const createBtn = el('button', { class: 'rl-btn rl-btn-primary' }, 'Create key');
	const scopes = scopeControls();
	const submit = async () => {
		const name = nameInput.value.trim();
		if (!name) { toastErr('Give the key a name first'); nameInput.focus(); return; }
		createBtn.disabled = true;
		try {
			const made = await api.post('/api/admin/api-keys', { name, expiresIn: expirySelect.value || undefined, limits: scopes.collect() });
			nameInput.value = '';
			expirySelect.value = '';
			showNewKeyModal(made);
			loadKeys();
		} catch (err) {
			toastErr(err);
		} finally {
			createBtn.disabled = false;
		}
	};
	createBtn.addEventListener('click', submit);
	nameInput.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });

	// Limits/scopes live in a collapsed section so the common case (name + expiry)
	// stays a single calm row.
	const advanced = el('details', { class: 'rl-stack', style: 'gap:var(--rl-space-3)' },
		el('summary', { style: 'cursor:pointer;color:var(--rl-muted);font-size:var(--rl-text-sm);user-select:none' }, 'Limits & scopes (optional)'),
		scopes.node,
	);

	const createCard = el('div', { class: 'rl-card rl-stack' },
		el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Create a key'),
		el('p', { class: 'rl-help', style: 'margin-top:0' }, 'The full key is shown only once, right after you create it. Store it somewhere safe; if it is lost, revoke it and make a new one.'),
		el('div', { class: 'rl-row rl-row-wrap', style: 'gap:var(--rl-space-2);align-items:flex-end' },
			el('div', { class: 'rl-field', style: 'flex:1;min-width:200px;margin:0' },
				el('label', { class: 'rl-label' }, 'Name'),
				nameInput,
			),
			el('div', { class: 'rl-field', style: 'margin:0' },
				el('label', { class: 'rl-label' }, 'Expiry'),
				expirySelect,
			),
			createBtn,
		),
		advanced,
	);

	keysTbody = el('tbody');
	const table = el('div', { style: 'overflow-x:auto' },
		el('table', { class: 'rl-table' },
			el('thead', {},
				el('tr', {},
					el('th', {}, 'Name'),
					el('th', {}, 'Key'),
					el('th', { class: 'rl-col-w' }, 'Created'),
					el('th', { class: 'rl-col-w' }, 'Last used'),
					el('th', { class: 'rl-col-w' }, 'Expires'),
					el('th', { class: 'rl-col-num' }, 'Shares'),
					el('th', { class: 'rl-col-num' }, 'Data'),
					el('th', {}, 'Status'),
					el('th', { style: 'text-align:right' }, 'Actions'),
				),
			),
			keysTbody,
		),
	);

	view.replaceChildren(
		viewHead('API keys', 'Let other servers and scripts upload programmatically. See the request examples after creating a key.'),
		createCard,
		el('div', { class: 'rl-card', style: 'padding:0;overflow:hidden;margin-top:var(--rl-space-3)' }, table),
	);

	loadKeys();
}

function keysColspanRow(content) {
	return el('tr', {}, el('td', { colspan: 9 }, content));
}

async function loadKeys() {
	if (!keysTbody) return;
	keysTbody.replaceChildren(keysColspanRow(
		el('div', { class: 'rl-center', style: 'padding:var(--rl-space-6)' }, el('span', { class: 'rl-spinner' })),
	));
	try {
		const { keys } = await api.get('/api/admin/api-keys');
		if (!keys || !keys.length) {
			keysTbody.replaceChildren(keysColspanRow(
				el('div', { class: 'rl-empty' },
					el('div', { class: 'rl-empty-icon' }, '\u{1F511}'),
					el('p', {}, 'No API keys yet. Create one above to allow programmatic uploads.'),
				),
			));
			return;
		}
		keysTbody.replaceChildren(...keys.map(keyRow));
	} catch (err) {
		toastErr(err);
		keysTbody.replaceChildren(keysColspanRow(el('p', { class: 'rl-dim rl-center' }, 'Could not load API keys.')));
	}
}

function keyRow(k) {
	const st = keyStatus(k);

	const prefix = el('button', {
		class: 'rl-mono', title: 'Copy key id',
		style: 'background:transparent;border:0;padding:0;color:var(--rl-primary);cursor:pointer;font-size:var(--rl-text-xs)',
		onclick: e => { e.stopPropagation(); copyText(k.prefix); },
	}, `${k.prefix}_...`);

	const actions = el('div', { class: 'rl-row', style: 'gap:var(--rl-space-1);justify-content:flex-end' },
		st.active ? el('button', {
			class: 'rl-btn rl-btn-secondary rl-btn-sm',
			onclick: e => { e.stopPropagation(); confirmRevoke(k); },
		}, 'Revoke') : false,
		k.revokedAt ? el('button', {
			class: 'rl-btn rl-btn-secondary rl-btn-sm',
			onclick: e => { e.stopPropagation(); confirmReinstate(k); },
		}, 'Reinstate') : false,
		el('button', {
			class: 'rl-btn rl-btn-danger rl-btn-sm',
			onclick: e => { e.stopPropagation(); confirmDeleteKey(k); },
		}, 'Delete'),
	);

	const summary = limitsSummary(k.limits);
	const nameCell = el('td', {},
		el('span', { style: 'font-weight:var(--rl-weight-semibold)' }, k.name),
		summary.length ? el('div', { class: 'rl-dim', style: 'font-size:var(--rl-text-xs)' }, summary.join(' · ')) : false,
	);

	const tr = el('tr', { class: 'rl-card-interactive', style: 'cursor:pointer' },
		nameCell,
		el('td', {}, prefix),
		el('td', { class: 'rl-col-w' }, formatDate(k.createdAt)),
		el('td', { class: 'rl-col-w' }, k.lastUsedAt ? formatDate(k.lastUsedAt) : el('span', { class: 'rl-dim' }, 'Never')),
		el('td', { class: 'rl-col-w' }, k.expiresAt ? timeUntil(k.expiresAt) : 'Never'),
		el('td', { class: 'rl-col-num' }, String(k.uploadCount ?? 0)),
		el('td', { class: 'rl-col-num' }, formatBytes(k.bytesUploaded ?? 0)),
		el('td', {}, el('span', { class: `rl-badge ${st.cls}` }, st.label)),
		el('td', { style: 'text-align:right' }, actions),
	);
	tr.addEventListener('click', () => openKeyDetail(k.id));
	return tr;
}

// One-time reveal of a freshly minted token, with copy-able request examples.
function showNewKeyModal(made) {
	const origin = location.origin;
	const tokenBox = el('div', {
		class: 'rl-mono',
		style: 'user-select:all;word-break:break-all;padding:var(--rl-space-3);background:var(--rl-bg-tertiary,var(--rl-bg-secondary));border:var(--rl-border-thin) solid var(--rl-border);border-radius:var(--rl-radius-sm);font-size:var(--rl-text-sm)',
	}, made.token);

	const curl = [
		`curl -X POST "${origin}/api/v1/upload?title=My%20file" \\`,
		`  -H "Authorization: Bearer ${made.token}" \\`,
		`  -H "X-Filename: report.pdf" \\`,
		`  --data-binary @report.pdf`,
	].join('\n');
	const curlBox = el('pre', {
		class: 'rl-mono',
		style: 'white-space:pre-wrap;word-break:break-word;margin:0;padding:var(--rl-space-3);background:var(--rl-bg-tertiary,var(--rl-bg-secondary));border:var(--rl-border-thin) solid var(--rl-border);border-radius:var(--rl-radius-sm);font-size:var(--rl-text-xs)',
	}, curl);

	const body = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-3)' },
		el('div', { class: 'rl-alert rl-alert-warning' }, 'Copy this key now. For security it is not stored and cannot be shown again.'),
		el('div', { class: 'rl-field' },
			el('label', { class: 'rl-label' }, `Key "${made.name}"`),
			tokenBox,
			el('div', { class: 'rl-row', style: 'gap:var(--rl-space-2);margin-top:var(--rl-space-2)' },
				el('button', { class: 'rl-btn rl-btn-primary rl-btn-sm', onclick: () => copyText(made.token) }, 'Copy key'),
			),
		),
		el('div', { class: 'rl-field' },
			el('label', { class: 'rl-label' }, 'One-shot upload example'),
			curlBox,
			el('div', { class: 'rl-row', style: 'gap:var(--rl-space-2);margin-top:var(--rl-space-2)' },
				el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm', onclick: () => copyText(curl) }, 'Copy example'),
			),
			el('p', { class: 'rl-help' }, 'For large or resumable uploads, POST /api/v1/shares to get an editToken, then use the standard chunked endpoints.'),
		),
	);

	openModal({ title: 'API key created', body, actions: [{ label: 'Done', variant: 'primary' }] });
}

function confirmRevoke(k) {
	openModal({
		title: 'Revoke key',
		body: el('p', {}, `Revoke "${k.name}"? Programs using it will immediately stop being able to upload. Its history is kept; this cannot be undone.`),
		actions: [
			{ label: 'Cancel', variant: 'ghost' },
			{
				label: 'Revoke', variant: 'danger',
				onClick: async () => {
					try {
						await api.post(`/api/admin/api-keys/${encodeURIComponent(k.id)}/revoke`, {});
						toastOk('Key revoked');
						loadKeys();
					} catch (err) {
						toastErr(err);
					}
				},
			},
		],
	});
}

function confirmReinstate(k) {
	openModal({
		title: 'Reinstate key',
		body: el('p', {}, `Reinstate "${k.name}"? It will be able to upload again immediately.${k.expiresAt && k.expiresAt * 1000 < Date.now() ? ' Note: it is also past its expiry, so it stays inactive until you extend it.' : ''}`),
		actions: [
			{ label: 'Cancel', variant: 'ghost' },
			{
				label: 'Reinstate', variant: 'primary',
				onClick: async () => {
					try {
						await api.post(`/api/admin/api-keys/${encodeURIComponent(k.id)}/reinstate`, {});
						toastOk('Key reinstated');
						loadKeys();
					} catch (err) {
						toastErr(err);
					}
				},
			},
		],
	});
}

function confirmDeleteKey(k, onDone) {
	openModal({
		title: 'Delete key',
		body: el('p', {}, `Permanently delete "${k.name}"? This removes the key and its usage record. Shares it already created are not affected.`),
		actions: [
			{ label: 'Cancel', variant: 'ghost' },
			{
				label: 'Delete', variant: 'danger',
				onClick: async () => {
					try {
						await api.del(`/api/admin/api-keys/${encodeURIComponent(k.id)}`);
						toastOk('Key deleted');
						loadKeys();
						onDone?.();
					} catch (err) {
						toastErr(err);
					}
				},
			},
		],
	});
}

async function openKeyDetail(id) {
	const bodyHost = el('div', { class: 'rl-center', style: 'padding:var(--rl-space-6)' }, el('span', { class: 'rl-spinner' }));
	const modal = openModal({ title: 'API key', body: bodyHost });
	try {
		const k = await api.get(`/api/admin/api-keys/${encodeURIComponent(id)}`);
		const st = keyStatus(k);

		// Recent shares this key created.
		const sharesHost = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1)' });
		const shares = k.shares || [];
		if (!shares.length) sharesHost.append(el('p', { class: 'rl-dim' }, 'No shares created with this key yet.'));
		else for (const s of shares) {
			sharesHost.append(el('div', { class: 'rl-row', style: 'justify-content:space-between;gap:var(--rl-space-3);font-size:var(--rl-text-sm)' },
				el('a', {
					href: `${location.origin}/${s.id}`, target: '_blank', rel: 'noopener',
					class: 'rl-truncate', style: 'color:var(--rl-primary);text-decoration:none',
				}, s.title || s.id),
				el('span', { class: 'rl-dim', style: 'flex-shrink:0;font-size:var(--rl-text-xs)' },
					`${formatBytes(s.totalSize)}${s.deleted ? ' - deleted' : ''}`),
			));
		}

		// Editable name + limits/scopes.
		const nameInput = el('input', { class: 'rl-input', type: 'text', value: k.name, maxlength: 100 });
		const scopes = scopeControls(k.limits || {});
		const saveBtn = el('button', { class: 'rl-btn rl-btn-primary' }, 'Save changes');
		saveBtn.addEventListener('click', async () => {
			const name = nameInput.value.trim();
			if (!name) { toastErr('Name cannot be empty'); return; }
			saveBtn.disabled = true;
			try {
				await api.patch(`/api/admin/api-keys/${encodeURIComponent(k.id)}`, { name, limits: scopes.collect() });
				toastOk('Key updated');
				loadKeys();
				modal.close();
			} catch (err) {
				saveBtn.disabled = false;
				toastErr(err);
			}
		});

		// Lifecycle actions adapt to the key's state.
		const lifecycle = el('div', { class: 'rl-row rl-row-wrap', style: 'gap:var(--rl-space-2)' },
			k.revokedAt
				? el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm', onclick: () => { modal.close(); confirmReinstate(k); } }, 'Reinstate')
				: el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm', onclick: () => { modal.close(); confirmRevoke(k); } }, 'Revoke'),
			el('button', { class: 'rl-btn rl-btn-danger rl-btn-sm', onclick: () => confirmDeleteKey(k, () => modal.close()) }, 'Delete'),
		);

		bodyHost.replaceChildren(
			el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1);margin-bottom:var(--rl-space-4)' },
				el('div', { class: 'rl-row', style: 'justify-content:space-between;align-items:center' },
					el('strong', {}, k.name),
					el('span', { class: `rl-badge ${st.cls}` }, st.label),
				),
				el('div', { class: 'rl-mono rl-dim', style: 'font-size:var(--rl-text-xs)' }, `${k.prefix}_...`),
			),
			el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1);margin-bottom:var(--rl-space-4)' },
				infoRow('Created', formatDate(k.createdAt)),
				infoRow('Last used', k.lastUsedAt ? formatDate(k.lastUsedAt) : 'Never'),
				infoRow('Expires', k.expiresAt ? `${formatDate(k.expiresAt)} (${timeUntil(k.expiresAt)})` : 'Never'),
				infoRow('Shares created', String(k.uploadCount ?? 0)),
				infoRow('Data uploaded', formatBytes(k.bytesUploaded ?? 0)),
			),
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Limits & scopes'),
			el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-3)' },
				editField('Name', nameInput),
				scopes.node,
				el('div', { class: 'rl-row', style: 'justify-content:flex-end' }, saveBtn),
			),
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg);margin-top:var(--rl-space-6)' }, `Recent shares (${shares.length})`),
			sharesHost,
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg);margin-top:var(--rl-space-6)' }, 'Lifecycle'),
			lifecycle,
		);
	} catch (err) {
		bodyHost.replaceChildren(el('p', { class: 'rl-dim' }, (err && err.message) || 'Could not load key.'));
	}
}

// ===========================================================================
// API docs
// ===========================================================================

const METHOD_CLS = { GET: 'rl-badge-success', POST: 'rl-badge-gold', PATCH: 'rl-badge-warning', DELETE: 'rl-badge-danger' };

// A read-only code block with a Copy button.
function docCode(text) {
	return el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' },
		el('pre', {
			class: 'rl-mono',
			style: 'white-space:pre-wrap;word-break:break-word;margin:0;padding:var(--rl-space-3);background:var(--rl-bg-tertiary,var(--rl-bg-secondary));border:var(--rl-border-thin) solid var(--rl-border);border-radius:var(--rl-radius-sm);font-size:var(--rl-text-xs)',
		}, text),
		el('div', { class: 'rl-row', style: 'justify-content:flex-end' },
			el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm', onclick: () => copyText(text) }, 'Copy'),
		),
	);
}

function endpointCard(method, path, desc, extra) {
	return el('div', { class: 'rl-card rl-card-pad-sm rl-stack', style: 'gap:var(--rl-space-2)' },
		el('div', { class: 'rl-row', style: 'gap:var(--rl-space-2);align-items:center;flex-wrap:wrap' },
			el('span', { class: `rl-badge ${METHOD_CLS[method] || 'rl-badge-neutral'}`, style: 'min-width:56px;justify-content:center' }, method),
			el('span', { class: 'rl-mono', style: 'font-size:var(--rl-text-sm);word-break:break-all' }, path),
		),
		el('p', { class: 'rl-muted', style: 'margin:0;font-size:var(--rl-text-sm)' }, desc),
		extra || false,
	);
}

// A compact "name - description" parameter list.
function paramList(rows) {
	return el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1)' },
		...rows.map(([name, desc]) => el('div', { style: 'font-size:var(--rl-text-sm)' },
			el('span', { class: 'rl-mono', style: 'color:var(--rl-text-form)' }, name),
			el('span', { class: 'rl-dim' }, ` - ${desc}`),
		)),
	);
}

function renderApiDocs() {
	const origin = location.origin;
	const tok = 'rsk_<id>_<secret>';

	const oneShot = [
		`curl -X POST "${origin}/api/v1/upload?title=My%20file" \\`,
		`  -H "Authorization: Bearer ${tok}" \\`,
		`  -H "X-Filename: report.pdf" \\`,
		`  --data-binary @report.pdf`,
	].join('\n');

	const resumable = [
		'# 1. Create a share, capture its id + editToken',
		`RESP=$(curl -s -X POST "${origin}/api/v1/shares" \\`,
		`  -H "Authorization: Bearer ${tok}" \\`,
		`  -H "Content-Type: application/json" \\`,
		`  -d '{"title":"Big upload"}')`,
		'ID=$(echo "$RESP" | jq -r .id); ET=$(echo "$RESP" | jq -r .editToken)',
		'',
		'# 2. Register the file (declare its name + size)',
		`curl -X POST "${origin}/api/shares/$ID/files" \\`,
		'  -H "X-Edit-Token: $ET" -H "Content-Type: application/json" \\',
		'  -d \'{"name":"big.iso","size":1073741824,"mime":"application/octet-stream"}\'',
		'',
		'# 3. PATCH each chunk at its byte offset, then finalize',
		`curl -X PATCH "${origin}/api/shares/$ID/files/$FILE_ID?offset=0" \\`,
		'  -H "X-Edit-Token: $ET" --data-binary @chunk0',
		`curl -X POST "${origin}/api/shares/$ID/finalize" -H "X-Edit-Token: $ET"`,
	].join('\n');

	const limitsPanel = el('div', { class: 'rl-card rl-stack' },
		el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'This instance'),
		el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-1)' }, panelSpinner()),
	);
	(async () => {
		const host = limitsPanel.lastChild;
		try {
			const c = await api.get('/api/config');
			host.replaceChildren(
				infoRow('Base URL', c.baseUrl || origin),
				infoRow('Max file size', formatBytes(c.maxFileSize)),
				infoRow('Max share size', formatBytes(c.maxShareSize)),
				infoRow('Upload chunk size', formatBytes(c.chunkSize)),
				infoRow('Default expiry', c.defaultExpiry ? timeUntil(Math.floor(Date.now() / 1000) + c.defaultExpiry) : 'Never'),
			);
		} catch {
			host.replaceChildren(el('p', { class: 'rl-dim' }, 'Could not load server limits.'));
		}
	})();

	view.replaceChildren(
		viewHead('API docs', 'Programmatic upload API for other servers and scripts.', el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm', onclick: () => { location.hash = '#/apikeys'; } }, 'Manage keys')),

		el('div', { class: 'rl-card rl-stack' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Authentication'),
			el('p', { class: 'rl-muted', style: 'margin:0;font-size:var(--rl-text-sm)' }, 'Create a key in the API keys tab, then send it as a bearer token on every request. Either header works:'),
			docCode('Authorization: Bearer rsk_<id>_<secret>\nX-Api-Key: rsk_<id>_<secret>'),
			el('p', { class: 'rl-help' }, 'A key is shown in full only once, at creation. Missing, invalid, revoked, or expired keys get a 401.'),
		),

		limitsPanel,

		el('div', { class: 'rl-card rl-stack' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Endpoints'),
			el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-3)' },
				endpointCard('GET', '/api/v1/me', 'Verify a key and read its name and usage. Handy as a health check.'),
				endpointCard('POST', '/api/v1/upload', 'One-shot upload: the request body IS the file. Returns a finished share. Bounded by the server max request body size.',
					el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' },
						paramList([
							['X-Filename', 'header (or ?filename=) - required, the file name'],
							['?title ?slug ?password', 'optional share options (query params)'],
							['?expiresIn ?maxDownloads ?oneTime ?mime', 'optional share options (query params)'],
						]),
						el('p', { class: 'rl-help' }, 'Returns { id, url, fileId, name, size }.'),
					),
				),
				endpointCard('POST', '/api/v1/shares', 'Create a share for the resumable flow and get back an editToken plus this key\'s effective caps. Use for large files.',
					el('p', { class: 'rl-help' }, 'Body (JSON, all optional): title, slug, password, expiresIn, maxDownloads, oneTime. Returns { id, editToken, url, chunkSize, maxFileSize, maxShareSize }.')),
				endpointCard('POST', '/api/shares/:id/files', 'Register a file on the share (declare name, size, mime). Auth: X-Edit-Token header.'),
				endpointCard('PATCH', '/api/shares/:id/files/:fileId?offset=N', 'Upload one chunk of raw bytes at byte offset N. Resume from the server-reported offset after an interruption.'),
				endpointCard('POST', '/api/shares/:id/finalize', 'Mark the share complete once every file is fully uploaded.'),
			),
		),

		el('div', { class: 'rl-card rl-stack' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Example: one-shot upload'),
			el('p', { class: 'rl-muted', style: 'margin:0;font-size:var(--rl-text-sm)' }, 'Send a whole file in a single request and get back a share URL.'),
			docCode(oneShot),
		),

		el('div', { class: 'rl-card rl-stack' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Example: resumable upload'),
			el('p', { class: 'rl-muted', style: 'margin:0;font-size:var(--rl-text-sm)' }, 'For large files: create a share, then register, chunk, and finalize.'),
			docCode(resumable),
		),

		el('div', { class: 'rl-card rl-stack' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Limits & scopes'),
			el('p', { class: 'rl-muted', style: 'margin:0;font-size:var(--rl-text-sm)' }, 'Each key can be restricted below the instance limits in the API keys tab:'),
			paramList([
				['Max file size / share size', 'per-file and per-share byte caps, clamped to the server limits'],
				['Max total shares', 'a lifetime cap on how many shares the key can create'],
				['Max share lifetime', 'forces every share from the key to expire within a window'],
				['Allow custom links / passwords', 'toggles whether the key may set slugs or share passwords'],
			]),
			el('p', { class: 'rl-help' }, 'A request that exceeds a cap or uses a disallowed scope gets a 403 (scope/limit) or 413 (size).'),
		),
	);
}

// ===========================================================================
// Server (quick link, settings, restart)
// ===========================================================================

// Per-field overrides so the Server page stays calm: a short (or no) hint, a
// trimmed label, and byte fields edited in friendly units. The API still carries
// the long labels/help; these just shape the presentation.
const SETTING_HINTS = {
	BASE_URL: 'Public URLs, comma-separated. First is canonical.',
	APP_NAME: 'Brand name. <col=RRGGBB> colours, <b> bolds.',
	TRUST_PROXY: 'Only enable behind a trusted proxy.',
	MAX_TOTAL_SIZE: '0 means unlimited.',
	CHUNK_SIZE: 'Advanced. Leave the default.',
	DEFAULT_EXPIRY: '0 means never.',
	SWEEP_INTERVAL: 'How often expired shares are purged.',
	ADMIN_PASSWORD: 'Blank keeps the current one.',
	UPLOAD_PASSWORD: 'Blank keeps it; tick Clear for open uploads.',
};
const SETTING_LABELS = {
	MAX_FILE_SIZE: 'Max file size',
	MAX_SHARE_SIZE: 'Max share size',
	MAX_TOTAL_SIZE: 'Max total storage',
	CHUNK_SIZE: 'Upload chunk size',
	DEFAULT_EXPIRY: 'Default expiry (seconds)',
	SWEEP_INTERVAL: 'Sweep interval (seconds)',
};
const BYTE_KEYS = new Set(['MAX_FILE_SIZE', 'MAX_SHARE_SIZE', 'MAX_TOTAL_SIZE', 'CHUNK_SIZE']);
const BYTE_UNITS = [['B', 1], ['KB', 1024], ['MB', 1048576], ['GB', 1073741824]];

// Pick the friendliest unit for a byte count: the largest that divides evenly
// (so 8388608 shows as "8 MB"), else the largest where the value is >= 1.
function splitBytes(bytes) {
	if (!bytes) return { value: '0', unit: 1 };
	for (let i = BYTE_UNITS.length - 1; i >= 0; i--) if (bytes % BYTE_UNITS[i][1] === 0) return { value: String(bytes / BYTE_UNITS[i][1]), unit: BYTE_UNITS[i][1] };
	for (let i = BYTE_UNITS.length - 1; i >= 0; i--) if (bytes >= BYTE_UNITS[i][1]) return { value: String(+(bytes / BYTE_UNITS[i][1]).toFixed(2)), unit: BYTE_UNITS[i][1] };
	return { value: String(bytes), unit: 1 };
}

function settingHint(key) {
	return key in SETTING_HINTS ? el('p', { class: 'rl-help' }, SETTING_HINTS[key]) : false;
}

function settingRow(f, inputs) {
	const label = SETTING_LABELS[f.key] || f.label;

	if (f.type === 'bool') {
		const cb = el('input', { type: 'checkbox' });
		cb.checked = String(f.value) === '1' || String(f.value).toLowerCase() === 'true';
		inputs.set(f.key, { input: cb, type: 'bool' });
		return el('div', { class: 'rl-field' },
			el('div', { class: 'rl-row', style: 'justify-content:space-between;gap:var(--rl-space-3)' },
				el('span', { class: 'rl-label', style: 'margin:0' }, label),
				el('label', { class: 'rl-switch' }, cb, el('span', { class: 'rl-switch-track' })),
			),
			settingHint(f.key),
		);
	}

	if (BYTE_KEYS.has(f.key)) {
		const seed = splitBytes(Number(f.value) || 0);
		const num = el('input', { class: 'rl-input', type: 'number', min: 0, step: 'any', value: seed.value, style: 'flex:1;min-width:0' });
		const unit = el('select', { class: 'rl-select', style: 'max-width:88px' }, ...BYTE_UNITS.map(([name, v]) => el('option', { value: v }, name)));
		unit.value = String(seed.unit);
		const exact = el('p', { class: 'rl-help rl-dim', style: 'margin:0' });
		const getBytes = () => Math.round(parseFloat(num.value || '0') * Number(unit.value));
		const sync = () => {
			const b = getBytes();
			exact.textContent = f.key === 'MAX_TOTAL_SIZE' && b === 0 ? 'Unlimited' : `= ${new Intl.NumberFormat().format(b)} bytes`;
		};
		num.addEventListener('input', sync);
		unit.addEventListener('change', sync);
		sync();
		inputs.set(f.key, { type: 'bytes', getBytes });
		return el('div', { class: 'rl-field' },
			el('label', { class: 'rl-label' }, label),
			el('div', { class: 'rl-row', style: 'gap:var(--rl-space-2)' }, num, unit),
			settingHint(f.key),
			exact,
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
		return el('div', { class: 'rl-field', dataset: { settingKey: f.key } },
			el('label', { class: 'rl-label' }, label),
			el('div', { class: 'rl-row rl-row-wrap', style: 'gap:var(--rl-space-2)' }, ...controls),
			// SECRET keeps its full red warning; the others get a short hint.
			f.danger ? el('p', { class: 'rl-help', style: 'color:var(--rl-danger)' }, f.danger) : settingHint(f.key),
		);
	}

	const input = el('input', { class: 'rl-input', type: f.type === 'int' ? 'number' : 'text', value: f.value ?? '' });
	inputs.set(f.key, { input, type: f.type });
	return el('div', { class: 'rl-field' },
		el('label', { class: 'rl-label' }, label),
		input,
		settingHint(f.key),
	);
}

async function saveSettings(inputs, saveBtn, banner) {
	const values = {};
	const clear = [];
	let secretChange = false;
	for (const [key, meta] of inputs) {
		if (meta.type === 'bool') {
			values[key] = meta.input.checked ? '1' : '0';
		} else if (meta.type === 'bytes') {
			values[key] = String(meta.getBytes());
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

// The quick-access upload link (admin only). It is only meaningful when an upload
// password is configured, so it lives right under the UPLOAD_PASSWORD field. The
// link carries a derived token, never the password itself.
function uploadLinkControl() {
	const host = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2);margin-top:var(--rl-space-2)' }, el('span', { class: 'rl-spinner' }));
	(async () => {
		try {
			const r = await api.get('/api/admin/upload-link');
			if (r && r.enabled) {
				const btn = el('button', { class: 'rl-btn rl-btn-secondary rl-btn-sm', type: 'button' }, 'Copy quick-access link');
				btn.addEventListener('click', () => copyText(r.url));
				host.replaceChildren(btn, el('p', { class: 'rl-help' }, 'Instant-login link for the upload page (uses a derived token, never the password).'));
			} else {
				host.replaceChildren(el('p', { class: 'rl-help' }, 'Set an upload password (and restart) to enable a quick-access upload link.'));
			}
		} catch {
			host.replaceChildren(el('p', { class: 'rl-dim' }, 'Quick link unavailable.'));
		}
	})();
	return host;
}

function renderServer() {
	const banner = el('div', { class: 'rl-alert rl-alert-warning rl-hidden' }, 'Saved. Restart to apply.');
	const formHost = el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-2)' });
	const instanceStrip = el('div', { class: 'rl-card rl-card-pad-sm rl-stack', style: 'gap:var(--rl-space-2)' });

	const inputs = new Map();
	const saveBtn = el('button', { class: 'rl-btn rl-btn-primary' }, 'Save settings');
	const restartBtn = el('button', { class: 'rl-btn rl-btn-danger' }, 'Restart server');
	saveBtn.addEventListener('click', () => saveSettings(inputs, saveBtn, banner));
	restartBtn.addEventListener('click', confirmRestart);

	// Fields grouped so the page scans easily instead of reading as one long wall.
	const GROUPS = [
		{ title: 'General', keys: ['BASE_URL', 'APP_NAME', 'TRUST_PROXY'] },
		{ title: 'Limits', keys: ['MAX_FILE_SIZE', 'MAX_SHARE_SIZE', 'MAX_TOTAL_SIZE', 'CHUNK_SIZE', 'MAX_FILES_PER_SHARE', 'MAX_PASSWORD_LENGTH', 'DEFAULT_EXPIRY', 'SWEEP_INTERVAL'] },
		{ title: 'Security', keys: ['ADMIN_PASSWORD', 'UPLOAD_PASSWORD', 'SECRET'] },
	];
	const COLSPAN = new Set(['BASE_URL', 'SECRET']);

	const group = (title, fields) => {
		const grid = el('div', { class: 'rl-optgrid' });
		for (const f of fields) {
			const node = settingRow(f, inputs);
			if (COLSPAN.has(f.key)) node.classList.add('rl-col-span');
			grid.append(node);
		}
		return el('div', { class: 'rl-stack', style: 'gap:var(--rl-space-3)' },
			el('div', { class: 'rl-eyebrow', style: 'margin-top:var(--rl-space-3);padding-bottom:var(--rl-space-2);border-bottom:var(--rl-border-thin) solid var(--rl-border)' }, title),
			grid,
		);
	};

	const loadSettings = async () => {
		formHost.replaceChildren(panelSpinner());
		try {
			const data = await api.get('/api/admin/settings');
			inputs.clear();
			const byKey = new Map(data.fields.map(f => [f.key, f]));
			const used = new Set();
			const groups = [];
			for (const g of GROUPS) {
				const fields = g.keys.map(k => byKey.get(k)).filter(Boolean);
				fields.forEach(f => used.add(f.key));
				if (fields.length) groups.push(group(g.title, fields));
			}
			// Anything not in a known group still shows, so a field can never vanish.
			const extra = data.fields.filter(f => !used.has(f.key));
			if (extra.length) groups.push(group('Other', extra));
			formHost.replaceChildren(...groups);

			// The quick-access upload link sits with the upload password it depends on.
			const pwField = formHost.querySelector('[data-setting-key="UPLOAD_PASSWORD"]');
			if (pwField) pwField.append(uploadLinkControl());

			const ro = data.readOnly || {};
			const chip = (l, v) => el('span', { class: 'rl-help' }, l + ' ', el('span', { class: 'rl-mono' }, v));
			instanceStrip.replaceChildren(
				el('div', { class: 'rl-eyebrow' }, 'Fixed by the container'),
				el('div', { class: 'rl-row rl-row-wrap', style: 'gap:var(--rl-space-3)' }, chip('Host', `${ro.HOST}:${ro.PORT}`), chip('Data', ro.DATA_DIR)),
			);
		} catch (err) {
			formHost.replaceChildren(el('p', { class: 'rl-dim' }, 'Could not load settings.'));
			toastErr(err);
		}
	};

	const actionBar = el('div', {
		class: 'rl-row rl-row-wrap',
		style: 'position:sticky;bottom:0;justify-content:flex-end;align-items:center;gap:var(--rl-space-3);padding-top:var(--rl-space-3);margin-top:var(--rl-space-2);background:var(--rl-bg-secondary);border-top:var(--rl-border-thin) solid var(--rl-border)',
	}, el('span', { class: 'rl-spacer' }), banner, restartBtn, saveBtn);

	view.replaceChildren(
		viewHead('Server', 'Settings save to disk and apply on the next restart, not live.'),
		el('div', { style: 'margin-bottom:var(--rl-space-3)' }, instanceStrip),
		el('div', { class: 'rl-card rl-stack' },
			el('h2', { class: 'rl-h2', style: 'font-size:var(--rl-text-lg)' }, 'Settings'),
			formHost,
			actionBar,
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

// Log level -> badge variant + short label (reuses rl-badge colors).
const LOG_LEVELS = {
	info: { cls: 'rl-badge-neutral', label: 'INFO' },
	log: { cls: 'rl-badge-neutral', label: 'INFO' },
	debug: { cls: 'rl-badge-neutral', label: 'DEBUG' },
	warn: { cls: 'rl-badge-warning', label: 'WARN' },
	warning: { cls: 'rl-badge-warning', label: 'WARN' },
	error: { cls: 'rl-badge-danger', label: 'ERR' },
};

function logRow(l) {
	const lvl = LOG_LEVELS[String(l.level || 'info').toLowerCase()] || LOG_LEVELS.info;
	return el('div', { class: 'rl-logrow' },
		el('span', { class: 'rl-mono rl-dim', style: 'white-space:nowrap;font-variant-numeric:tabular-nums' }, new Date(l.ts).toLocaleTimeString()),
		el('span', { class: `rl-badge ${lvl.cls}`, style: 'font-size:10px;min-width:52px;justify-content:center;text-transform:uppercase' }, lvl.label),
		el('span', { class: 'rl-mono', style: 'white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;min-width:0;color:var(--rl-text-form)' }, l.msg),
	);
}

function renderLogs() {
	const POLL = 2000;
	let paused = false;
	const logBox = el('div', { class: 'rl-log', id: 'log-box' });

	const loadLogs = async () => {
		if (!logBox.isConnected) return;
		try {
			const { logs } = await api.get('/api/admin/logs?limit=500');
			// Only auto-scroll when already near the bottom, so reading history is
			// never interrupted by the live stream.
			const pinned = logBox.scrollHeight - logBox.scrollTop - logBox.clientHeight < 48;
			const frag = document.createDocumentFragment();
			(logs || []).forEach(l => frag.append(logRow(l)));
			logBox.replaceChildren(frag);
			if (pinned) logBox.scrollTop = logBox.scrollHeight;
		} catch { /* keep the last rows on a transient error */ }
	};

	const liveBadge = el('span', { class: 'rl-badge rl-badge-success' }, 'Live');
	const pauseBtn = el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm' }, 'Pause');
	pauseBtn.addEventListener('click', () => {
		paused = !paused;
		pauseBtn.textContent = paused ? 'Resume' : 'Pause';
		liveBadge.className = `rl-badge ${paused ? 'rl-badge-neutral' : 'rl-badge-success'}`;
		liveBadge.textContent = paused ? 'Paused' : 'Live';
		if (!paused) loadLogs();
	});

	// Stop the stream when navigating away from this view.
	cleanup = stopLogsPoll;

	view.replaceChildren(
		viewHead('Logs', 'Live process output from the in-memory ring buffer.',
			el('div', { class: 'rl-row', style: 'gap:var(--rl-space-3)' }, liveBadge, pauseBtn),
		),
		el('div', { class: 'rl-card', style: 'padding:var(--rl-space-2)' }, logBox),
	);

	loadLogs();
	logsTimer = setInterval(() => { if (!paused) loadLogs(); }, POLL);
}

boot();
