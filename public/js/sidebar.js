// Shared site sidebar rail, used on every page (upload, view, my shares, admin).
// One rail everywhere: site pages show a light set of links; the admin dashboard
// passes in its own section group plus an account/logout footer. Behaviour
// (collapse, mobile drawer, active highlight) lives here so every page matches.
//
// No build step: plain ES module, imported by each page's script.

import { el, $$ } from '/js/shared.js';

// ---- Icon registry ---------------------------------------------------------
// Inline SVG line icons, one family (24x24, currentColor stroke). Sized to 18px
// by .rl-side-ico in app.css. Populated by the design pass; keep the set uniform.
export const ICONS = {
	upload: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2\"/><path d=\"M12 15V4\"/><path d=\"M8 8l4-4 4 4\"/></svg>",
	files: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M4 7a2 2 0 0 1 2-2h3.2a2 2 0 0 1 1.4.6L12 7h6a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7z\"/></svg>",
	admin: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M12 3 5 6v5c0 4.4 3 7.6 7 9 4-1.4 7-4.6 7-9V6l-7-3z\"/><path d=\"m9 11.5 2.2 2.2L15 10\"/></svg>",
	overview: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect x=\"4\" y=\"4\" width=\"7\" height=\"7\" rx=\"1.6\"/><rect x=\"13\" y=\"4\" width=\"7\" height=\"7\" rx=\"1.6\"/><rect x=\"4\" y=\"13\" width=\"7\" height=\"7\" rx=\"1.6\"/><rect x=\"13\" y=\"13\" width=\"7\" height=\"7\" rx=\"1.6\"/></svg>",
	shares: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M12 3.2 3 7.6l9 4.4 9-4.4-9-4.4z\"/><polyline points=\"3 12 12 16.4 21 12\"/><polyline points=\"3 16.4 12 20.8 21 16.4\"/></svg>",
	server: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect x=\"3\" y=\"4\" width=\"18\" height=\"7\" rx=\"2\"/><rect x=\"3\" y=\"13\" width=\"18\" height=\"7\" rx=\"2\"/><line x1=\"7\" y1=\"7.5\" x2=\"7.01\" y2=\"7.5\"/><line x1=\"7\" y1=\"16.5\" x2=\"7.01\" y2=\"16.5\"/></svg>",
	logs: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><line x1=\"9\" y1=\"6\" x2=\"20\" y2=\"6\"/><line x1=\"9\" y1=\"12\" x2=\"20\" y2=\"12\"/><line x1=\"9\" y1=\"18\" x2=\"20\" y2=\"18\"/><line x1=\"4\" y1=\"6\" x2=\"4.01\" y2=\"6\"/><line x1=\"4\" y1=\"12\" x2=\"4.01\" y2=\"12\"/><line x1=\"4\" y1=\"18\" x2=\"4.01\" y2=\"18\"/></svg>",
	user: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"8\" r=\"3.5\"/><path d=\"M5.5 20a6.5 6.5 0 0 1 13 0\"/></svg>",
	logout: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M9 21H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3\"/><path d=\"m16 17 5-5-5-5\"/><path d=\"M21 12H9\"/></svg>",
	collapse: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"m13 17-5-5 5-5\"/><path d=\"m18 17-5-5 5-5\"/></svg>",
	menu: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M4 7h16\"/><path d=\"M4 12h16\"/><path d=\"M4 17h16\"/></svg>",
	link: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\"/><path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\"/></svg>",
	key: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"7.5\" cy=\"15.5\" r=\"4.5\"/><path d=\"m10.7 12.3 8.3-8.3\"/><path d=\"m16 5 2.5 2.5\"/><path d=\"m13.5 7.5 2.5 2.5\"/></svg>",
	book: "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M4 5.5A1.5 1.5 0 0 1 5.5 4H18a2 2 0 0 1 2 2v13a1 1 0 0 1-1 1H6a2 2 0 0 1-2-2V5.5z\"/><path d=\"M8 4v14\"/><line x1=\"11\" y1=\"8.5\" x2=\"17\" y2=\"8.5\"/><line x1=\"11\" y1=\"12\" x2=\"17\" y2=\"12\"/></svg>",
};

function svgIcon(key, cls) {
	const span = el('span', { class: cls || 'rl-side-ico', 'aria-hidden': 'true' });
	span.innerHTML = ICONS[key] || '';
	return span;
}

// Logout used on the public pages (the admin page passes its own handler). Ends
// the admin session and returns to the login screen.
async function defaultLogout() {
	try {
		await fetch('/api/admin/logout', { method: 'POST' });
	} catch {
		/* best effort */
	}
	location.href = '/login';
}

const COLLAPSE_KEY = 'roeshare_side_collapsed';

// The admin dashboard's sections, as a single source of truth (id / label / icon).
// The admin page wires these to in-app hash navigation; the public pages render
// them as links into the /admin SPA, shown only once the visitor is confirmed as
// an admin. Keep the ids in sync with the admin dashboard's views.
export const ADMIN_GROUPS = [
	{ label: 'Admin', items: [
		{ id: 'overview', label: 'Overview', icon: 'overview' },
		{ id: 'shares', label: 'Shares', icon: 'shares' },
	] },
	{ label: 'API', items: [
		{ id: 'apikeys', label: 'API keys', icon: 'key' },
		{ id: 'apidocs', label: 'API docs', icon: 'book' },
	] },
	{ label: 'System', items: [
		{ id: 'server', label: 'Server', icon: 'server' },
		{ id: 'logs', label: 'Logs', icon: 'logs' },
	] },
];

// Shares this browser owns are tracked by the edit tokens saved at upload time
// (same prefix as myshares.js). The "My shares" nav item is only shown when at
// least one exists, so a fresh visitor is not pointed at an empty page.
const EDIT_PREFIX = 'roeshare:edit:';
function hasOwnedShares() {
	try {
		for (let i = 0; i < localStorage.length; i++) {
			if (localStorage.key(i)?.startsWith(EDIT_PREFIX)) return true;
		}
	} catch {
		/* localStorage unavailable: treat as none */
	}
	return false;
}

// Brand HTML (colour spans rendered from APP_NAME's <col=> tags, server-side) is
// templated into <template id="rl-brand"> on every page, so the wordmark renders
// without an extra request.
function brandInner() {
	const tpl = document.getElementById('rl-brand');
	return tpl ? tpl.innerHTML : 'RoeShare';
}

function navItem(item, activeId) {
	const inner = [svgIcon(item.icon), el('span', { class: 'rl-side-label' }, item.label)];
	const active = item.id && item.id === activeId;
	const cls = `rl-side-item${active ? ' is-active' : ''}${item.hidden ? ' rl-hidden' : ''}`;
	if (item.href) {
		return el('a', { class: cls, href: item.href, 'data-id': item.id || '' }, ...inner);
	}
	const btn = el('button', { class: cls, type: 'button', 'data-id': item.id || '' }, ...inner);
	if (item.onClick) btn.addEventListener('click', item.onClick);
	return btn;
}

/**
 * Build and mount the rail. The "Share" group (Upload / My shares) is ALWAYS
 * rendered first on every page, so those items never move; pages can only add
 * groups BELOW it. Returns helpers for the page to drive it.
 *
 * opts:
 *   active    - id of the current nav item (for highlight)
 *   groups    - extra nav groups rendered below Share. Each group:
 *               { label?, items: [{ id, label, icon, href } | { id, label, icon, onClick }, ...] }
 *               With none, a single Admin link is shown.
 *   account   - { name, onLogout } to render the footer account row (admin only)
 *
 * returns { node(id), setActive(id) }
 */
export function mountSidebar({ active, groups, account } = {}) {
	const share = { label: 'Share', items: [
		{ id: 'upload', label: 'Upload', icon: 'upload', href: '/' },
	] };
	// Only surface "My shares" when this browser actually has shares to manage
	// (or we are already on that page), so it never leads to an empty list.
	if (active === 'mine' || hasOwnedShares()) {
		share.items.push({ id: 'mine', label: 'My shares', icon: 'files', href: '/mine' });
	}
	// Share first, always; then the page's groups. On the public pages (no groups
	// passed) the FULL admin dashboard sections are rendered as links into /admin,
	// hidden until /api/admin/me confirms the visitor is an admin - so a signed-in
	// admin gets the same nav everywhere, and everyone else sees none of it.
	const showsDefaultAdmin = !(groups && groups.length);
	const publicAdmin = showsDefaultAdmin
		? ADMIN_GROUPS.map(g => ({ label: g.label, adminGated: true, items: g.items.map(it => ({ ...it, href: `/admin#/${it.id}` })) }))
		: [];
	const allGroups = [share, ...(showsDefaultAdmin ? publicAdmin : groups)];

	const nav = el('nav', { class: 'rl-side-nav', 'aria-label': 'Navigation' });
	const adminGatedNodes = []; // labels + items revealed together once admin is confirmed
	for (const group of allGroups) {
		if (group.label) {
			const labelEl = el('span', { class: 'rl-side-group' }, group.label);
			if (group.adminGated) { labelEl.classList.add('rl-hidden'); adminGatedNodes.push(labelEl); }
			nav.append(labelEl);
		}
		for (const item of group.items) {
			const itemEl = navItem(item, active);
			if (group.adminGated) { itemEl.classList.add('rl-hidden'); adminGatedNodes.push(itemEl); }
			nav.append(itemEl);
		}
	}

	const brand = el('a', { class: 'rl-side-brand', href: '/', title: 'Home' },
		el('img', { src: '/favicon-32x32.png', alt: '', width: 26, height: 26 }),
		el('span', { html: brandInner() }),
	);

	// One footer row: Collapse on the left, Log out on the right (admin only),
	// both the same height. The "logged in as Admin" label is dropped - the admin
	// views are only reachable in admin mode, so it carried no information.
	const foot = el('div', { class: 'rl-side-foot' });
	const footRow = el('div', { class: 'rl-side-foot-row' });
	const collapseBtn = el('button', { class: 'rl-side-foot-btn rl-side-foot-collapse', type: 'button' },
		svgIcon('collapse'),
		el('span', { class: 'rl-side-label' }, 'Collapse'),
	);
	footRow.append(collapseBtn);
	// Log out: an explicit handler on the admin page; on the public pages a default
	// one shown only once admin is confirmed (revealed alongside the admin nav), so
	// a signed-in admin can log out from anywhere. Icon-only (the rail is too narrow
	// for two labelled buttons), same height as Collapse, flush at the right.
	const onLogout = (account && account.onLogout) || (showsDefaultAdmin ? defaultLogout : null);
	if (onLogout) {
		const logoutBtn = el('button', { class: 'rl-side-foot-btn rl-side-foot-logout', type: 'button', title: 'Log out', 'aria-label': 'Log out' },
			svgIcon('logout'),
		);
		logoutBtn.addEventListener('click', onLogout);
		if (!account) { logoutBtn.classList.add('rl-hidden'); adminGatedNodes.push(logoutBtn); }
		footRow.append(logoutBtn);
	}
	foot.append(footRow);

	const aside = el('aside', { class: 'rl-side' }, brand, nav, foot);

	// Reveal the admin sections if this visitor is logged in as an admin, so the
	// full panel nav is available everywhere (upload, view, My shares), not just on
	// the dashboard itself.
	if (showsDefaultAdmin && adminGatedNodes.length) {
		fetch('/api/admin/me', { headers: { Accept: 'application/json' } })
			.then(r => (r.ok ? r.json() : null))
			.then(me => { if (me && me.admin) adminGatedNodes.forEach(n => n.classList.remove('rl-hidden')); })
			.catch(() => {});
	}

	const toggle = el('button', { class: 'rl-side-toggle', type: 'button', 'aria-label': 'Open menu' }, svgIcon('menu'));
	const backdrop = el('div', { class: 'rl-side-backdrop' });

	document.body.prepend(aside, toggle, backdrop);
	document.body.classList.add('rl-side-on');

	// ---- Collapse (desktop icon-only rail), remembered across visits. -------
	const syncCollapse = mini => {
		document.body.classList.toggle('rl-side-mini', mini);
		collapseBtn.setAttribute('aria-label', mini ? 'Expand sidebar' : 'Collapse sidebar');
	};
	let mini = false;
	try { mini = localStorage.getItem(COLLAPSE_KEY) === '1'; } catch {}
	syncCollapse(mini);
	collapseBtn.addEventListener('click', () => {
		mini = !document.body.classList.contains('rl-side-mini');
		syncCollapse(mini);
		try { localStorage.setItem(COLLAPSE_KEY, mini ? '1' : '0'); } catch {}
	});

	// Enable transitions only after the initial (possibly collapsed) layout has
	// painted, so navigating between pages never animates the rail on arrival.
	requestAnimationFrame(() => document.body.classList.add('rl-side-ready'));

	// ---- Mobile drawer ------------------------------------------------------
	const closeDrawer = () => document.body.classList.remove('rl-side-open');
	toggle.addEventListener('click', () => document.body.classList.add('rl-side-open'));
	backdrop.addEventListener('click', closeDrawer);
	// Close on navigation within the page (links handle their own navigation).
	nav.addEventListener('click', e => { if (e.target.closest('.rl-side-item')) closeDrawer(); });

	return {
		node: id => aside.querySelector(`[data-id="${id}"]`),
		setActive: id => {
			$$('.rl-side-item', aside).forEach(b => b.classList.toggle('is-active', b.dataset.id === id));
		},
	};
}
