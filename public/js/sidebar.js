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
};

function svgIcon(key, cls) {
	const span = el('span', { class: cls || 'rl-side-ico', 'aria-hidden': 'true' });
	span.innerHTML = ICONS[key] || '';
	return span;
}

const COLLAPSE_KEY = 'roeshare_side_collapsed';

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
 *   quickLink - onClick handler; adds a hidden "Quick link" item to the Share
 *               group that the caller reveals via node('quicklink')
 *
 * returns { node(id), setActive(id) }
 */
export function mountSidebar({ active, groups, account, quickLink } = {}) {
	const share = { label: 'Share', items: [
		{ id: 'upload', label: 'Upload', icon: 'upload', href: '/' },
		{ id: 'mine', label: 'My shares', icon: 'files', href: '/mine' },
	] };
	if (quickLink) share.items.push({ id: 'quicklink', label: 'Quick link', icon: 'link', hidden: true, onClick: quickLink });
	// Share first, always; then the page's groups (or a lone Admin link).
	const allGroups = [share, ...(groups && groups.length ? groups : [{ items: [{ id: 'admin', label: 'Admin', icon: 'admin', href: '/admin' }] }])];

	const nav = el('nav', { class: 'rl-side-nav', 'aria-label': 'Navigation' });
	for (const group of allGroups) {
		if (group.label) nav.append(el('span', { class: 'rl-side-group' }, group.label));
		for (const item of group.items) nav.append(navItem(item, active));
	}

	const brand = el('a', { class: 'rl-side-brand', href: '/', title: 'Home' },
		el('img', { src: '/favicon-32x32.png', alt: '', width: 26, height: 26 }),
		el('span', { html: brandInner() }),
	);

	const foot = el('div', { class: 'rl-side-foot' });
	if (account) {
		const logoutBtn = el('button', { class: 'rl-side-logout', type: 'button', title: 'Log out', 'aria-label': 'Log out' },
			svgIcon('logout', 'rl-side-logout-ico'));
		if (account.onLogout) logoutBtn.addEventListener('click', account.onLogout);
		foot.append(el('div', { class: 'rl-side-account' },
			svgIcon('user', 'rl-side-user'),
			el('span', { class: 'rl-side-who' }, account.name || 'Account'),
			logoutBtn,
		));
	}
	const collapseBtn = el('button', { class: 'rl-side-collapse', type: 'button' },
		svgIcon('collapse'),
		el('span', { class: 'rl-side-label' }, 'Collapse'),
	);
	foot.append(collapseBtn);

	const aside = el('aside', { class: 'rl-side' }, brand, nav, foot);
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
