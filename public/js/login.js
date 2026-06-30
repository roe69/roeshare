// Admin login page (/login). The ONLY admin script served to an unauthenticated
// visitor; it holds no dashboard markup or logic. On success the cookie is set
// and we go to /admin, which the server then answers with the real dashboard.

import { $, api, ApiError, toastErr } from '/js/shared.js';
import { mountSidebar } from '/js/sidebar.js';

mountSidebar({ active: 'admin' });

const form = $('#login-form');
const input = $('#login-password');
const btn = $('#login-btn');

form.addEventListener('submit', async (e) => {
	e.preventDefault();
	const password = input.value;
	if (!password) return;
	btn.disabled = true;
	try {
		await api.post('/api/admin/login', { password });
		// Cookie is set; reload so the server serves the gated dashboard.
		location.href = '/admin';
	} catch (err) {
		if (err instanceof ApiError && err.status === 403) toastErr('Wrong password');
		else toastErr(err);
		btn.disabled = false;
		input.focus();
		input.select();
	}
});

input.focus();
