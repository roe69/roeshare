// Admin login page (/login). The ONLY admin script served to an unauthenticated
// visitor; it holds no dashboard markup or logic. On a password-only success
// the cookie is set and we go to /admin. When two-factor auth is enabled
// (F-13), the password step instead reports `mfaRequired: true` and this swaps
// the form for a 6-digit code step (with a "use a backup code" toggle) before
// completing the login at /api/admin/login/mfa.

import { $, el, api, ApiError, toastErr } from '/js/shared.js';
import { mountSidebar } from '/js/sidebar.js';

mountSidebar({ active: 'admin' });

const form = $('#login-form');
const input = $('#login-password');
const btn = $('#login-btn');

let mode = 'password'; // 'password' | 'mfa'
let useBackupCode = false;

function renderMfaStep() {
	mode = 'mfa';
	const codeInput = el('input', {
		id: 'login-code',
		class: 'rl-input',
		type: 'text',
		inputmode: useBackupCode ? 'text' : 'numeric',
		autocomplete: 'one-time-code',
		placeholder: useBackupCode ? 'XXXXX-XXXXX' : '000000',
		maxlength: useBackupCode ? '11' : '6',
	});
	const toggle = el('button', { type: 'button', class: 'rl-btn rl-btn-ghost rl-btn-sm' },
		useBackupCode ? 'Use an authenticator code instead' : 'Use a backup code instead');
	toggle.addEventListener('click', () => {
		useBackupCode = !useBackupCode;
		renderMfaStep();
	});

	form.replaceChildren(
		el('div', { class: 'rl-center' },
			el('h1', { class: 'rl-h2' }, 'Two-factor code'),
			el('p', { class: 'rl-muted' }, 'Enter the code from your authenticator app.'),
		),
		el('div', { class: 'rl-field' },
			el('label', { class: 'rl-label', for: 'login-code' }, useBackupCode ? 'Backup code' : 'Authenticator code'),
			codeInput,
		),
		el('button', { class: 'rl-btn rl-btn-primary rl-btn-block', type: 'submit' }, 'Continue'),
		el('div', { class: 'rl-center' }, toggle),
	);
	codeInput.focus();
}

form.addEventListener('submit', async e => {
	e.preventDefault();

	if (mode === 'mfa') {
		const codeInput = $('#login-code');
		const code = codeInput.value.trim();
		if (!code) return;
		try {
			await api.post('/api/admin/login/mfa', { code });
			location.href = '/admin';
		} catch (err) {
			if (err instanceof ApiError && err.status === 403) toastErr(err.message || 'Invalid code');
			else toastErr(err);
			codeInput.value = '';
			codeInput.focus();
		}
		return;
	}

	const password = input.value;
	if (!password) return;
	btn.disabled = true;
	try {
		const res = await api.post('/api/admin/login', { password });
		if (res && res.mfaRequired) {
			renderMfaStep();
			return;
		}
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
