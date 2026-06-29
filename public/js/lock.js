// Standalone lock page. Verifies the upload password; on success the server sets
// the upload cookie and we reload, at which point the server serves the real
// upload page (and only then is the portal's code available). No shared imports,
// so this page reveals nothing about the upload portal.

const form = document.getElementById('lock-form');
const input = document.getElementById('lock-password');
const btn = document.getElementById('lock-btn');
const errEl = document.getElementById('lock-error');

function showError(msg) {
	errEl.textContent = msg;
	errEl.classList.remove('rl-hidden');
}

form.addEventListener('submit', async e => {
	e.preventDefault();
	const password = input.value;
	if (!password) {
		input.focus();
		return;
	}
	btn.disabled = true;
	errEl.classList.add('rl-hidden');
	try {
		const res = await fetch('/api/upload/verify', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ password }),
		});
		if (res.ok) {
			location.reload();
			return;
		}
		showError(res.status === 429 ? 'Too many attempts, please slow down.' : 'Incorrect upload password.');
	} catch {
		showError('Could not reach the server.');
	}
	btn.disabled = false;
	input.focus();
	input.select();
});
