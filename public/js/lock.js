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

// Compact "time remaining" ("45s", "4m 12s", "1h 5m"). This page intentionally
// imports nothing from shared.js (so it reveals no portal code), hence the local
// copy - keep it in sync with formatDuration in shared.js.
function formatDuration(seconds) {
	const s = Math.max(1, Math.ceil(Number(seconds) || 0));
	const h = Math.floor(s / 3600);
	const m = Math.floor((s % 3600) / 60);
	const sec = s % 60;
	if (h >= 1) return m ? `${h}h ${m}m` : `${h}h`;
	if (m >= 1) return sec ? `${m}m ${sec}s` : `${m}m`;
	return `${sec}s`;
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
		if (res.status === 429) {
			let retryAfter = 0;
			try {
				const body = await res.json();
				retryAfter = Number(body && body.retryAfter);
			} catch {}
			if (!Number.isFinite(retryAfter) || retryAfter <= 0) retryAfter = Number(res.headers.get('Retry-After')) || 0;
			showError(retryAfter > 0 ? `Too many attempts. Try again in ${formatDuration(retryAfter)}.` : 'Too many attempts, please slow down.');
		} else {
			showError('Incorrect upload password.');
		}
	} catch {
		showError('Could not reach the server.');
	}
	btn.disabled = false;
	input.focus();
	input.select();
});
