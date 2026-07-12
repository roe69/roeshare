// Interstitial page for the upload quick-access magic link (?token=...). The
// server (routes/pages.js GET /) deliberately does NOT redeem the token
// itself - a bare GET/HEAD is reachable by server-side link-preview scanners
// (Slack, Teams, Outlook Safe Links, ...) that prefetch pasted URLs with no
// cookie and no JS execution, which would otherwise silently burn the
// single-use token before the human ever clicked it (M-03). This script only
// runs in a real browser, so it is what actually redeems the token: fire the
// POST, then head to the clean URL either way - a success lands on the
// unlocked upload page (the server now sees the cookie); a failure (missing,
// invalid, expired, or already-redeemed token) lands on the lock page,
// exactly as a plain visit with no token always has.
const token = new URLSearchParams(location.search).get('token');

async function redeem() {
	if (token) {
		try {
			await fetch('/api/upload/link/redeem', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ token }),
			});
		} catch {
			// Network error: fall through to the redirect below like any other
			// failure - there is nothing else useful to do on this page.
		}
	}
	location.replace('/');
}

redeem();
