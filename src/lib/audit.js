// Structured security-event audit log (section 10 of the security audit).
// Every call site below writes ONE row to audit_events (see db.js's schema)
// via a single prepared synchronous INSERT - bun:sqlite is synchronous and
// this is a low-write table, so there is no async, batching, or queue here.
//
// REDACTION: this module trusts its callers completely - it does no
// sanitizing beyond the 1000-char truncation backstop below. NEVER pass any
// of the following in `detail` (or `target`): a password or password
// candidate, a TOTP secret/code/backup code, an API key secret or full
// bearer token, a share edit token or access-grant token, a session/cookie
// value, a raw Authorization/Cookie/X-Edit-Token header, a full request URL
// or query string (pathname only), an E2E fragment key, or a request body.
// `detail` must always be a small object of explicitly allowlisted scalar
// fields built at the call site - never a spread of req/body/headers.
//
// A write failure here must never fail, slow, or alter the request path -
// the whole body is wrapped in try/catch with console.error on failure.
import { db, now } from '../db.js';

export const AUDIT_RETENTION_SECONDS = 90 * 24 * 3600;

const insertAudit = db.query(
	'INSERT INTO audit_events (ts, event, ip, actor, target, detail) VALUES (?, ?, ?, ?, ?, ?)',
);

export function audit(event, { ip = null, actor = null, target = null, detail = null } = {}) {
	try {
		const detailStr = detail == null ? null : JSON.stringify(detail).slice(0, 1000);
		insertAudit.run(now(), event, ip, actor, target, detailStr);
	} catch (err) {
		console.error('[audit] write failed:', err);
	}
}
