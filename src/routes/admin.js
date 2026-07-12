// Admin API: session login/logout, share browsing, hard deletes, and dashboard
// stats. Every endpoint except login/login-mfa/logout/me requires a valid
// admin cookie. Every non-GET route (including login/logout) additionally
// requires requireSameOrigin() to pass first (F-10 CSRF defense-in-depth: the
// admin cookie is already SameSite=Lax, this rejects cross-site requests from
// old browsers or same-site attackers too - see lib/http.js).
//
// F-13: when TOTP MFA is enabled (see lib/mfa.js), a correct password at
// /login no longer issues the admin cookie - only a short-lived intermediate
// cookie, exchanged for the real one at /login/mfa after a second factor
// (TOTP or backup code) verifies. See lib/auth.js's adminTag()/ADMIN_MFA_COOKIE.

import { existsSync } from 'node:fs';
import { config } from '../config.js';
import { db, now } from '../db.js';
import { json, error, cookie, clearCookie, clearSessionCookie, sessionCookieName, requestScheme, requestOrigin, requireSameOrigin, SECURITY_HEADERS, readJson, LOGIN_BODY_MAX, METADATA_BODY_MAX } from '../lib/http.js';
import { ADMIN_COOKIE, ADMIN_MFA_COOKIE, checkAdminPassword, issueAdminToken, isAdmin, mintUploadLink, issueAdminMfaToken, checkAdminMfaToken } from '../lib/auth.js';
import { deleteShareFiles, deleteBlob, totalUsage, withFileLock } from '../lib/storage.js';
import { enforce, reset } from '../lib/ratelimit.js';
import { acquire, overloaded } from '../lib/semaphore.js';
import { hashPassword } from '../lib/crypto.js';
import { slugError } from '../lib/slug.js';
import { getLogs } from '../lib/logbuffer.js';
import { ALLOWED_KEYS, ALLOWLIST, envManagedKeys, readSettings, validatePatch, writeSettings } from '../lib/settings.js';
import { lifetimeMetrics, topUploaders as lifetimeUploaders } from '../lib/stats.js';
import { listApiKeys, getApiKey, createApiKey, updateApiKey, revokeApiKey, reinstateApiKey, rotateApiKey, deleteApiKey, sanitizeLimits, limitsOf } from '../lib/apikeys.js';
import * as quota from '../lib/quota.js';
import { performShareRename, BUSY } from '../lib/renames.js';
import { audit } from '../lib/audit.js';
import { declareRoutePolicy } from '../lib/routePolicy.js';
import {
	mfaEnabled, pendingEnrollment, backupCodesRemaining, beginEnrollment, confirmEnrollment,
	disableMfa, regenerateBackupCodes, verifyLoginCode, consumeBackupCode, verifyMfaCode,
} from '../lib/mfa.js';

// The editable settings keys mapped to their current effective (booted) values,
// for pre-filling the editor. Secret keys are reported only as set/unset.
const effectiveSettings = () => ({
	BASE_URL: config.baseUrls.join(','),
	TRUST_PROXY: config.trustProxy ? '1' : '0',
	APP_NAME: config.appName,
	MAX_FILE_SIZE: String(config.maxFileSize),
	MAX_SHARE_SIZE: String(config.maxShareSize),
	MAX_TOTAL_SIZE: String(config.maxTotalSize),
	CHUNK_SIZE: String(config.chunkSize),
	MAX_FILES_PER_SHARE: String(config.maxFilesPerShare),
	MAX_PASSWORD_LENGTH: String(config.maxPasswordLength),
	DEFAULT_EXPIRY: String(config.defaultExpiry),
	SWEEP_INTERVAL: String(config.sweepInterval),
});
const secretIsSet = key =>
	key === 'SECRET' ? !config.ephemeralSecret : key === 'ADMIN_PASSWORD' ? !!config.adminPassword : !!config.uploadPassword;

// Allowlists keep the dynamic ORDER BY clause free of injected SQL.
const SORT_COLUMNS = {
	created: 'created_at',
	size: 'totalSize',
	downloads: 'download_count',
};
const SORT_ORDERS = { asc: 'ASC', desc: 'DESC' };

// L-03: every admin JSON body is read through this, capped at a route-
// appropriate ceiling (LOGIN_BODY_MAX / METADATA_BODY_MAX) instead of the
// server-wide upload-chunk-sized limit. `response` is a ready-to-return
// 413/400 Response when the body was rejected; `body` is always an object
// (never null) so existing destructuring call sites need no other change.
async function readBody(req, maxBytes) {
	const { value, response } = await readJson(req, maxBytes);
	return { body: value || {}, response };
}

export default router => {
	// ---- Session ----------------------------------------------------------

	declareRoutePolicy('POST', '/api/admin/login', { auth: 'public', csrf: true, rateLimit: 'admin-login', audit: 'admin.login.failure|admin.login.success' });
	router.post('/api/admin/login', async ({ req, ip, url, server }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		// Brute-force guard: 8 attempts per 5 minutes per IP. A successful login
		// clears the counter so a legitimate admin is never locked out. When MFA is
		// enabled this bucket is only cleared once the SECOND factor also succeeds
		// (see /api/admin/login/mfa below) - a correct password alone must not
		// widen the password-guessing budget.
		const limited = enforce('admin-login', ip, 8, 5 * 60 * 1000);
		if (limited) return limited;

		const { body, response: bodyErr } = await readBody(req, LOGIN_BODY_MAX);
		if (bodyErr) return bodyErr;
		const { password } = body;
		if (!checkAdminPassword(password)) {
			audit('admin.login.failure', { ip });
			return error(403, 'Invalid password');
		}

		const secure = requestScheme(req, url, server) === 'https';

		if (!mfaEnabled()) {
			reset('admin-login', ip);
			audit('admin.login.success', { ip, actor: 'admin' });
			const setCookie = cookie(sessionCookieName(ADMIN_COOKIE, secure), issueAdminToken(), { maxAge: config.adminSessionTtl, httpOnly: true, sameSite: 'Lax', secure });
			return json({ ok: true }, { headers: { 'Set-Cookie': setCookie } });
		}

		// MFA is enabled: the password alone is not enough. Issue a short-lived
		// intermediate cookie (not the real admin session) and require a second
		// step at /api/admin/login/mfa.
		const setCookie = cookie(sessionCookieName(ADMIN_MFA_COOKIE, secure), issueAdminMfaToken(), { maxAge: 5 * 60, httpOnly: true, sameSite: 'Lax', secure });
		return json({ ok: true, mfaRequired: true }, { headers: { 'Set-Cookie': setCookie } });
	});

	// Second step of a login when MFA is enabled: a 6-digit TOTP code, or a
	// backup code (any non-6-digit input is tried as one). Requires the
	// intermediate cookie from a just-passed password check, not the real admin
	// cookie - so it never grants anything on its own.
	declareRoutePolicy('POST', '/api/admin/login/mfa', { auth: 'adminIntermediate', csrf: true, rateLimit: 'admin-mfa', audit: 'admin.login.mfa_failure|admin.login.success|admin.mfa.backup_code_used' });
	router.post('/api/admin/login/mfa', async ({ req, ip, url, server }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		const limited = enforce('admin-mfa', ip, 8, 5 * 60 * 1000);
		if (limited) return limited;

		if (!checkAdminMfaToken(req)) return error(403, 'Session expired, enter your password again');

		const { body, response: bodyErr } = await readBody(req, LOGIN_BODY_MAX);
		if (bodyErr) return bodyErr;
		const { code } = body;
		const isTotpShaped = /^\d{6}$/.test(String(code ?? ''));
		const ok = isTotpShaped ? verifyLoginCode(code) : consumeBackupCode(code);
		if (!ok) {
			audit('admin.login.mfa_failure', { ip });
			return error(403, 'Invalid code');
		}

		reset('admin-mfa', ip);
		reset('admin-login', ip);
		audit('admin.login.mfa_success', { ip });
		// The password step (POST /login) intentionally does not log
		// admin.login.success while MFA is enabled - only once this second
		// factor also completes does the login actually finish.
		audit('admin.login.success', { ip, actor: 'admin' });
		if (!isTotpShaped) audit('admin.mfa.backup_code_used', { ip, actor: 'admin', detail: { remaining: backupCodesRemaining() } });

		const secure = requestScheme(req, url, server) === 'https';
		const headers = new Headers({ 'Content-Type': 'application/json; charset=utf-8', ...SECURITY_HEADERS });
		headers.append('Set-Cookie', cookie(sessionCookieName(ADMIN_COOKIE, secure), issueAdminToken(), { maxAge: config.adminSessionTtl, httpOnly: true, sameSite: 'Lax', secure }));
		headers.append('Set-Cookie', clearCookie(sessionCookieName(ADMIN_MFA_COOKIE, secure), secure));
		return new Response(JSON.stringify({ ok: true }), { headers });
	});

	declareRoutePolicy('POST', '/api/admin/logout', { auth: 'public', csrf: true, rateLimit: null, audit: 'admin.logout' });
	router.post('/api/admin/logout', async ({ req, ip, url, server }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (isAdmin(req)) audit('admin.logout', { ip, actor: 'admin' });
		const secure = requestScheme(req, url, server) === 'https';
		const headers = new Headers({ 'Content-Type': 'application/json; charset=utf-8', ...SECURITY_HEADERS });
		// Clears BOTH the current dynamic cookie name and the legacy plain name
		// (see clearSessionCookie()) - readSessionCookie()'s migration fallback
		// means a pre-existing session issued under the plain name must not
		// survive logout just because this request's scheme now mints "__Host-".
		for (const c of clearSessionCookie(ADMIN_COOKIE, secure)) headers.append('Set-Cookie', c);
		for (const c of clearSessionCookie(ADMIN_MFA_COOKIE, secure)) headers.append('Set-Cookie', c);
		return new Response(JSON.stringify({ ok: true }), { headers });
	});

	declareRoutePolicy('GET', '/api/admin/me', { auth: 'public', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/me', async ({ req }) => {
		return json({ admin: isAdmin(req) });
	});

	// ---- MFA management (F-13) ---------------------------------------------

	declareRoutePolicy('GET', '/api/admin/mfa', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/mfa', ({ req }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const enabled = mfaEnabled();
		return json({ enabled, pendingSetup: pendingEnrollment(), backupCodesRemaining: enabled ? backupCodesRemaining() : 0 });
	});

	// Requires the admin PASSWORD (not just the ambient cookie), same step-up
	// gate as /disable below - a hijacked admin cookie alone must not be able to
	// start enrolling a TOTP secret the attacker controls.
	declareRoutePolicy('POST', '/api/admin/mfa/setup', { auth: 'admin', csrf: true, rateLimit: 'admin-mfa-setup', audit: 'admin.mfa.setup_failed|admin.mfa.setup_started' });
	router.post('/api/admin/mfa/setup', async ({ req, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-mfa-setup', ip, 20, 60 * 60 * 1000);
		if (limited) return limited;
		const { body, response: bodyErr } = await readBody(req, LOGIN_BODY_MAX);
		if (bodyErr) return bodyErr;
		const { password } = body;
		if (!checkAdminPassword(password)) {
			audit('admin.mfa.setup_failed', { ip, detail: { reason: 'password' } });
			return error(403, 'Invalid password');
		}
		const { secret, otpauth } = beginEnrollment();
		audit('admin.mfa.setup_started', { ip, actor: 'admin' });
		return json({ secret, otpauth });
	});

	// Requires the admin PASSWORD, and - when MFA is ALREADY enabled - also a
	// valid code against the CURRENT confirmed factor (existingCode) before a
	// new pending secret is allowed to overwrite it. Without this, a hijacked
	// admin cookie could silently swap the enrolled authenticator/device out
	// from under the real admin and lock them out; first-ever enrollment (no
	// confirmed secret yet) has nothing to step up against, so existingCode is
	// only required once mfaEnabled() is true - checked fresh here, not cached.
	declareRoutePolicy('POST', '/api/admin/mfa/confirm', { auth: 'admin', csrf: true, rateLimit: 'admin-mfa-confirm', audit: 'admin.mfa.confirm_failed|admin.mfa.enabled' });
	router.post('/api/admin/mfa/confirm', async ({ req, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-mfa-confirm', ip, 10, 5 * 60 * 1000);
		if (limited) return limited;
		const { body, response: bodyErr } = await readBody(req, LOGIN_BODY_MAX);
		if (bodyErr) return bodyErr;
		const { password, code, existingCode } = body;
		if (!checkAdminPassword(password)) {
			audit('admin.mfa.confirm_failed', { ip, actor: 'admin', detail: { reason: 'password' } });
			return error(403, 'Invalid password');
		}
		if (mfaEnabled() && !verifyMfaCode(existingCode)) {
			audit('admin.mfa.confirm_failed', { ip, actor: 'admin', detail: { reason: 'existingCode' } });
			return error(403, 'Invalid existing code');
		}
		const backupCodes = confirmEnrollment(code);
		if (!backupCodes) {
			audit('admin.mfa.confirm_failed', { ip, actor: 'admin', detail: { reason: 'code' } });
			return error(403, 'Invalid code');
		}
		audit('admin.mfa.enabled', { ip, actor: 'admin' });
		return json({ ok: true, backupCodes });
	});

	// Requires the admin PASSWORD (not just the ambient cookie) and a valid
	// second factor (TOTP or backup code), so a hijacked admin cookie alone can
	// never silently strip MFA off the account.
	declareRoutePolicy('POST', '/api/admin/mfa/disable', { auth: 'admin', csrf: true, rateLimit: 'admin-mfa-disable', audit: 'admin.mfa.disable_failed|admin.mfa.disabled' });
	router.post('/api/admin/mfa/disable', async ({ req, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-mfa-disable', ip, 8, 5 * 60 * 1000);
		if (limited) return limited;
		const { body, response: bodyErr } = await readBody(req, LOGIN_BODY_MAX);
		if (bodyErr) return bodyErr;
		const { password, code } = body;
		if (!checkAdminPassword(password)) {
			audit('admin.mfa.disable_failed', { ip, detail: { reason: 'password' } });
			return error(403, 'Invalid password');
		}
		if (!verifyMfaCode(code)) {
			audit('admin.mfa.disable_failed', { ip, detail: { reason: 'code' } });
			return error(403, 'Invalid code');
		}
		disableMfa();
		audit('admin.mfa.disabled', { ip, actor: 'admin' });
		return json({ ok: true });
	});

	declareRoutePolicy('POST', '/api/admin/mfa/backup-codes', { auth: 'admin', csrf: true, rateLimit: 'admin-mfa-backup-codes', audit: 'admin.mfa.backup_codes_regen_failed|admin.mfa.backup_codes_regenerated' });
	router.post('/api/admin/mfa/backup-codes', async ({ req, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-mfa-backup-codes', ip, 20, 60 * 60 * 1000);
		if (limited) return limited;
		if (!mfaEnabled()) return error(400, 'MFA is not enabled');
		const { body, response: bodyErr } = await readBody(req, LOGIN_BODY_MAX);
		if (bodyErr) return bodyErr;
		const { code } = body;
		if (!verifyLoginCode(code)) {
			audit('admin.mfa.backup_codes_regen_failed', { ip, actor: 'admin' });
			return error(403, 'Invalid code');
		}
		const backupCodes = regenerateBackupCodes();
		audit('admin.mfa.backup_codes_regenerated', { ip, actor: 'admin' });
		return json({ backupCodes });
	});

	// ---- Share browsing ---------------------------------------------------

	declareRoutePolicy('GET', '/api/admin/shares', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/shares', async ({ req, query }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');

		const search = (query.get('search') || '').trim();
		// L-1: a plain bracket lookup on a client-supplied key (e.g. "__proto__")
		// resolves to Object.prototype instead of undefined - truthy, so the `||`
		// fallback never kicks in, and the object then gets stringified into the
		// raw SQL below as "[object Object]", a syntax error (500). hasOwn ignores
		// inherited properties, so an unrecognized/prototype-polluting key always
		// falls through to the default.
		const sortKeyIn = query.get('sort');
		const sortCol = (sortKeyIn && Object.hasOwn(SORT_COLUMNS, sortKeyIn)) ? SORT_COLUMNS[sortKeyIn] : SORT_COLUMNS.created;
		const orderKeyIn = (query.get('order') || '').toLowerCase();
		const sortOrder = Object.hasOwn(SORT_ORDERS, orderKeyIn) ? SORT_ORDERS[orderKeyIn] : 'DESC';

		let limit = Number(query.get('limit'));
		if (!Number.isFinite(limit) || limit <= 0) limit = 50;
		limit = Math.min(Math.trunc(limit), 500);
		let offset = Number(query.get('offset'));
		if (!Number.isFinite(offset) || offset < 0) offset = 0;
		offset = Math.trunc(offset);

		// Optional filter to just the shares created by one API key.
		const apiKey = (query.get('apiKey') || '').trim();

		const like = `%${search}%`;
		const conds = ['s.deleted_at IS NULL'];
		const filterArgs = [];
		if (search) {
			conds.push('(s.id LIKE ? OR s.title LIKE ?)');
			filterArgs.push(like, like);
		}
		if (apiKey) {
			conds.push('s.api_key_id = ?');
			filterArgs.push(apiKey);
		}
		const where = 'WHERE ' + conds.join(' AND ');

		const total = db.query(`SELECT COUNT(*) AS n FROM shares s ${where}`).get(...filterArgs).n;

		const rows = db
			.query(
				`SELECT s.id, s.title, s.created_at, s.expires_at, s.password_hash, s.one_time, s.max_downloads, s.download_count, s.view_count, s.finalized, s.api_key_id,
					(SELECT COUNT(*) FROM files f WHERE f.share_id = s.id) AS fileCount,
					(SELECT COALESCE(SUM(f.size), 0) FROM files f WHERE f.share_id = s.id) AS totalSize
				FROM shares s
				${where}
				ORDER BY ${sortCol} ${sortOrder}
				LIMIT ? OFFSET ?`,
			)
			.all(...filterArgs, limit, offset);

		const shares = rows.map(r => ({
			id: r.id,
			title: r.title,
			createdAt: r.created_at,
			expiresAt: r.expires_at,
			protected: !!r.password_hash,
			oneTime: !!r.one_time,
			maxDownloads: r.max_downloads,
			downloadCount: r.download_count,
			viewCount: r.view_count,
			finalized: !!r.finalized,
			fileCount: r.fileCount,
			totalSize: r.totalSize,
			apiKeyId: r.api_key_id,
		}));

		return json({ shares, total });
	});

	declareRoutePolicy('GET', '/api/admin/shares/:id', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/shares/:id', async ({ req, params }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');

		const share = db.query('SELECT * FROM shares WHERE id = ?').get(params.id);
		if (!share) return error(404, 'Not found');

		const files = db.query('SELECT * FROM files WHERE share_id = ? ORDER BY created_at ASC, id ASC').all(params.id);
		const events = db.query('SELECT id, file_id, ts, ip, ua FROM download_events WHERE share_id = ? ORDER BY ts DESC, id DESC LIMIT 20').all(params.id);

		let totalSize = 0;
		for (const f of files) totalSize += f.size;

		// Surface the API key that created the share (if any), so the admin can
		// trace it back and jump to that key's full share list.
		const apiKeyName = share.api_key_id ? db.query('SELECT name FROM api_keys WHERE id = ?').get(share.api_key_id)?.name ?? null : null;

		return json({
			id: share.id,
			title: share.title,
			createdAt: share.created_at,
			expiresAt: share.expires_at,
			protected: !!share.password_hash,
			oneTime: !!share.one_time,
			maxDownloads: share.max_downloads,
			downloadCount: share.download_count,
			viewCount: share.view_count,
			finalized: !!share.finalized,
			deletedAt: share.deleted_at,
			creatorIp: share.creator_ip,
			creatorUa: share.creator_ua,
			apiKeyId: share.api_key_id,
			apiKeyName,
			fileCount: files.length,
			totalSize,
			files: files.map(f => ({
				id: f.id,
				name: f.name,
				size: f.size,
				received: f.received,
				mime: f.mime,
				complete: !!f.complete,
				downloadCount: f.download_count,
				createdAt: f.created_at,
				// H-1: operator visibility only - which AAD scheme (e2e.js's
				// recordAad) this file's E2E records were sealed under. Meaningless
				// for a non-E2E share.
				aadVersion: f.e2e_aad_version,
			})),
			events: events.map(e => ({
				id: e.id,
				fileId: e.file_id,
				ts: e.ts,
				ip: e.ip,
				ua: e.ua,
			})),
		});
	});

	// ---- Edit (full field control) ----------------------------------------

	declareRoutePolicy('PATCH', '/api/admin/shares/:id', { auth: 'admin', csrf: true, rateLimit: 'admin-share-edit', audit: 'share.renamed' });
	router.patch('/api/admin/shares/:id', async ({ req, params, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-share-edit', ip, 120, 60 * 1000);
		if (limited) return limited;
		const share = db.query('SELECT id FROM shares WHERE id = ?').get(params.id);
		if (!share) return error(404, 'Not found');

		const { value, response: bodyErr } = await readJson(req, METADATA_BODY_MAX);
		if (bodyErr) return bodyErr;
		const body = value || {};

		// Validate a slug (id) change up front, before any writes.
		let newSlug = null;
		if (typeof body.slug === 'string' && body.slug.trim() && body.slug.trim() !== params.id) {
			newSlug = body.slug.trim();
			const err = slugError(newSlug);
			if (err) return error(400, err);
			if (db.query('SELECT id FROM shares WHERE lower(id) = lower(?) AND deleted_at IS NULL AND id != ?').get(newSlug, params.id)) return error(409, 'That custom link is already taken');
		}

		// Collect scalar field updates (all validated before the single UPDATE runs).
		const sets = [];
		const args = [];

		if ('title' in body) {
			const t = typeof body.title === 'string' ? body.title.trim().slice(0, 200) : '';
			sets.push('title = ?');
			args.push(t || null);
		}
		if ('expiresAt' in body) {
			if (body.expiresAt === null) {
				sets.push('expires_at = ?');
				args.push(null);
			} else {
				const n = Number(body.expiresAt);
				if (!Number.isFinite(n) || n < 0) return error(400, 'Invalid expiresAt');
				sets.push('expires_at = ?');
				args.push(Math.trunc(n));
			}
		}
		if ('maxDownloads' in body) {
			if (body.maxDownloads === null || body.maxDownloads === 0) {
				sets.push('max_downloads = ?');
				args.push(null);
			} else {
				const n = Number(body.maxDownloads);
				if (!Number.isFinite(n) || n < 1) return error(400, 'Invalid maxDownloads');
				sets.push('max_downloads = ?');
				args.push(Math.trunc(n));
			}
		}
		if ('oneTime' in body) {
			sets.push('one_time = ?');
			args.push(body.oneTime ? 1 : 0);
		}
		if ('finalized' in body) {
			sets.push('finalized = ?');
			args.push(body.finalized ? 1 : 0);
		}
		if (body.removePassword) {
			sets.push('password_hash = ?');
			args.push(null);
		} else if (typeof body.password === 'string' && body.password.length > 0) {
			if (body.password.length > config.maxPasswordLength) return error(400, 'Password is too long');
			const release = acquire('argon2', null, 4);
			if (!release) return overloaded(2);
			let hash;
			try {
				hash = await hashPassword(body.password);
			} finally {
				release();
			}
			sets.push('password_hash = ?');
			args.push(hash);
		}

		if (sets.length) db.query(`UPDATE shares SET ${sets.join(', ')} WHERE id = ?`).run(...args, params.id);

		let newId = params.id;
		if (newSlug) {
			try {
				await performShareRename(params.id, newSlug);
			} catch (e) {
				if (e === BUSY) return error(409, 'Another rename is in progress');
				// The DB side already committed (see lib/renames.js) - only the
				// filesystem move failed. The DB is authoritative; a restart will
				// finish moving the files via reconcileShareRenames().
				return error(500, 'Rename recorded; a restart will finish moving files');
			}
			newId = newSlug;
			audit('share.renamed', { ip, actor: 'admin', target: `${params.id}->${newSlug}` });
		}

		return json({ ok: true, id: newId });
	});

	// ---- Hard deletes -----------------------------------------------------

	declareRoutePolicy('DELETE', '/api/admin/shares/:id', { auth: 'admin', csrf: true, rateLimit: 'admin-share-delete', audit: 'share.deleted' });
	router.delete('/api/admin/shares/:id', async ({ req, params, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-share-delete', ip, 120, 60 * 1000);
		if (limited) return limited;

		const share = db.query('SELECT id, deleted_at FROM shares WHERE id = ?').get(params.id);
		if (!share) return error(404, 'Not found');

		// A soft-deleted share already released its quota at the moment it went
		// out of live (see lib/quota.js's idempotency rule) - releasing again here
		// would double-subtract. Only a still-live share (deleted_at IS NULL,
		// e.g. an admin hard-deleting without a prior soft-delete) needs it now,
		// and it must happen BEFORE the files rows are deleted below (releaseShare
		// reads them to total the committed bytes).
		if (share.deleted_at == null) quota.releaseShare(params.id);

		await deleteShareFiles(params.id);
		db.query('DELETE FROM files WHERE share_id = ?').run(params.id);
		db.query('DELETE FROM download_events WHERE share_id = ?').run(params.id);
		db.query('DELETE FROM shares WHERE id = ?').run(params.id);
		audit('share.deleted', { ip, actor: 'admin', target: params.id });

		return json({ ok: true });
	});

	declareRoutePolicy('DELETE', '/api/admin/shares/:id/files/:fileId', { auth: 'admin', csrf: true, rateLimit: 'admin-share-file-delete', audit: null });
	router.delete('/api/admin/shares/:id/files/:fileId', async ({ req, params, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-share-file-delete', ip, 120, 60 * 1000);
		if (limited) return limited;

		const file = db.query('SELECT id FROM files WHERE id = ? AND share_id = ?').get(params.fileId, params.id);
		if (!file) return error(404, 'Not found');

		// M-06 TOCTOU fix: held around the blob removal + row delete so this can
		// never interleave with lib/migrate.js's migrateFile() swap for the same
		// file id - see storage.js's withFileLock for what that closes.
		await withFileLock(params.fileId, async () => {
			// Re-check under the lock: a migration may have completed (or the file
			// may have been deleted by a concurrent request) while this request was
			// queued behind another lock holder.
			const stillThere = db.query('SELECT id FROM files WHERE id = ? AND share_id = ?').get(params.fileId, params.id);
			if (!stillThere) return;

			// Before removing the row: releases the file's committed usage (if it
			// was complete) and/or its still-open reservation.
			quota.releaseFile(params.fileId);
			await deleteBlob(params.id, params.fileId);
			db.query('DELETE FROM files WHERE id = ? AND share_id = ?').run(params.fileId, params.id);
		});

		return json({ ok: true });
	});

	// ---- Dashboard --------------------------------------------------------

	declareRoutePolicy('GET', '/api/admin/stats', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/stats', async ({ req }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');

		const shareCount = db.query('SELECT COUNT(*) AS n FROM shares WHERE deleted_at IS NULL').get().n;
		const downloadTotal = db.query('SELECT COALESCE(SUM(download_count), 0) AS n FROM shares WHERE deleted_at IS NULL').get().n;
		const viewTotal = db.query('SELECT COALESCE(SUM(view_count), 0) AS n FROM shares WHERE deleted_at IS NULL').get().n;
		const fileAgg = db
			.query(
				`SELECT COUNT(*) AS n, COALESCE(SUM(f.size), 0) AS total
				FROM files f
				JOIN shares s ON s.id = f.share_id
				WHERE s.deleted_at IS NULL`,
			)
			.get();

		return json({
			shareCount,
			fileCount: fileAgg.n,
			totalSize: fileAgg.total,
			downloadTotal,
			viewTotal,
			storageUsed: await totalUsage(),
			maxTotalSize: config.maxTotalSize,
		});
	});

	// At-a-glance leaderboards for the Overview: biggest shares by size, top
	// uploaders aggregated by creator IP (a "power user" view), and what is
	// expiring soonest.
	declareRoutePolicy('GET', '/api/admin/overview', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/overview', ({ req }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');

		const biggestShares = db
			.query(
				`SELECT s.id, s.title, COALESCE(SUM(f.size), 0) AS size, s.download_count AS downloads, s.view_count AS views, s.expires_at AS expiresAt
				FROM shares s LEFT JOIN files f ON f.share_id = s.id
				WHERE s.deleted_at IS NULL
				GROUP BY s.id ORDER BY size DESC LIMIT 8`,
			)
			.all();

		// Top uploaders come from the persistent lifetime table, so they are not
		// lost when a share is deleted. Mapped to the existing client field names.
		const topUploaders = lifetimeUploaders(8).map(u => ({
			ip: u.ip,
			shareCount: u.shares,
			totalSize: u.bytes,
			downloads: u.downloads,
			lastUpload: u.lastSeen,
		}));

		const expiringSoon = db
			.query(
				`SELECT s.id, s.title, s.expires_at AS expiresAt, COALESCE(SUM(f.size), 0) AS size
				FROM shares s LEFT JOIN files f ON f.share_id = s.id
				WHERE s.deleted_at IS NULL AND s.expires_at IS NOT NULL AND s.expires_at > strftime('%s', 'now')
				GROUP BY s.id ORDER BY s.expires_at ASC LIMIT 6`,
			)
			.all();

		// Lifetime totals (all-time, surviving deletion) for the Overview.
		const lifetime = lifetimeMetrics();

		return json({ biggestShares, topUploaders, expiringSoon, lifetime });
	});

	// ---- API keys ----------------------------------------------------------
	// Credentials that let other servers/scripts upload programmatically (see
	// routes/api.js). The secret is shown ONCE at creation and only its hash is
	// stored, so it can never be retrieved again - revoke and reissue if lost.

	declareRoutePolicy('GET', '/api/admin/api-keys', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/api-keys', ({ req }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		return json({ keys: listApiKeys() });
	});

	declareRoutePolicy('POST', '/api/admin/api-keys', { auth: 'admin', csrf: true, rateLimit: 'admin-apikey', audit: 'apikey.created' });
	router.post('/api/admin/api-keys', async ({ req, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-apikey', ip, 30, 60 * 60 * 1000);
		if (limited) return limited;

		const { body, response: bodyErr } = await readBody(req, METADATA_BODY_MAX);
		if (bodyErr) return bodyErr;
		const name = typeof body.name === 'string' ? body.name.trim().slice(0, 100) : '';
		if (!name) return error(400, 'A name is required');

		let expiresAt = null;
		if (body.expiresIn !== undefined && body.expiresIn !== null && body.expiresIn !== '') {
			const n = Number(body.expiresIn);
			if (!Number.isFinite(n) || n < 0) return error(400, 'Invalid expiresIn');
			if (n > 0) expiresAt = now() + Math.trunc(n);
		}

		const lim = sanitizeLimits(body.limits || {});
		if (lim.error) return error(400, lim.error);

		// The token is returned exactly once here; afterwards only its hash exists.
		const made = createApiKey(name, expiresAt, lim.values);
		audit('apikey.created', { ip, actor: 'admin', target: made.id });
		return json({ id: made.id, name: made.name, token: made.token, prefix: made.prefix, expiresAt }, 201);
	});

	// Edit a key's name and limits/scopes (does not touch the secret or expiry).
	declareRoutePolicy('PATCH', '/api/admin/api-keys/:id', { auth: 'admin', csrf: true, rateLimit: 'admin-apikey-edit', audit: 'apikey.updated' });
	router.patch('/api/admin/api-keys/:id', async ({ req, params, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-apikey-edit', ip, 120, 60 * 1000);
		if (limited) return limited;
		const { body, response: bodyErr } = await readBody(req, METADATA_BODY_MAX);
		if (bodyErr) return bodyErr;
		const name = typeof body.name === 'string' ? body.name.trim().slice(0, 100) : '';
		if (!name) return error(400, 'A name is required');
		const lim = sanitizeLimits(body.limits || {});
		if (lim.error) return error(400, lim.error);
		const before = getApiKey(params.id);
		if (!updateApiKey(params.id, name, lim.values)) return error(404, 'Not found');
		if (before) {
			const changed = [];
			if (before.name !== name) changed.push('name');
			const after = limitsOf(lim.values);
			for (const k of ['maxFileSize', 'maxShareSize', 'maxShares', 'maxExpiry', 'allowSlug', 'allowPassword']) {
				if (before.limits[k] !== after[k]) changed.push(k);
			}
			for (const s of ['create', 'write', 'read', 'delete']) {
				if (before.limits.scopes[s] !== after.scopes[s]) changed.push(`scope:${s}`);
			}
			if (changed.length) audit('apikey.updated', { ip, actor: 'admin', target: params.id, detail: { changed } });
		}
		return json({ ok: true });
	});

	declareRoutePolicy('GET', '/api/admin/api-keys/:id', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/api-keys/:id', ({ req, params }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const key = getApiKey(params.id);
		if (!key) return error(404, 'Not found');
		// A few recent shares this key created, for the detail view.
		const shares = db
			.query(
				`SELECT s.id, s.title, s.created_at AS createdAt, s.deleted_at AS deletedAt,
					(SELECT COALESCE(SUM(f.size), 0) FROM files f WHERE f.share_id = s.id) AS totalSize
				FROM shares s WHERE s.api_key_id = ? ORDER BY s.created_at DESC LIMIT 20`,
			)
			.all(params.id)
			.map(s => ({ id: s.id, title: s.title, createdAt: s.createdAt, deleted: s.deletedAt != null, totalSize: s.totalSize }));
		return json({ ...key, shares });
	});

	declareRoutePolicy('POST', '/api/admin/api-keys/:id/revoke', { auth: 'admin', csrf: true, rateLimit: 'admin-apikey-revoke', audit: 'apikey.revoked' });
	router.post('/api/admin/api-keys/:id/revoke', ({ req, params, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-apikey-revoke', ip, 120, 60 * 1000);
		if (limited) return limited;
		if (!revokeApiKey(params.id)) return error(404, 'Not found');
		audit('apikey.revoked', { ip, actor: 'admin', target: params.id });
		return json({ ok: true });
	});

	declareRoutePolicy('POST', '/api/admin/api-keys/:id/reinstate', { auth: 'admin', csrf: true, rateLimit: 'admin-apikey-reinstate', audit: 'apikey.reinstated' });
	router.post('/api/admin/api-keys/:id/reinstate', ({ req, params, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-apikey-reinstate', ip, 120, 60 * 1000);
		if (limited) return limited;
		if (!reinstateApiKey(params.id)) return error(404, 'Not found');
		audit('apikey.reinstated', { ip, actor: 'admin', target: params.id });
		return json({ ok: true });
	});

	// Rotate a key's secret: the old token stops working at once and portal
	// sessions bound to it are signed out. The new token is returned exactly once,
	// like creation; afterwards only its hash exists.
	declareRoutePolicy('POST', '/api/admin/api-keys/:id/rotate', { auth: 'admin', csrf: true, rateLimit: 'admin-apikey-rotate', audit: 'apikey.rotated' });
	router.post('/api/admin/api-keys/:id/rotate', ({ req, params, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-apikey-rotate', ip, 120, 60 * 1000);
		if (limited) return limited;
		const made = rotateApiKey(params.id);
		if (!made) return error(404, 'Not found');
		audit('apikey.rotated', { ip, actor: 'admin', target: params.id });
		return json({ id: made.id, name: made.name, token: made.token, prefix: made.prefix });
	});

	declareRoutePolicy('DELETE', '/api/admin/api-keys/:id', { auth: 'admin', csrf: true, rateLimit: 'admin-apikey-delete', audit: 'apikey.deleted' });
	router.delete('/api/admin/api-keys/:id', ({ req, params, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-apikey-delete', ip, 120, 60 * 1000);
		if (limited) return limited;
		if (!deleteApiKey(params.id)) return error(404, 'Not found');
		audit('apikey.deleted', { ip, actor: 'admin', target: params.id });
		return json({ ok: true });
	});

	// ---- Server operations -------------------------------------------------

	// Quick-access upload link (a single-use, 15-minute magic-link token - see
	// lib/auth.js's mintUploadLink()). The admin needs no upload cookie, so this
	// is a separate route from the upload-cookie-gated /api/upload/link. POST,
	// not GET (M-01): minting now creates server-side state (a row in
	// upload_link_tokens), so this is a state-creating action driven by the
	// ambient admin cookie and needs the same requireSameOrigin() CSRF proof
	// every other cookie-authenticated mutation in this file gets.
	declareRoutePolicy('POST', '/api/admin/upload-link', { auth: 'admin', csrf: true, rateLimit: null, audit: null });
	router.post('/api/admin/upload-link', ({ req, url, server }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		if (!config.uploadPassword) return json({ enabled: false });
		return json({ enabled: true, url: `${requestOrigin(req, url, server)}/?token=${encodeURIComponent(mintUploadLink())}` });
	});

	// Current editable settings. Secret values are NEVER returned - only a
	// set/unset flag. Keys provided by the server environment are reported as
	// envManaged: read-only in the editor, and for secrets not even the value's
	// origin beyond "the environment sets this". Non-secret keys show the
	// pending managed value if saved, else the live effective value.
	declareRoutePolicy('GET', '/api/admin/settings', { auth: 'admin', csrf: false, rateLimit: null, audit: null });
	router.get('/api/admin/settings', ({ req }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const managed = readSettings(config.dataDir);
		const eff = effectiveSettings();
		const fields = ALLOWED_KEYS.map(key => {
			const s = ALLOWLIST[key];
			const envManaged = envManagedKeys.has(key);
			const base = { key, label: s.label, help: s.help || null, type: s.type, secret: !!s.secret, clearable: !!s.clearable, danger: s.danger || null, envManaged };
			if (s.secret) return { ...base, set: secretIsSet(key) };
			return { ...base, value: envManaged ? (eff[key] ?? '') : key in managed ? managed[key] : (eff[key] ?? '') };
		});
		return json({
			fields,
			readOnly: { HOST: config.host, PORT: String(config.port), DATA_DIR: config.dataDir },
			ephemeralSecret: config.ephemeralSecret,
			uploadPasswordSet: !!config.uploadPassword,
			// Process uptime: admin-only (see L-07 - the public /health probe
			// deliberately discloses nothing).
			uptime: Math.floor(process.uptime()),
		});
	});

	// Save settings to the managed file (does NOT apply live - needs a restart).
	declareRoutePolicy('PUT', '/api/admin/settings', { auth: 'admin', csrf: true, rateLimit: 'admin-settings', audit: 'admin.settings.updated' });
	router.put('/api/admin/settings', async ({ req, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-settings', ip, 30, 60 * 60 * 1000);
		if (limited) return limited;

		const { value, response: bodyErr } = await readJson(req, METADATA_BODY_MAX);
		if (bodyErr) return bodyErr;
		const body = value || {};
		const r = validatePatch(body);
		if (r.error) return error(400, r.error);

		try {
			writeSettings(config.dataDir, r);
		} catch (e) {
			console.error('settings write failed:', e);
			return error(500, 'Could not save settings');
		}
		// target = comma-joined changed KEY names ONLY - never values (some of
		// these keys are secrets: SECRET/ADMIN_PASSWORD/UPLOAD_PASSWORD).
		const changedKeys = [...Object.keys(r.set), ...r.clear];
		if (changedKeys.length) audit('admin.settings.updated', { ip, actor: 'admin', target: changedKeys.join(',') });
		return json({ ok: true, restartRequired: true, warnings: [] });
	});

	// Restart by exiting; a supervisor (Docker restart: unless-stopped, systemd)
	// relaunches the process, which re-reads the managed settings file.
	declareRoutePolicy('POST', '/api/admin/restart', { auth: 'admin', csrf: true, rateLimit: 'admin-restart', audit: 'admin.restart' });
	router.post('/api/admin/restart', ({ req, ip }) => {
		const csrf = requireSameOrigin(req);
		if (csrf) return csrf;
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-restart', ip, 5, 60 * 60 * 1000);
		if (limited) return limited;
		audit('admin.restart', { ip, actor: 'admin' });
		console.warn('[admin] restart requested - exiting for the supervisor to relaunch');
		// Exit after the response has a chance to flush.
		setTimeout(() => process.exit(0), 200);
		return json({ ok: true, restarting: true, willAutoRecover: existsSync('/.dockerenv') });
	});

	// Recent process logs (newest-last), from the in-memory ring buffer.
	declareRoutePolicy('GET', '/api/admin/logs', { auth: 'admin', csrf: false, rateLimit: 'admin-logs', audit: null });
	router.get('/api/admin/logs', ({ req, ip, query }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-logs', ip, 120, 60 * 1000);
		if (limited) return limited;
		let limit = Number(query.get('limit'));
		if (!Number.isFinite(limit) || limit <= 0) limit = 300;
		return json({ logs: getLogs(limit) });
	});

	// Structured security-event audit log (see lib/audit.js). Same pagination
	// shape as GET /api/admin/shares: limit capped at 500 (default 100),
	// offset >= 0, ordered newest-first, with an optional exact-match event
	// filter. detail is stored as a JSON string; parsed back here for the
	// caller's convenience (falls back to the raw string if it somehow isn't
	// valid JSON, rather than dropping it).
	declareRoutePolicy('GET', '/api/admin/audit', { auth: 'admin', csrf: false, rateLimit: 'admin-audit', audit: null });
	router.get('/api/admin/audit', ({ req, ip, query }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-audit', ip, 120, 60 * 1000);
		if (limited) return limited;

		let limit = Number(query.get('limit'));
		if (!Number.isFinite(limit) || limit <= 0) limit = 100;
		limit = Math.min(Math.trunc(limit), 500);
		let offset = Number(query.get('offset'));
		if (!Number.isFinite(offset) || offset < 0) offset = 0;
		offset = Math.trunc(offset);
		const eventFilter = query.get('event') || '';

		const where = eventFilter ? 'WHERE event = ?' : '';
		const args = eventFilter ? [eventFilter] : [];

		const total = db.query(`SELECT COUNT(*) AS n FROM audit_events ${where}`).get(...args).n;
		const rows = db
			.query(`SELECT id, ts, event, ip, actor, target, detail FROM audit_events ${where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`)
			.all(...args, limit, offset);

		const events = rows.map(r => {
			let detail = null;
			if (r.detail != null) {
				try {
					detail = JSON.parse(r.detail);
				} catch {
					detail = r.detail;
				}
			}
			return { id: r.id, ts: r.ts, event: r.event, ip: r.ip, actor: r.actor, target: r.target, detail };
		});

		return json({ events, total });
	});
};
