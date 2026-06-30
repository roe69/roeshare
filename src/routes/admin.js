// Admin API: session login/logout, share browsing, hard deletes, and dashboard
// stats. Every endpoint except login/logout/me requires a valid admin cookie.

import { existsSync } from 'node:fs';
import { config } from '../config.js';
import { db } from '../db.js';
import { json, error, cookie, clearCookie, requestScheme, requestOrigin } from '../lib/http.js';
import { ADMIN_COOKIE, checkAdminPassword, issueAdminToken, isAdmin, uploadLinkToken } from '../lib/auth.js';
import { deleteShareFiles, deleteBlob, totalUsage, renameShareDir } from '../lib/storage.js';
import { enforce, reset } from '../lib/ratelimit.js';
import { hashPassword } from '../lib/crypto.js';
import { slugError } from '../lib/slug.js';
import { getLogs } from '../lib/logbuffer.js';
import { ALLOWED_KEYS, ALLOWLIST, readSettings, validatePatch, writeSettings } from '../lib/settings.js';

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

// Move a share to a new id (slug): copy the row, repoint children, drop the old
// row. Done as one transaction so FK constraints never see a dangling parent.
const renameShare = db.transaction((oldId, newId) => {
	db.query(
		`INSERT INTO shares (id, title, created_at, expires_at, password_hash, max_downloads, download_count, one_time, edit_token, finalized, deleted_at, creator_ip, creator_ua)
		 SELECT ?, title, created_at, expires_at, password_hash, max_downloads, download_count, one_time, edit_token, finalized, deleted_at, creator_ip, creator_ua FROM shares WHERE id = ?`,
	).run(newId, oldId);
	db.query('UPDATE files SET share_id = ? WHERE share_id = ?').run(newId, oldId);
	db.query('UPDATE download_events SET share_id = ? WHERE share_id = ?').run(newId, oldId);
	db.query('DELETE FROM shares WHERE id = ?').run(oldId);
});

// Allowlists keep the dynamic ORDER BY clause free of injected SQL.
const SORT_COLUMNS = {
	created: 'created_at',
	size: 'totalSize',
	downloads: 'download_count',
};
const SORT_ORDERS = { asc: 'ASC', desc: 'DESC' };

async function readBody(req) {
	try {
		return await req.json();
	} catch {
		return {};
	}
}

export default router => {
	// ---- Session ----------------------------------------------------------

	router.post('/api/admin/login', async ({ req, ip, url }) => {
		// Brute-force guard: 8 attempts per 5 minutes per IP. A successful login
		// clears the counter so a legitimate admin is never locked out.
		const limited = enforce('admin-login', ip, 8, 5 * 60 * 1000);
		if (limited) return limited;

		const { password } = await readBody(req);
		if (!checkAdminPassword(password)) return error(403, 'Invalid password');
		reset('admin-login', ip);
		const setCookie = cookie(ADMIN_COOKIE, issueAdminToken(), { maxAge: config.adminSessionTtl, httpOnly: true, sameSite: 'Lax', secure: requestScheme(req, url) === 'https' });
		return json({ ok: true }, { headers: { 'Set-Cookie': setCookie } });
	});

	router.post('/api/admin/logout', async () => {
		return json({ ok: true }, { headers: { 'Set-Cookie': clearCookie(ADMIN_COOKIE) } });
	});

	router.get('/api/admin/me', async ({ req }) => {
		return json({ admin: isAdmin(req) });
	});

	// ---- Share browsing ---------------------------------------------------

	router.get('/api/admin/shares', async ({ req, query }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');

		const search = (query.get('search') || '').trim();
		const sortCol = SORT_COLUMNS[query.get('sort')] || SORT_COLUMNS.created;
		const sortOrder = SORT_ORDERS[(query.get('order') || '').toLowerCase()] || 'DESC';

		let limit = Number(query.get('limit'));
		if (!Number.isFinite(limit) || limit <= 0) limit = 50;
		limit = Math.min(Math.trunc(limit), 500);
		let offset = Number(query.get('offset'));
		if (!Number.isFinite(offset) || offset < 0) offset = 0;
		offset = Math.trunc(offset);

		const like = `%${search}%`;
		const where = 'WHERE s.deleted_at IS NULL' + (search ? ' AND (s.id LIKE ? OR s.title LIKE ?)' : '');
		const filterArgs = search ? [like, like] : [];

		const total = db.query(`SELECT COUNT(*) AS n FROM shares s ${where}`).get(...filterArgs).n;

		const rows = db
			.query(
				`SELECT s.id, s.title, s.created_at, s.expires_at, s.password_hash, s.one_time, s.max_downloads, s.download_count, s.view_count, s.finalized,
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
		}));

		return json({ shares, total });
	});

	router.get('/api/admin/shares/:id', async ({ req, params }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');

		const share = db.query('SELECT * FROM shares WHERE id = ?').get(params.id);
		if (!share) return error(404, 'Not found');

		const files = db.query('SELECT * FROM files WHERE share_id = ? ORDER BY created_at ASC, id ASC').all(params.id);
		const events = db.query('SELECT id, file_id, ts, ip, ua FROM download_events WHERE share_id = ? ORDER BY ts DESC, id DESC LIMIT 20').all(params.id);

		let totalSize = 0;
		for (const f of files) totalSize += f.size;

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

	router.patch('/api/admin/shares/:id', async ({ req, params }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const share = db.query('SELECT id FROM shares WHERE id = ?').get(params.id);
		if (!share) return error(404, 'Not found');

		let body;
		try {
			body = (await req.json()) || {};
		} catch {
			return error(400, 'Invalid JSON body');
		}

		// Validate a slug (id) change up front, before any writes.
		let newSlug = null;
		if (typeof body.slug === 'string' && body.slug.trim() && body.slug.trim() !== params.id) {
			newSlug = body.slug.trim();
			const err = slugError(newSlug);
			if (err) return error(400, err);
			if (db.query('SELECT id FROM shares WHERE id = ?').get(newSlug)) return error(409, 'That custom link is already taken');
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
			sets.push('password_hash = ?');
			args.push(await hashPassword(body.password));
		}

		if (sets.length) db.query(`UPDATE shares SET ${sets.join(', ')} WHERE id = ?`).run(...args, params.id);

		let newId = params.id;
		if (newSlug) {
			renameShare(params.id, newSlug);
			await renameShareDir(params.id, newSlug);
			newId = newSlug;
		}

		return json({ ok: true, id: newId });
	});

	// ---- Hard deletes -----------------------------------------------------

	router.delete('/api/admin/shares/:id', async ({ req, params }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');

		const share = db.query('SELECT id FROM shares WHERE id = ?').get(params.id);
		if (!share) return error(404, 'Not found');

		await deleteShareFiles(params.id);
		db.query('DELETE FROM files WHERE share_id = ?').run(params.id);
		db.query('DELETE FROM download_events WHERE share_id = ?').run(params.id);
		db.query('DELETE FROM shares WHERE id = ?').run(params.id);

		return json({ ok: true });
	});

	router.delete('/api/admin/shares/:id/files/:fileId', async ({ req, params }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');

		const file = db.query('SELECT id FROM files WHERE id = ? AND share_id = ?').get(params.fileId, params.id);
		if (!file) return error(404, 'Not found');

		await deleteBlob(params.id, params.fileId);
		db.query('DELETE FROM files WHERE id = ? AND share_id = ?').run(params.fileId, params.id);

		return json({ ok: true });
	});

	// ---- Dashboard --------------------------------------------------------

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

		// Sum per-share size from a pre-grouped subquery so SUM(download_count) is
		// not multiplied by the files-per-share fan-out.
		const topUploaders = db
			.query(
				`SELECT s.creator_ip AS ip, COUNT(DISTINCT s.id) AS shareCount,
					COALESCE(SUM(sz.total), 0) AS totalSize, COALESCE(SUM(s.download_count), 0) AS downloads, MAX(s.created_at) AS lastUpload
				FROM shares s LEFT JOIN (SELECT share_id, SUM(size) AS total FROM files GROUP BY share_id) sz ON sz.share_id = s.id
				WHERE s.deleted_at IS NULL
				GROUP BY s.creator_ip ORDER BY totalSize DESC LIMIT 8`,
			)
			.all();

		const expiringSoon = db
			.query(
				`SELECT s.id, s.title, s.expires_at AS expiresAt, COALESCE(SUM(f.size), 0) AS size
				FROM shares s LEFT JOIN files f ON f.share_id = s.id
				WHERE s.deleted_at IS NULL AND s.expires_at IS NOT NULL AND s.expires_at > strftime('%s', 'now')
				GROUP BY s.id ORDER BY s.expires_at ASC LIMIT 6`,
			)
			.all();

		return json({ biggestShares, topUploaders, expiringSoon });
	});

	// ---- Server operations -------------------------------------------------

	// Quick-access upload link (the HMAC-derived token, not the password). The
	// admin needs no upload cookie, so this is a separate route from the
	// upload-cookie-gated /api/upload/link.
	router.get('/api/admin/upload-link', ({ req, url }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		if (!config.uploadPassword) return json({ enabled: false });
		return json({ enabled: true, url: `${requestOrigin(req, url)}/?token=${encodeURIComponent(uploadLinkToken())}` });
	});

	// Current editable settings. Secret values are NEVER returned - only a
	// set/unset flag. Non-secret keys show the pending managed value if saved,
	// else the live effective value.
	router.get('/api/admin/settings', ({ req }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const managed = readSettings(config.dataDir);
		const eff = effectiveSettings();
		const fields = ALLOWED_KEYS.map(key => {
			const s = ALLOWLIST[key];
			const base = { key, label: s.label, help: s.help || null, type: s.type, secret: !!s.secret, clearable: !!s.clearable, danger: s.danger || null };
			if (s.secret) return { ...base, set: secretIsSet(key) };
			return { ...base, value: key in managed ? managed[key] : (eff[key] ?? '') };
		});
		return json({
			fields,
			readOnly: { HOST: config.host, PORT: String(config.port), DATA_DIR: config.dataDir },
			ephemeralSecret: config.ephemeralSecret,
			uploadPasswordSet: !!config.uploadPassword,
		});
	});

	// Save settings to the managed file (does NOT apply live - needs a restart).
	router.put('/api/admin/settings', async ({ req, ip }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-settings', ip, 30, 60 * 60 * 1000);
		if (limited) return limited;

		let body;
		try {
			body = (await req.json()) || {};
		} catch {
			return error(400, 'Invalid JSON body');
		}
		const r = validatePatch(body);
		if (r.error) return error(400, r.error);

		try {
			writeSettings(config.dataDir, r);
		} catch (e) {
			console.error('settings write failed:', e);
			return error(500, 'Could not save settings');
		}
		const warnings = [];
		if (r.secretChanged) warnings.push('SECRET changed: after restart, all sessions and quick-access links are invalidated and existing encrypted uploads become permanently unreadable.');
		return json({ ok: true, restartRequired: true, warnings });
	});

	// Restart by exiting; a supervisor (Docker restart: unless-stopped, systemd)
	// relaunches the process, which re-reads the managed settings file.
	router.post('/api/admin/restart', ({ req, ip }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-restart', ip, 5, 60 * 60 * 1000);
		if (limited) return limited;
		console.warn('[admin] restart requested - exiting for the supervisor to relaunch');
		// Exit after the response has a chance to flush.
		setTimeout(() => process.exit(0), 200);
		return json({ ok: true, restarting: true, willAutoRecover: existsSync('/.dockerenv') });
	});

	// Recent process logs (newest-last), from the in-memory ring buffer.
	router.get('/api/admin/logs', ({ req, ip, query }) => {
		if (!isAdmin(req)) return error(403, 'Forbidden');
		const limited = enforce('admin-logs', ip, 120, 60 * 1000);
		if (limited) return limited;
		let limit = Number(query.get('limit'));
		if (!Number.isFinite(limit) || limit <= 0) limit = 300;
		return json({ logs: getLogs(limit) });
	});
};
