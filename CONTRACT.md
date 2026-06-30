# RoeShare build contract

This is the shared spec for the modules built on top of the core. The core
(config, db, router, server, `src/lib/*`, `public/css/*`, `public/js/shared.js`)
already exists and MUST NOT be modified except to fix a genuine bug. Build the
leaf modules described here against these exact contracts.

## Runtime

- Bun (>= 1.1). ES modules. No build step, no extra dependencies.
- Server entry `src/server.js` already wires the router, static assets, security
  headers, and the expired-share sweeper. Start with `bun run src/server.js`.

## Data model (`src/db.js`)

`db` is a `bun:sqlite` `Database`. `now()` returns epoch seconds.

- **shares**: `id` (text pk), `title`, `created_at`, `expires_at` (null=never),
  `password_hash` (null=public), `max_downloads` (null=unlimited),
  `download_count`, `one_time` (0/1), `edit_token`, `finalized` (0/1),
  `deleted_at` (null=live), `creator_ip`.
- **files**: `id` (text pk), `share_id` (fk, cascade), `name` (sanitized
  display name), `size` (declared bytes), `received` (bytes on disk = resume
  offset), `mime`, `complete` (0/1), `download_count`, `created_at`,
  `stored_name` (== `id`, the on-disk blob name).
- **download_events**: `id`, `share_id`, `file_id`, `ts`, `ip`, `ua`.

Use prepared statements: `db.query('...').get/all/run(...)`.

## Core library surface (import and use; do not reimplement)

- `../config.js` -> `config` (chunkSize, maxFileSize, maxShareSize,
  maxTotalSize, defaultExpiry, baseUrl, adminPassword, uploadPassword, ...).
- `../lib/http.js` -> `json(data, statusOrInit)`, `error(status, msg, extra?)`,
  `text`, `noContent`, `parseCookies(req)`, `cookie(name,val,opts)`,
  `clearCookie(name)`, `clientIp(req,server)`, `parseRange(header,size)`
  (returns `null` | `{invalid:true}` | `{start,end,length}`),
  `contentDisposition(name, inline?)`, `SECURITY_HEADERS`.
- `../lib/crypto.js` -> `hashPassword`, `verifyPassword`, `safeEqual`,
  `signToken`, `verifyToken`.
- `../lib/auth.js` -> `ADMIN_COOKIE`, `checkAdminPassword(pw)`,
  `issueAdminToken()`, `isAdmin(req)`, `uploadAllowed(pw)`,
  `issueAccessToken(shareId)`, `hasAccessToken(token, shareId)`,
  `readAccessToken(req, url)`.
- `../lib/storage.js` -> `writeChunk(shareId,fileId,offset,bytes)->newSize`,
  `blobFile(shareId,fileId)` (Bun file: `.size`, `.stream()`, `.slice(a,b)`),
  `deleteShareFiles(shareId)`, `deleteBlob(shareId,fileId)`, `totalUsage()`.
- `../lib/zip.js` -> `createZipStream(entries, when?)` where `entries` is
  `[{ name, file: blobFile(...), size }]`, returns a `ReadableStream`.
- `../lib/ids.js` -> `newShareId()`, `newFileId()`, `newToken()`.

## Route module shape

Each `src/routes/<name>.js` default-exports `(router) => { ... }` and registers
routes with `router.get/post/patch/delete(pattern, handler)`. Handlers are
`async (ctx) => Response` where `ctx = { req, url, params, server, ip, query }`.
`params` come from `:name` segments. Always return a `Response`.

## Auth transport

- **Admin**: signed cookie `ADMIN_COOKIE`. Guard with `isAdmin(req)`.
- **Share owner**: `editToken` returned at creation, sent back as the
  `X-Edit-Token` request header. Compare against `shares.edit_token`.
- **Share visitor (password-gated)**: access token from
  `readAccessToken(req, url)` (Authorization: Bearer OR `?access=` query),
  validated with `hasAccessToken(token, shareId)`. A valid `editToken` also
  grants access.

## HTTP API (build these)

### Public config
`GET /api/config` -> `{ chunkSize, maxFileSize, maxShareSize, defaultExpiry, uploadPasswordRequired: boolean, baseUrl }`
`POST /api/upload/verify` body `{ password }` -> `{ ok: true }` + sets the signed
`roeshare_upload` cookie if it matches `config.uploadPassword` (or uploads are
open), else `403`. Rate-limited. The cookie gates BOTH page serving and creation:
when `config.uploadPassword` is set and the cookie is absent, `GET /` serves
`lock.html` (not `upload.html`) and `GET /js/upload.js` 404s, so the upload
portal's markup/code never leaves the server unauthorized. `POST /api/shares`
accepts the cookie (`hasUploadAccess`) or a `uploadPassword` in the body.

### Upload (owner, via X-Edit-Token except create)
- `POST /api/shares` body `{ title?, slug?, password?, expiresIn? (sec, 0=never, omit=default), maxDownloads? (0/null=unlimited), oneTime? (bool), uploadPassword? }`
  -> `201 { id, editToken, chunkSize, maxFileSize, maxShareSize }`.
  If `config.uploadPassword` is set, reject when `uploadAllowed(uploadPassword)` is false (`403`).
  `slug` is an optional custom share URL: `[A-Za-z0-9_-]{3,64}` (`400` if malformed),
  used as the share `id` when free (`409` if already taken). Omit for a random id.
  `e2e: true` marks a zero-knowledge end-to-end share: the client encrypts every
  chunk (AES-256-GCM, record = 12B IV + ct + 16B tag) and the encrypted filename
  before upload; the server stores raw ciphertext (no server-side encryption,
  `iv=null`), never sees the key (it lives only in the link `#fragment`), and
  disables server-side zip (`download-all` -> `409`). `GET /api/shares/:id`
  returns `e2e: boolean`; for e2e shares the file `name` is the encrypted blob and
  `mime` is `application/octet-stream`. The chunk guard allows `chunkSize + 64`.
- `POST /api/shares/:id/files` (X-Edit-Token) body `{ name, size, mime }`
  -> `{ fileId, received }`. Sanitize `name` (basename only). Enforce
  `size <= maxFileSize` and running share total `<= maxShareSize`; if
  `maxTotalSize` set, enforce `totalUsage()+size <= maxTotalSize`.
- `GET /api/shares/:id/files/:fileId/status` (X-Edit-Token) -> `{ received, size, complete }` (for resume).
- `PATCH /api/shares/:id/files/:fileId?offset=N` (X-Edit-Token) body = raw bytes
  (`application/octet-stream`). Reject if `offset !== files.received` (`409 { received }`).
  Write via `writeChunk`, update `received`, set `complete` when `received === size`.
  -> `{ received, complete }`.
- `POST /api/shares/:id/finalize` (X-Edit-Token) -> `{ id, url }` (`url = config.baseUrl + '/' + id`). Sets `finalized=1`.

### View / download (visitor)
- `GET /api/shares/:id` -> share metadata. `404` if missing/deleted/expired.
  If password-protected and caller lacks a valid access/edit token: `401 { protected: true, title? }`.
  Otherwise `{ id, title, createdAt, expiresAt, oneTime, maxDownloads, downloadCount, finalized, totalSize, owner: boolean, files: [{ id, name, size, mime, complete, downloadCount }] }`.
- `POST /api/shares/:id/unlock` body `{ password }` -> `{ accessToken }` on success, `403` on failure. Use `verifyPassword`.
- `GET /api/shares/:id/files/:fileId/preview` -> inline stream
  (`Content-Disposition: inline`), Range-aware (`206` + `Content-Range` +
  `Accept-Ranges: bytes`). Does NOT count as a download. Enforce access + not expired.
- `GET /api/shares/:id/files/:fileId/download` -> attachment stream, Range-aware.
  Counts as one download: increment `files.download_count` and `shares.download_count`,
  insert a `download_events` row. Enforce `maxDownloads` (block with `410` when reached),
  expiry, and access. If `one_time`, soft-delete the share + `deleteShareFiles` after the response.
- `GET /api/shares/:id/download-all` -> a single zip (`createZipStream`) of all
  complete files, attachment named `<title-or-id>.zip`. Counts as one download;
  same `maxDownloads`/`one_time` handling.

### Owner / admin management
- `DELETE /api/shares/:id` (X-Edit-Token OR admin) -> owner deletes their own share. `{ ok: true }`.
- `POST /api/admin/login` body `{ password }` -> set `ADMIN_COOKIE` (HttpOnly, SameSite=Lax, Max-Age=config.adminSessionTtl), `{ ok: true }`. Use `checkAdminPassword`.
- `POST /api/admin/logout` -> clear cookie.
- `GET /api/admin/me` -> `{ admin: boolean }`.
- `GET /api/admin/shares?search=&sort=created|size|downloads&order=asc|desc&limit=&offset=&apiKey=` (admin)
  -> `{ shares: [{ id, title, createdAt, expiresAt, protected, oneTime, maxDownloads, downloadCount, finalized, fileCount, totalSize, apiKeyId }], total }`.
  `apiKey` scopes the list to the shares created by that API key id.
- `GET /api/admin/shares/:id` (admin) -> full detail incl files + last ~20 download_events + `creatorIp`/`creatorUa` + `apiKeyId`/`apiKeyName` (the key that created it, if any).
- `PATCH /api/admin/shares/:id` (admin) -> edit any field. Body keys are optional and only applied when present: `title`, `slug` (rename id; validated + 409 if taken), `expiresAt` (epoch sec or null=never), `maxDownloads` (number or null/0=unlimited), `oneTime` (bool), `finalized` (bool), `password` (set new) or `removePassword: true` (clear). Returns `{ ok, id }` (id changes on rename).
- `DELETE /api/admin/shares/:id` (admin) -> hard delete (db rows + blobs). `{ ok: true }`.
- `DELETE /api/admin/shares/:id/files/:fileId` (admin) -> delete one file (blob + row). `{ ok: true }`.
- `GET /api/admin/stats` (admin) -> `{ shareCount, fileCount, totalSize, downloadTotal, storageUsed, maxTotalSize }`.

### API keys (admin manages; programs use)
API keys let other servers/scripts upload without a browser session. A key is a
bearer token `rsk_<id>_<secret>`; only `sha256(secret)` is stored (`src/lib/apikeys.js`).
The `id` is the public lookup key and the recognizable prefix.
Each key carries optional limits/scopes (`limits` object, all optional):
`maxFileSize`/`maxShareSize` (bytes, clamped to the server maxima, 0/blank=inherit),
`maxShares` (lifetime share cap, null=unlimited), `maxExpiry` (seconds; forces every
share from the key to expire within this window), `allowSlug`/`allowPassword` (bool,
default true). Enforced at share creation and file registration.
- `GET /api/admin/api-keys` (admin) -> `{ keys: [{ id, name, prefix, createdAt, lastUsedAt, expiresAt, revokedAt, uploadCount, bytesUploaded, liveShares, limits }] }`.
- `POST /api/admin/api-keys` (admin) body `{ name, expiresIn? (sec, 0/omit=never), limits? }` -> `201 { id, name, token, prefix, expiresAt }`. `token` is the FULL key and is returned ONCE.
- `PATCH /api/admin/api-keys/:id` (admin) body `{ name, limits }` -> `{ ok: true }`. Edits the name and the full limits/scopes set (does not touch the secret or expiry).
- `GET /api/admin/api-keys/:id` (admin) -> the key (incl `limits`) plus `shares: [{ id, title, createdAt, deleted, totalSize }]` (last ~20 it created).
- `POST /api/admin/api-keys/:id/revoke` (admin) -> `{ ok: true }` (sets `revoked_at`).
- `POST /api/admin/api-keys/:id/reinstate` (admin) -> `{ ok: true }` (clears `revoked_at`; a key past its expiry stays inactive until extended).
- `DELETE /api/admin/api-keys/:id` (admin) -> hard delete the key row. `{ ok: true }` (shares it created are untouched).

### Programmatic API (`/api/v1`, `src/routes/api.js`)
Auth: `Authorization: Bearer rsk_...` or `X-Api-Key: rsk_...`. `401` when missing/invalid/revoked/expired.
Shares created here are attributed via `shares.api_key_id` and count toward the
key's `uploadCount`/`bytesUploaded`. The key's own limits/scopes apply on top of the
server caps: exceeding a byte cap is `413`; hitting the share cap, or using a disallowed
slug/password scope, is `403`; the key's `maxExpiry` clamps the share's expiry.
- `GET /api/v1/me` -> `{ id, name, createdAt, lastUsedAt, expiresAt, uploadCount, bytesUploaded }`. Cheap key check.
- `POST /api/v1/shares` body `{ title?, slug?, password?, expiresIn?, maxDownloads?, oneTime? }`
  -> `201 { id, editToken, url, chunkSize, maxFileSize, maxShareSize }`. Then drive the standard
  resumable endpoints (`POST /api/shares/:id/files`, PATCH chunks, `POST .../finalize`) with `X-Edit-Token`. Use for large files.
- `POST /api/v1/upload` one-shot: request body IS the file bytes; filename via the
  `X-Filename` header (or `?filename=`); options as query params (`title`, `slug`,
  `password`, `expiresIn`, `maxDownloads`, `oneTime`, `mime`). Creates + finalizes a
  single-file share. -> `201 { id, url, fileId, name, size }`. Bounded by the server's
  max request body size (so for files beyond that, use the resumable flow above).

Manage / restore (for backup clients). A key can only see and act on the shares it
created (others 404):
- `GET /api/v1/shares?limit=&offset=&search=` -> `{ shares: [{ id, title, url, createdAt, expiresAt, oneTime, e2e, password, maxDownloads, downloadCount, viewCount, finalized, fileCount, totalSize }], total, limit, offset }`. Excludes soft-deleted. `limit` max 500.
- `GET /api/v1/shares/:id` -> the share plus `files: [{ id, name, size, received, mime, complete, downloadCount, download }]` (the `download` URL is ready to fetch with the same key).
- `DELETE /api/v1/shares/:id` -> soft-delete the share + drop its blobs. `{ ok: true }`.
- Retrieval: the existing `GET /api/shares/:id/files/:fileId/download` (and `/preview`,
  `/download-all`) treat the **owning API key** as the owner, so a private (even
  password-protected) backup is fetched by sending `Authorization: Bearer rsk_...` -
  no per-share password or edit token needed. Range-aware for resumable restores.

### Pages (`src/routes/pages.js`)
- `GET /` -> serve `public/upload.html`.
- `GET /s/:id` -> serve `public/view.html`.
- `GET /admin` -> serve `public/admin.html`.
- `GET /<slug>` (root-level custom link) -> serve `public/view.html`. Handled as a
  fallback in `server.js` AFTER routes + static, matching `^/[A-Za-z0-9_-]{1,64}$`,
  so it never shadows real routes or assets. `view.js` resolves the share from the
  last path segment, so `/s/:id` and `/:id` both work.
Serve with `Bun.file(...)` and `Content-Type: text/html` + the page CSP.

## Streaming pattern (download/preview)

```js
const f = blobFile(shareId, fileId);          // Bun file
const size = f.size;
const range = parseRange(req.headers.get('range'), size);
if (range?.invalid) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${size}` } });
const slice = range ? f.slice(range.start, range.end + 1) : f;
return new Response(slice.stream(), {
  status: range ? 206 : 200,
  headers: {
    'Content-Type': mime,
    'Content-Length': String(range ? range.length : size),
    'Accept-Ranges': 'bytes',
    'Content-Disposition': contentDisposition(name, /*inline*/ true|false),
    ...(range ? { 'Content-Range': `bytes ${range.start}-${range.end}/${size}` } : {}),
  },
});
```

## Frontend pages (no build, `<script type="module">`)

Each HTML page links `/css/app.css`, renders the aurora background + header, and
loads its module. Shared helpers live in `/js/shared.js`:
`el, $, $$, escapeHtml, api, ApiError, toast/toastOk/toastErr, openModal,
formatBytes, formatDate, timeUntil, copyText, fileGlyph, previewKind`.

- **`public/upload.html` + `public/js/upload.js`**: drag-and-drop + file picker,
  per-file resumable chunked upload (create share -> register files -> PATCH
  chunks of `config.chunkSize` -> finalize), live progress bars, share options
  (password, expiry, max downloads, one-time, title). On finish: show the share
  link + copy button + QR. Persist `editToken` to `localStorage` keyed by id.
- **`public/view.html` + `public/js/view.js`**: fetch metadata; if `401 protected`,
  show a password form -> `unlock` -> store accessToken in memory and append
  `?access=` to media URLs. List files with inline preview (image/video/audio/
  pdf/text via `previewKind`), per-file download, and "Download all (zip)".
  If owner (has editToken for this id), show delete controls.
- **`public/admin.html` + `public/js/admin.js`**: login form (if `me.admin` is
  false) -> stats cards -> searchable/sortable table of shares with per-row open
  link, copy link, and delete (with confirm modal); bulk delete; per-file delete
  in a detail view.

For QR, vendor a small self-contained generator at `public/js/qrcode.js` (pure
JS, no network) and import it from `upload.js`; if omitted, fall back to a copy
link only.

## Conventions

- No emojis or em-dashes in user-facing copy (glyph icons in `fileGlyph` are ok).
- Use the `rl-*` classes from `app.css`; do not inline hex colors or hand-tuned spacing.
- Validate all inputs server-side. Never trust client-declared sizes for caps.
- Return proper status codes (400/401/403/404/409/410/413/416/500).
