# RoeShare API & module reference

The authoritative technical reference for RoeShare: the HTTP API (request and
response shapes, status codes, auth transport), the data model, and the internal
module surfaces the routes are built on. For setup, configuration, and usage see
[README.md](README.md); to rebrand it, see [CUSTOMIZING.md](CUSTOMIZING.md).

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
- `../lib/auth.js` -> `ADMIN_COOKIE`, `ADMIN_MFA_COOKIE`, `checkAdminPassword(pw)`,
  `issueAdminToken()`, `issueAdminMfaToken()`, `checkAdminMfaToken(req)`,
  `isAdmin(req)`, `uploadAllowed(pw)`, `hasUploadAccess(req)`,
  `issueUploadToken()`, `mintUploadLink()`, `redeemUploadLink(token)`,
  `issueAccessToken(shareId)`, `hasAccessToken(token, shareId)`,
  `readAccessToken(req, url)`.
- `../lib/mfa.js` -> `mfaEnabled()`, `mfaEnabledAt()`, `pendingEnrollment()`,
  `backupCodesRemaining()`, `beginEnrollment()`, `confirmEnrollment(code)`,
  `disableMfa()`, `regenerateBackupCodes()`, `verifyLoginCode(code)`,
  `consumeBackupCode(code)`, `verifyMfaCode(code)`.
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
  `X-Edit-Token` request header. Compare against `shares.edit_token`. (M-05)
  A browser may instead exchange that header once, via
  `POST /api/shares/:id/owner-session`, for an HttpOnly, per-share, "__Host-"
  (over https) cookie - every owner-gated route accepts either credential;
  the header path is unaffected and needs no same-origin proof, the cookie
  path does (`requireSameOrigin()`).
- **Share visitor (password-gated)**: access token from
  `readAccessToken(req, url)` (Authorization: Bearer OR `?access=` query),
  validated with `hasAccessToken(token, shareId)`. A valid `editToken` (header
  or owner-session cookie) also grants access.

## HTTP API (build these)

### Public config
`GET /api/config` -> `{ chunkSize, maxFileSize, maxShareSize, defaultExpiry, uploadPasswordRequired: boolean, baseUrl }`
`POST /api/upload/verify` body `{ password }` -> `{ ok: true }` + sets the signed
`roeshare_upload` cookie if it matches `config.uploadPassword` (or uploads are
open), else `403`. Rate-limited. The cookie gates BOTH page serving and creation:
when `config.uploadPassword` is set and the cookie is absent, `GET /` serves
`lock.html` (not `upload.html`) and `GET /js/upload.js` 404s, so the upload
portal's markup/code never leaves the server unauthorized.

**Magic link** (instant-login link for someone who already has upload access,
so the real upload password never has to be shared out):
- `POST /api/upload/link` (requires existing upload access; CSRF-checked) ->
  `{ enabled: false }` if no `config.uploadPassword` is set, else
  `{ enabled: true, url }` where `url` is `<origin>/?token=<token>` - a
  single-use, 15-minute token minted from `SECRET` (`mintUploadLink()`), not
  the password itself.
- `POST /api/upload/link/redeem` body `{ token }` -> `{ ok: true }` and sets
  the same `roeshare_upload` cookie as `/api/upload/verify`, or `403` for a
  missing/invalid/expired/already-redeemed token (never reveals which).
  Rate-limited (`magic-link` bucket, 20/5min per IP). Deliberately a POST
  fired only from the `/?token=` interstitial's own JS, never a bare GET, so
  a link-preview scanner prefetching the pasted URL can't silently burn the
  token before the intended human clicks it.

`POST /api/shares`
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
  Two record formats exist, disambiguated per-file by `files.e2e_aad_version`
  (H-1): **legacy** (`aadVersion 0`) is `12B IV + ct + 16B tag` with no AAD -
  self-authenticated only, so splicing two same-length records under the same
  key goes undetected. **Current** (`aadVersion 1`) additionally binds
  `roeshare/e2e/v1\0<purpose>\0<fileId>\0<chunkIndex>\0<plainLen>` as GCM
  additional data on every record (`purpose` is `name` for the encrypted
  filename/metadata record, `chunk` for a content record; see
  `public/js/e2e.js`'s `recordAad`), closing that gap. `GET /api/shares/:id`
  includes `aadVersion` on every file in `files`; the client must use it to
  pick the right scheme when decrypting, or when encrypting further chunks of
  an already-registered (possibly resumed) file - a file's scheme is fixed for
  its whole lifetime once registered.
- `POST /api/shares/:id/files` (X-Edit-Token) body `{ name, size, mime, id?, aadVersion? }`
  -> `{ fileId, received }`. Sanitize `name` (basename only). `id`/`aadVersion`
  are optional and only honored together on an `e2e` share (H-1): the browser
  generates `id` itself (same shape as the encryption key -
  `toB64u(crypto.getRandomValues(16))`, charset `[0-9A-Za-z_-]{1,64}`) so the
  encrypted-filename record can be AAD-bound to it, and asserts `aadVersion`
  (the scheme it actually used - the server cannot infer this). A PK collision
  on a supplied `id` is `409` (regenerate and retry). Omitted on old clients
  or non-`e2e` shares, which keep the server-generated id / `aadVersion 0`
  behavior unchanged. Enforce
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
  Otherwise `{ id, title, createdAt, expiresAt, oneTime, maxDownloads, downloadCount, finalized, totalSize, owner: boolean, protected: boolean, files: [{ id, name, size, mime, complete, downloadCount, aadVersion }] }`. `protected` reflects whether a password is currently set (D3: lets the owner UI show "Remove password" vs. "Make private" without a second request).
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
- `PATCH /api/shares/:id` (X-Edit-Token, owning API key, or owner-session cookie)
  body `{ expiresIn?, password? }` - the minimal owner self-service surface (no
  title/slug editing; a share is already unlisted-by-id). `expiresIn`: `0` =
  never, a positive integer = seconds from now, absent = unchanged; anything
  else `400 'Invalid expiresIn'`. A share created by an API key with
  `max_expiry` has `expiresIn` clamped to that cap here too (same as create) -
  a key holder cannot PATCH past the admin-imposed lifetime. `expiresIn` on a
  not-yet-finalized share is `409` ("Finish uploading before changing
  expiry") - its expiry clock hasn't started yet, and finalize's
  upload-duration shift would silently re-shift whatever was just set.
  `password`: a string sets/replaces it ("make
  private"), explicit `null` clears it ("make public"), absent = unchanged; an
  empty string is `400`. Rate-limited (20/min per share). Because visitor
  access tokens are bound to `password_hash` (`issueAccessToken`/
  `hasAccessToken`), setting/changing/clearing the password invalidates every
  outstanding visitor access token for the share automatically - the owner
  re-obtains one from `GET /api/shares/:id`. -> `200 { ok: true, expiresAt,
  protected }`.
- `POST /api/admin/login` body `{ password }` -> on success, either sets
  `ADMIN_COOKIE` (HttpOnly, SameSite=Lax, Max-Age=config.adminSessionTtl) and
  returns `{ ok: true }`, or - when TOTP MFA is enabled (F-13) - returns
  `{ ok: true, mfaRequired: true }` with NO admin cookie yet, instead setting a
  short-lived (5 min) intermediate cookie that only `/api/admin/login/mfa`
  below accepts. `403` on a wrong password either way. Use `checkAdminPassword`.
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

### Admin MFA (TOTP step-up)
F-13: optional second factor on top of the admin password (`src/lib/mfa.js`).
When enabled, `POST /api/admin/login` alone no longer issues the real admin
cookie (see above) - the flow finishes at `/login/mfa`. Endpoints below other
than the login step require the real admin cookie (`isAdmin`) and, where
noted, the admin PASSWORD again as step-up proof, so a hijacked admin cookie
alone can never enroll, disable, or read backup codes.
- `POST /api/admin/login/mfa` (requires the intermediate cookie from a
  just-passed password check, not the real admin cookie) body `{ code }` -> a
  6-digit string is tried as a TOTP code, anything else as a backup code ->
  sets `ADMIN_COOKIE` and clears the intermediate cookie, `{ ok: true }`.
  `403 'Invalid code'` on failure, `403` with a re-authenticate message if the
  intermediate cookie expired (5 min). Rate-limited (`admin-mfa`, 8/5min).
- `GET /api/admin/mfa` (admin) -> `{ enabled, pendingSetup: boolean, backupCodesRemaining }`.
- `POST /api/admin/mfa/setup` (admin) body `{ password }` -> `{ secret, otpauth }`
  (a new pending TOTP secret + `otpauth://` URI to render as a QR code). `403`
  on a wrong password. Rate-limited (`admin-mfa-setup`, 20/hour).
- `POST /api/admin/mfa/confirm` (admin) body `{ password, code, existingCode? }`
  -> confirms the pending secret from `/setup` with a valid 6-digit `code`,
  enabling MFA -> `{ ok: true, backupCodes: string[] }` (shown once). Requires
  `existingCode` (valid against the currently enabled factor) when MFA is
  already on, so a hijacked cookie can't swap out the enrolled authenticator.
  `403` on a wrong password/existingCode/code. Rate-limited (`admin-mfa-confirm`, 10/5min).
- `POST /api/admin/mfa/disable` (admin) body `{ password, code }` -> disables
  MFA. Requires both the password and a valid TOTP/backup `code`. `403` on
  either failing. Rate-limited (`admin-mfa-disable`, 8/5min).
- `POST /api/admin/mfa/backup-codes` (admin) body `{ code }` -> regenerates
  the backup code set -> `{ backupCodes: string[] }`. `400` if MFA isn't
  enabled, `403` on an invalid code. Rate-limited (`admin-mfa-backup-codes`, 20/hour).

### API keys (admin manages; programs use)
API keys let other servers/scripts upload without a browser session. A key is a
bearer token `rsk_<id>_<secret>`; only `sha256(secret)` is stored (`src/lib/apikeys.js`).
The `id` is the public lookup key and the recognizable prefix.
Each key carries optional limits/scopes (`limits` object, all optional):
`maxFileSize`/`maxShareSize` (bytes, clamped to the server maxima, 0/blank=inherit),
`maxShares` (lifetime share cap; omitted/blank defaults to `config.defaultKeyMaxShares`
(`DEFAULT_KEY_MAX_SHARES`, default 1000), explicit `0`/null=unlimited), `maxExpiry` (seconds; forces every
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
Auth: `Authorization: Bearer rsk_...` or `X-Api-Key: rsk_...`, OR the portal session
cookie below. `401` when missing/invalid/revoked/expired.

Browser portal (so a key holder can manage their shares at `/api`):
- `POST /api/v1/login` body `{ name, token }` -> sets the `roeshare_apikey` session cookie when the token is valid AND its key name matches `name`; `{ id, name }`. Else `403`. Rate-limited.
- `GET /api/v1/session` -> `{ session: { id, name } | null }`.
- `POST /api/v1/logout` -> clears the cookie.
The cookie authenticates every `/api/v1` endpoint and is accepted as the owner on
`/api/shares/:id/files/:fileId/download` (and preview/zip), so the portal can list,
download, and delete without re-sending the token.
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
  `expiresIn`, `maxDownloads`, `oneTime`, `mime`). `expiresIn` (seconds): omitted or
  empty = `config.defaultExpiry` (7 days on prod); `0` = never; a positive integer =
  seconds from now, clamped by the key's `maxExpiry`. RoeSnip's RoeShare provider
  sends the literal `expiresIn=0` by default (never-expire), not the omitted/default
  form. Password via the `X-Upload-Password`
  header ONLY (keeps it out of proxy logs/history/Referer) - a `?password=` query param
  is rejected with `400` rather than silently ignored, so a stale client fails loud
  instead of publishing an unprotected share. Creates + finalizes a single-file share.
  -> `201 { id, url, fileId, name, size, editToken, expiresAt }`. `editToken` is the
  plaintext owner secret (only its hash is stored server-side) - use it as
  `X-Edit-Token` on owner-gated routes. `expiresAt` is the resolved expiry (epoch
  seconds, or `null` for never). Both fields are additive; older clients that only
  read `url` are unaffected. Bounded by the server's max request body
  size (so for files beyond that, use the resumable flow above).

Manage / restore (for backup clients). A key can only see and act on the shares it
created (others 404):
- `GET /api/v1/shares?limit=&offset=&search=` -> `{ shares: [{ id, title, url, createdAt, expiresAt, oneTime, e2e, password, maxDownloads, downloadCount, viewCount, finalized, fileCount, totalSize }], total, limit, offset }`. Excludes soft-deleted. `limit` max 500.
- `GET /api/v1/shares/:id` -> the share plus `files: [{ id, name, size, received, mime, complete, downloadCount, download }]` (the `download` URL is ready to fetch with the same key).
- `DELETE /api/v1/shares/:id` -> soft-delete the share + drop its blobs. `{ ok: true }`.
- Retrieval: the existing `GET /api/shares/:id/files/:fileId/download` (and `/preview`,
  `/download-all`) treat the owning API key as the owner, so a private (even
  password-protected) backup is fetched by sending `Authorization: Bearer rsk_...` -
  no per-share password or edit token needed. Range-aware for resumable restores.

### Pages (`src/routes/pages.js`)
- `GET /` -> serve `public/upload.html`.
- `GET /s/:id` -> serve `public/view.html` via `serveSharePage(id, origin)`.
- `GET /admin` -> serve `public/admin.html`.
- `GET /<slug>` (root-level custom link) -> serve `public/view.html` via the same
  `serveSharePage()`. Handled as a fallback in `server.js` AFTER routes + static,
  matching `^/[A-Za-z0-9_-]{1,64}$`, so it never shadows real routes or assets.
  `view.js` resolves the share from the last path segment, so `/s/:id` and `/:id`
  both work. This is the route the one-shot upload's returned `url` actually hits.
Serve with `Bun.file(...)` and `Content-Type: text/html` + the page CSP.

`serveSharePage(idOrSlug, origin)` additionally splices per-request OpenGraph/
Twitter embed meta into `view.html`'s `{{SHARE_META}}` head token (never
memoized - only the templated base HTML is cached per file, same as every other
page). Resolves the share by a direct, read-only DB lookup (id, then a
case-insensitive slug fallback) with the exact same live/finalized/not-expired
predicate as `GET /api/shares/:id`, but never calls that handler - so a crawler
prefetching a pasted link never inflates `view_count`. A case-variant match
(the id/slug resolved only via the lower() fallback) `302`s to the
canonically-cased `/s/:id` instead of rendering the page directly - `view.js`'s
own share fetch is case-sensitive, so serving meta at the wrong case would show
a rich embed for a link that 404s the moment anyone clicks it. Rich meta
(title, description, `og:image` -> the file's `/preview` URL) is emitted only
when the share is finalized, not `e2e`, not password-protected, not `one_time`, not
download-capped (`maxDownloads` unset - `/preview` itself 403s a non-owner
once it is), and has at least one complete file whose mime is in
`EMBED_IMAGE_MIME` (png/jpeg/gif/webp/avif - a deliberate subset of
`download.js`'s `SAFE_INLINE`, no svg) or `EMBED_VIDEO_MIME` (mp4 only). Every
other case - missing id, `e2e`, password-protected, one-time, download-capped,
no eligible image/video, or unfinalized - renders NO embed meta at all: the
`{{SHARE_META}}` token resolves to an empty string (byte-identical pages with
zero per-share data, so the absence of meta never reveals which case applies),
and a chat link-preview crawler UA (`BOT_UA_RE`: Discordbot etc.) fetching such
a URL gets an empty `204` instead of the HTML page, so chat apps generate no
embed of any kind for a non-media link. (Embeddable shares keep the bare-bytes
bot path: the crawler's fetch of the share URL returns the raw image/mp4 bytes
directly via `servePreview`, with `Vary: User-Agent`.) Every dynamic value
(title, filename) is escaped via `lib/html.js`'s `escapeHtmlAttr` before
templating - the first server-side templating of user-controlled text into
HTML in this codebase.

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
  link + copy button + QR. (M-05) Exchange `editToken` for an owner-session
  cookie via `POST /api/shares/:id/owner-session`; persist only the share id
  (not the token) to `localStorage`, in the owned-ids list `shared.js` exposes.
- **`public/view.html` + `public/js/view.js`**: fetch metadata; if `401 protected`,
  show a password form -> `unlock` -> store accessToken in memory and append
  `?access=` to media URLs. List files with inline preview (image/video/audio/
  pdf/text via `previewKind`), per-file download, and "Download all (zip)".
  A single-file image share auto-expands its own preview, mirroring the
  existing single-text-note auto-expand, when preview is permitted for this
  viewer (owner, or no one-time/download-cap restriction). D3: before the
  metadata fetch, an `#edit=<token>` fragment (only ever produced by RoeSnip's
  Open action) is parsed and IMMEDIATELY stripped via `history.replaceState`
  (even if the exchange below fails), then exchanged via
  `POST /api/shares/:id/owner-session` for the owner-session cookie; failure
  is silent (proceeds as an ordinary visitor). If owner (`share.owner`,
  resolved server-side from the owner-session cookie), show expiry/password
  management controls (PATCH `/api/shares/:id`) alongside delete.
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
