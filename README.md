# RoeShare

RoeShare is a secure, self-hosted file-sharing server that wraps the RoeLite
OSRS-inspired design around a fast, dependency-free upload and download flow.
Drag a file in, get an opaque share link,
and control exactly who can fetch it and for how long. It runs on the Bun
runtime with no build step and no extra dependencies, storing its state in a
single SQLite database and plain blobs on disk.

## Features

- Resumable chunked uploads that survive refreshes and dropped connections.
- Drag-and-drop and file-picker uploads with live per-file progress bars.
- In-browser preview for video, audio, images, PDF, and text.
- Per-share controls: password, expiry, max downloads, and one-time burn.
- Custom share links: pick your own URL slug when it is free, or get a random one.
- Per-IP rate limiting on admin login, password unlock, and share creation.
- Zip download of an entire share in a single stream.
- Owner self-management through an edit token saved in the browser.
- Admin panel with delete, stats, and searchable, sortable share listings.
- Range streaming for smooth seeking and resumable downloads.
- QR code for every share link, generated locally with no network calls.

## Quick start (Docker, recommended)

One command builds and runs everything. It writes a `.env` with a strong random
`SECRET` and admin password on first run:

```sh
bash setup.sh
```

It prints the URL and the generated admin password. To override values:

```sh
PORT=8080 ADMIN_PASSWORD=hunter2 UPLOAD_PASSWORD=letmein bash setup.sh
```

Or run Compose directly once a `.env` exists:

```sh
docker compose up -d --build      # start
docker compose logs -f            # logs
docker compose down               # stop
```

The image is ~150 MB (Bun on Alpine, no build step, zero npm dependencies),
exposes `/healthz` for the container healthcheck, and persists the database and
uploads in the `roeshare-data` volume.

## Quick start (Bun, no Docker)

1. Install Bun (>= 1.1). See https://bun.sh for instructions.
2. Copy the example environment file and set the required secrets:

   ```sh
   cp .env.example .env
   ```

   Edit `.env` and set at least `ADMIN_PASSWORD` (unlocks the admin panel) and
   `SECRET` (signs cookies and access tokens). Generate a secret with:

   ```sh
   bun -e "console.log(crypto.randomUUID()+crypto.randomUUID())"
   ```

3. Start the server:

   ```sh
   bun run src/server.js
   ```

The server listens on `http://0.0.0.0:3300` by default. Open it in a browser to
upload, visit `/s/:id` for a share, and `/admin` for the admin panel. The data
directory (SQLite db plus uploaded blobs) is created automatically.

## Configuration

All settings are read from the environment once at boot. Every value has a sane
default except `ADMIN_PASSWORD` and `SECRET`, which you should always set.

| Variable         | Default                  | Description                                                                 |
| ---------------- | ------------------------ | --------------------------------------------------------------------------- |
| `HOST`           | `0.0.0.0`                | Network interface to bind.                                                   |
| `PORT`           | `3300`                   | Port to listen on.                                                          |
| `BASE_URL`       | `http://localhost:3300`  | Public base URL for share links and QR codes. No trailing slash. Comma-separate multiple domains for multi-domain serving (e.g. `https://share.example.com,https://files.example.com`); links are built from the visitor's domain, first entry is the canonical fallback. |
| `ADMIN_PASSWORD` | `change-me`              | Admin panel password. Required for admin access; if unset, admin is locked. |
| `SECRET`         | (ephemeral)              | Secret used to sign cookies and access tokens. Required in production.       |
| `TRUST_PROXY`    | `0`                      | Honor X-Forwarded-For/X-Real-IP for client IP. On ONLY behind a trusted proxy; off when exposed directly (else IPs are spoofable). |
| `DATA_DIR`       | `./data`                 | Directory holding the SQLite db and uploaded blobs.                         |
| `MAX_FILE_SIZE`  | `5368709120` (5 GiB)     | Max size of a single file, in bytes.                                        |
| `MAX_SHARE_SIZE` | `10737418240` (10 GiB)   | Max total size of one share, in bytes.                                      |
| `MAX_TOTAL_SIZE` | `0`                      | Total storage cap across all shares, in bytes. 0 = unlimited.              |
| `CHUNK_SIZE`     | `8388608` (8 MiB)        | Upload chunk size advertised to clients, in bytes.                         |
| `UPLOAD_PASSWORD`| (empty)                  | Require a password to create shares. Empty = open uploads.                  |
| `DEFAULT_EXPIRY` | `604800` (7 days)        | Default expiry for new shares, in seconds. 0 = never.                       |
| `SWEEP_INTERVAL` | `3600` (1 hour)          | Background sweep interval for expired shares, in seconds.                   |

If `SECRET` is unset, RoeShare generates an ephemeral key and warns at startup;
all sessions and access tokens reset on restart, so set a stable secret in
production.

### App-managed settings (admin panel)

The admin panel has a **Server** section that can edit most of the settings
above, copy a quick-access upload link, restart the server, and view recent
logs. Panel edits are saved to `${DATA_DIR}/settings.env` (inside the data
volume) and **applied on the next restart** — they are not live. A few things to
know:

- **They override `.env`.** At boot, the managed file is layered over the
  environment for its keys, so a value set once in the panel wins over the host
  `.env` forever. To hand a key back to `.env`, remove it from
  `settings.env` (or use the editor's Clear control where available) and
  restart. `HOST`, `PORT`, and `DATA_DIR` are intentionally **not** editable
  (they're pinned by the container/compose).
- **Restart needs a supervisor.** The Restart button exits the process; Docker's
  `restart: unless-stopped` (or systemd `Restart=always`) relaunches it. Without
  one, the app stays down.
- **`SECRET` is guarded.** Changing it logs everyone out, invalidates every
  quick-access link, and **permanently** breaks decryption of existing uploads,
  so the editor requires an explicit confirmation. Set it once and leave it.
- **Secrets now live in the volume.** Because the managed file can hold
  `SECRET`/passwords, a backup of the data volume may contain them — protect and
  encrypt volume backups accordingly. The file is written `0600`.

## Deployment

### Single binary

Bun can compile RoeShare into a standalone executable that bundles the runtime:

```sh
bun build --compile src/server.js --outfile roeshare
```

Ship the resulting `roeshare` binary alongside the `public/` directory and your
`.env`, then run `./roeshare`.

### systemd

Run it as a service with a unit like:

```ini
[Unit]
Description=RoeShare
After=network.target

[Service]
WorkingDirectory=/opt/roeshare
ExecStart=/usr/local/bin/bun run src/server.js
EnvironmentFile=/opt/roeshare/.env
Restart=always

[Install]
WantedBy=multi-user.target
```

Use `Restart=always` (not `on-failure`): the admin panel's **Restart** button
exits the process cleanly (exit 0), so only `always` relaunches it. The Docker
`docker-compose.yml` already uses `restart: unless-stopped`, which behaves the
same way.

### Docker / Compose

A production `Dockerfile` and `docker-compose.yml` are included. Use `setup.sh`
(see the Docker quick start above) or run `docker compose up -d --build`. The
`roeshare-data` volume persists the database and uploaded blobs.

## Performance

- **Compression**: text responses (HTML, CSS, JS, JSON, SVG, manifest) are
  served with brotli or gzip per the client's `Accept-Encoding`. Typical savings
  are 70-85% (e.g. the stylesheet drops from ~18 KB to ~3 KB). File downloads,
  previews, and zips are streamed uncompressed so HTTP range requests and
  already-compressed media are never buffered or re-encoded.
- **Static cache**: each asset under `public/` is read once, hashed for an
  `ETag`, and its compressed variants are cached in memory, so repeat requests
  serve from RAM with conditional `304 Not Modified` support. (Editing files in
  `public/` requires a restart to take effect.)
- **No build step, no dependencies**: the frontend is plain ES modules and the
  server has zero npm runtime dependencies, which keeps the image small and cold
  starts fast. SQLite runs in WAL mode with prepared statements throughout.
- **Health**: `GET /healthz` returns `{ ok, uptime }` for load balancers and the
  container healthcheck.

## Security notes

- Encryption at rest: uploaded blobs are stored as AES-256-CTR ciphertext, keyed
  from `SECRET`, and decrypted only in memory while streaming to an authorized
  request. Someone with raw disk, volume, or backup access cannot read the files.
  CTR keeps downloads seekable. Back up `SECRET` - without it the files are
  unrecoverable. (A random-slug share with no password is still reachable by
  anyone who has the link; add a password for confidentiality.)
- Opaque ids: random shares, file ids, and tokens are unguessable, so links
  cannot be enumerated. (Custom slugs are user-chosen and therefore guessable -
  password-protect anything sensitive that uses one.)
- Access control: admin endpoints require an HMAC-signed admin cookie (rate-
  limited login, no forgery without `SECRET`); password-protected shares refuse
  metadata, download, preview, zip, and ranged reads without the password or the
  owner edit token; per-share access tokens are scoped to one share.
- Transport: run behind HTTPS in production (the admin cookie is marked `Secure`
  automatically when `BASE_URL` is `https`). Set `TRUST_PROXY=1` only behind a
  trusted reverse proxy.
- Path-traversal-safe storage: uploaded names are sanitized to a basename and
  blobs are stored under their generated id, never under client-supplied paths.
- Argon2 share passwords: per-share passwords are hashed, never stored in plain
  text, and verified in constant time.
- Signed HMAC tokens: the admin cookie and per-share access tokens are signed
  with `SECRET` and validated server-side.
- Range streaming: downloads and previews stream with HTTP range support, so
  large files never need to be buffered in memory.
- All inputs are validated server-side and size caps are enforced against actual
  bytes on disk, not client-declared sizes.

## API overview

RoeShare exposes a JSON API under `/api`. The main groups are:

- Public config: `GET /api/config`.
- Upload (owner, via the `X-Edit-Token` header): create a share, register
  files, PATCH chunks, and finalize.
- View and download (visitor): fetch metadata, unlock password-protected
  shares, preview inline, download files, and download a whole share as a zip.
- Owner and admin management: owner delete, admin login/logout, searchable
  share listings, per-share and per-file delete, and stats.
- Programmatic API (`/api/v1`): API-key authenticated upload for other servers
  and scripts (see below).

The authoritative request and response shapes, status codes, auth transport,
and data model live in [CONTRACT.md](CONTRACT.md).

### Programmatic uploads (API keys)

Other servers and scripts can upload without a browser session using an API key.
Create and manage keys in the admin panel under **API keys**: each key is a
bearer token of the form `rsk_<id>_<secret>` shown in full exactly once at
creation (only a SHA-256 hash is stored, so it cannot be recovered - revoke and
reissue if lost). Keys can be given an expiry, revoked (and later reinstated), or
deleted, and the panel tracks each key's share count, bytes uploaded, and last use.
A built-in **API docs** page in the panel lists every endpoint with copy-ready
examples and the instance's current limits.

Each key can be scoped below the instance limits: per-file and per-share byte
caps, a lifetime cap on how many shares it may create, a maximum share lifetime
(forcing its shares to expire within a window), and toggles for whether it may set
custom slugs or share passwords. A request that exceeds a cap or uses a disallowed
scope is rejected (`413` for size, `403` for scope/limit).

Authenticate with `Authorization: Bearer rsk_...` (or the `X-Api-Key` header).
Two flows:

- **One-shot** - send a file in a single request and get back a finished share URL:

  ```sh
  curl -X POST "https://share.example.com/api/v1/upload?title=Report" \
    -H "Authorization: Bearer rsk_xxx_yyy" \
    -H "X-Filename: report.pdf" \
    --data-binary @report.pdf
  # -> { "id": "...", "url": "https://share.example.com/...", "fileId": "...", "size": 12345 }
  ```

  Options are query params: `title`, `slug`, `password`, `expiresIn` (seconds,
  `0`=never), `maxDownloads`, `oneTime`, `mime`. One-shot is bounded by the
  server's max request body size.

- **Resumable** - for large files, create a share then drive the standard chunked
  endpoints:

  ```sh
  curl -X POST "https://share.example.com/api/v1/shares" \
    -H "Authorization: Bearer rsk_xxx_yyy" \
    -H "Content-Type: application/json" \
    -d '{"title":"Big upload"}'
  # -> { "id", "editToken", "url", "chunkSize", "maxFileSize", "maxShareSize" }
  ```

  Then register each file (`POST /api/shares/:id/files`), PATCH chunks, and
  `POST /api/shares/:id/finalize` using the returned `editToken` as the
  `X-Edit-Token` header (the same flow the web uploader uses).

`GET /api/v1/me` returns the calling key's metadata - a quick way to verify a key
works. All the usual per-file, per-share, and total storage caps apply.

**Backups.** A key can manage and restore the shares it created, which is enough to
drive an external backup system end to end:

- `GET /api/v1/shares` lists the key's shares (paginated) and `GET /api/v1/shares/:id`
  returns each file with a ready-to-use download URL.
- Retrieval uses the existing `GET /api/shares/:id/files/:fileId/download` - the
  owning key authorizes it (`Authorization: Bearer rsk_...`), so a private backup
  needs no per-share password. Downloads are range-aware for resumable restores.
- `DELETE /api/v1/shares/:id` removes an old backup (rotation).

Create backup shares with `expiresIn=0` (never expire) and manage retention
yourself with `DELETE` - otherwise a share takes the server's default expiry and
is swept. Do not set a max share lifetime on a backup key, since that would
force-expire its shares. The owner's own restores never count against a share's
download cap or burn a one-time share, so caps/one-time set for recipients do not
get in the way of your own restores. The admin panel's **API keys** tab shows each
key's shares, usage, and a filtered view of everything it created; the **API docs**
page includes a full backup workflow example (push, list, restore, rotate).

Key holders can also sign in at **`/api`** with the key name and token to list,
download, and delete that key's shares from the browser - no admin access needed.
