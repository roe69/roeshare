# RoeShare

RoeShare is a secure, self-hosted file-sharing server: drag a file in, get an
opaque share link, and control exactly who can fetch it and for how long.
It runs on the Bun runtime with no build
step and no extra dependencies, storing its state in a single SQLite database
and plain (or encrypted) blobs on disk.

The name "RoeShare", its colours, and its icons are just the upstream
defaults - all of it is meant to be changed. See
[CUSTOMIZING.md](CUSTOMIZING.md) for a full rebranding guide.

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

There is more than one way to run RoeShare. Pick the guide that matches your
setup:

- [Quick start (Docker Compose)](#quick-start-docker-compose) - recommended.
- [Run with plain `docker run`](#run-with-plain-docker-run) - single container, no Compose.
- [Run with Bun directly (no Docker)](#run-with-bun-directly-no-docker) - bare metal or a VM.
- [Single compiled binary](#single-compiled-binary) - one executable, no runtime install.
- [Behind a reverse proxy (TLS)](#behind-a-reverse-proxy-tls) - add HTTPS in front of any of the above.

## Quick start (Docker Compose)

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
exposes `/healthz` for the container healthcheck, and persists the database
and uploads in the `roeshare-data` volume. (`roeshare` is just the default
container/volume/image name from `docker-compose.yml` - rename it there if
you'd like something else.)

## Run with plain `docker run`

If you don't want Compose, build the image once and run it directly:

```sh
docker build -t roeshare .
docker run -d \
  -p 3300:3300 \
  -v roeshare-data:/data \
  --env-file .env \
  --name roeshare \
  roeshare
```

This needs a `.env` file next to where you run the command (copy
`.env.example` and set at least `ADMIN_PASSWORD` and `SECRET` - see
[Configuration](#configuration)). Data (the SQLite db and uploaded blobs)
persists in the `roeshare-data` named volume across container recreation.

## Run with Bun directly (no Docker)

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

The server listens on `http://0.0.0.0:3300` by default. Open it in a browser
to upload, visit `/s/:id` for a share, and `/admin` for the admin panel. The
data directory (SQLite db plus uploaded blobs) is created automatically.

### Running as a systemd service

To keep it running and restart it automatically, install it as a service with
a unit like:

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

(`/opt/roeshare` is just an example install path - use whatever directory you
deployed the source to.) Use `Restart=always` (not `on-failure`): the admin
panel's **Restart** button exits the process cleanly (exit 0), so only
`always` relaunches it. The Docker `docker-compose.yml` already uses
`restart: unless-stopped`, which behaves the same way.

## Single compiled binary

Bun can compile RoeShare into a standalone executable that bundles the runtime:

```sh
bun build --compile src/server.js --outfile roeshare
```

Ship the resulting `roeshare` binary alongside the `public/` directory and
your `.env`, then run `./roeshare`. This is handy for environments where you'd
rather ship one file than install Bun or Docker.

## Behind a reverse proxy (TLS)

RoeShare speaks plain HTTP; for a public deployment, terminate TLS at a
reverse proxy (nginx, Caddy, or similar) in front of it and set
`TRUST_PROXY=1` so RoeShare trusts the proxy's forwarded client IP and
protocol for rate limiting, audit logging, and marking the admin cookie
`Secure`. Without a trusted proxy in front, leave `TRUST_PROXY=0` (the
default) - otherwise a direct client could spoof its IP and defeat rate
limits.

**nginx** - minimal example (forward the app port, whatever you set `PORT` to):

```nginx
server {
    listen 443 ssl;
    server_name share.example.com;

    location / {
        proxy_pass http://127.0.0.1:3300;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 0;
    }
}
```

For the full version - including TLS certificate directives and the
sendfile-offload `location` block described below - see
[`deploy/nginx.example.conf`](deploy/nginx.example.conf).

**Caddy** - minimal example (Caddy handles TLS automatically):

```
share.example.com {
    reverse_proxy 127.0.0.1:3300
}
```

For a version with comments and options, see
[`deploy/Caddyfile.example`](deploy/Caddyfile.example).

### Optional: sendfile byte offload

Two env vars let the reverse proxy serve file bytes itself instead of
streaming them through the Bun process, using the kernel's `sendfile`:

- `X_ACCEL_REDIRECT` - for **nginx**: set it to an internal `location` prefix
  (e.g. `/_roeshare_blobs`), configured to serve blobs straight off disk. See
  `deploy/nginx.example.conf` for the matching `location` block.
- `X_SENDFILE` - for **Apache/Lighttpd**: set to `1` to use the `X-Sendfile`
  response header.

This only applies to files that need no server-side decryption: all
end-to-end encrypted shares, or every file if you've also set
`ENCRYPT_AT_REST=0`. Server-managed encrypted blobs still stream through the
app either way, since only the app holds the key. Caddy has no equivalent -
it streams through the app, which is still lightweight since Caddy itself
doesn't buffer.

This is entirely optional and only matters at very high concurrent
stream counts (e.g. many simultaneous large-video views); leave both unset to
stream everything through the app (the default, and fine for most
deployments).

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
| `DEFAULT_E2E`    | `1` (true)               | Whether new shares default to end-to-end encryption in the upload UI. 0 = default to server-managed shares. |
| `ENCRYPT_AT_REST`| `1` (true)               | Whether server-managed (non-E2E) blobs are AES-256-CTR encrypted at rest. 0 = store them as plaintext (no server crypto, lighter to serve). E2E shares are unaffected either way. |
| `THEME_PRIMARY`  | (empty)                  | Hex colour (e.g. `#3b82f6`) to recolour the UI's primary/button accent. No CSS edit needed. See [CUSTOMIZING.md](CUSTOMIZING.md). |
| `THEME_ACCENT`   | (empty)                  | Hex colour (e.g. `#22c55e`) to recolour links/highlights. No CSS edit needed. See [CUSTOMIZING.md](CUSTOMIZING.md). |
| `X_ACCEL_REDIRECT`| (empty)                 | nginx internal `location` prefix for sendfile byte offload (advanced, optional). See [Behind a reverse proxy](#behind-a-reverse-proxy-tls). |
| `X_SENDFILE`     | `0`                      | Set to `1` to use the Apache/Lighttpd `X-Sendfile` header for byte offload (advanced, optional). See [Behind a reverse proxy](#behind-a-reverse-proxy-tls). |
| `ABANDONED_UPLOAD_TTL` | `172800` (48 hours) | How long an upload that was never finalized is kept before the background sweep deletes it, in seconds. |
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

## Customization

RoeShare is meant to be rebranded. Short version:

- **Name & wordmark colours**: set `APP_NAME`, which carries its own colours
  via `<col=RRGGBB>` and `<b>` tags, e.g.
  `APP_NAME=<col=5b9dff>Acme<b><col=34d27b>Drop</b>`. The plain-text `<title>`
  and PWA name derive from it automatically - no separate setting.
- **Accent colours**: set `THEME_PRIMARY` / `THEME_ACCENT` to a hex colour
  each, no CSS edit required.
- **Icons**: replace `favicon.ico`, `favicon-16x16.png`, and
  `favicon-32x32.png` in `public/`.
- **Public URL**: set `BASE_URL` to your own domain(s).

See [CUSTOMIZING.md](CUSTOMIZING.md) for the full guide, including deep
theming via `public/css/tokens.css`.

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
- **Reverse-proxy sendfile offload**: see
  [Behind a reverse proxy](#behind-a-reverse-proxy-tls) for `X_ACCEL_REDIRECT` /
  `X_SENDFILE`, which let nginx/Apache serve eligible blobs directly instead of
  streaming them through the app.

## Security notes

- Encryption at rest: uploaded blobs are stored as AES-256-CTR ciphertext, keyed
  from `SECRET`, and decrypted only in memory while streaming to an authorized
  request. CTR keeps downloads seekable. Back up `SECRET` - without it the files
  are unrecoverable. (A random-slug share with no password is still reachable by
  anyone who has the link; add a password for confidentiality.) This guarantee -
  that someone with raw disk, volume, or backup access cannot read the files -
  holds when `SECRET` is provided via the host environment or `.env` and kept
  outside the data volume. If `SECRET` is instead set or rotated through the
  admin panel, it is written to `${DATA_DIR}/settings.env` inside the same data
  volume as the ciphertext and the per-file IVs, so anyone who captures a volume
  snapshot or backup can recover `SECRET` and decrypt the blobs; see "App-managed
  settings" above. Encrypt and protect volume backups accordingly. Note also that
  CTR gives confidentiality, not integrity: it does not detect tampering, so
  someone with direct write access to the storage directory could corrupt or
  bit-flip stored ciphertext undetected. The app's access control and unguessable
  ids remain the authorization boundary, not the ciphertext itself. At-rest
  encryption can be disabled with `ENCRYPT_AT_REST=0` for performance (no
  server-side AES on upload/download, useful for large-video workloads with
  many concurrent streams); this only affects new server-managed blobs -
  end-to-end encrypted shares are always encrypted client-side regardless of
  this setting, and existing on-disk files keep decrypting correctly since that
  depends on the file's own stored IV, not this flag.
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
