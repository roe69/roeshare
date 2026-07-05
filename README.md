# RoeShare

RoeShare is a secure, self-hosted file-sharing server: drag a file in, get an
opaque share link, and control exactly who can fetch it and for how long.
It runs on the Bun runtime with no build
step and no extra dependencies, storing its state in a single SQLite database
and plain (or encrypted) blobs on disk.

The name "RoeShare", its colours, and its icons are just the upstream
defaults - all of it is meant to be changed.

## Documentation

- **This README** - features, [setup](#setup) for every method, [configuration](#configuration), [security](#security-notes).
- [CUSTOMIZING.md](CUSTOMIZING.md) - rename, recolour, and re-icon it as your own.
- [CONTRACT.md](CONTRACT.md) - the full HTTP API: request/response shapes, status codes, data model.
- [DEPLOY.md](DEPLOY.md) - optional GitHub Actions CI example for automated deploys.
- [`deploy/nginx.example.conf`](deploy/nginx.example.conf) / [`deploy/Caddyfile.example`](deploy/Caddyfile.example) - ready-to-adapt reverse-proxy configs.

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

## Setup

The recommended way to run RoeShare is the prebuilt Docker image - no cloning
required. Pick the guide that matches what you need:

- [Quick start (Docker)](#quick-start-docker) - recommended, uses the
  prebuilt image.
- [Run from source](#run-from-source) - clone the repo to build the Docker
  image yourself, run on plain Bun, install as a systemd service, or compile
  a standalone binary.
- [Behind a reverse proxy (TLS)](#behind-a-reverse-proxy-tls) - add HTTPS in
  front of any of the above.

### Quick start (Docker)

No cloning, no building. Create a `docker-compose.yml` anywhere with:

```yaml
services:
  roeshare:
    image: roe69/roeshare:latest
    container_name: roeshare
    restart: unless-stopped
    ports:
      - "3300:3300"
    environment:
      ADMIN_PASSWORD: change-me # admin panel login - change this
      SECRET: "" # generate with `openssl rand -hex 32` - back it up!
      BASE_URL: http://localhost:3300 # public URL used in share links
    volumes:
      - roeshare-data:/data

volumes:
  roeshare-data:
```

Change `ADMIN_PASSWORD` and fill in `SECRET` (generate one with
`openssl rand -hex 32`), then start it:

```sh
docker compose up -d
```

Open http://localhost:3300 - that's it. The admin panel is at `/admin`.

**Back up `SECRET`.** It derives the at-rest encryption key - losing it makes
encrypted uploads unrecoverable. Every other setting in the
[Configuration](#configuration) table below can be added the same way, under
`environment:`.

Secrets directly in the yaml are fine for a file that stays private to the
server. If you keep your compose file in version control or share it, move
them to a `.env` file next to it instead:

```yaml
    env_file:
      - .env
    environment:
      BASE_URL: http://localhost:3300
```

with `.env` holding plain `KEY=value` lines (`ADMIN_PASSWORD=hunter2`,
`SECRET=...`). Move those keys **out** of `environment:` when you do this -
values under `environment:` always win over `env_file`, so a leftover
`ADMIN_PASSWORD: change-me` there would silently override your `.env`.

The image is ~150 MB (Bun on Alpine, zero npm dependencies), works on amd64
and arm64, exposes `/health` for the container healthcheck, and persists the
database and uploads in the `roeshare-data` named volume. (`roeshare` is just
the container/volume name above - rename it to whatever you'd like.)

Don't use Compose? Run the same image directly:

```sh
docker run -d --name roeshare -p 3300:3300 -v roeshare-data:/data \
  -e ADMIN_PASSWORD=hunter2 -e SECRET=$(openssl rand -hex 32) \
  roe69/roeshare:latest
```

Data (the SQLite db and uploaded blobs) persists in the `roeshare-data` named
volume across container recreation either way. (`--env-file some.env` also
works, if you'd rather maintain your own `KEY=value` file than pass `-e`
flags.)

### Run from source

Only needed to build the image yourself, run on bare Bun, or work on the
source. Start by cloning the repo:

```sh
git clone https://github.com/roe69/roeshare.git
cd roeshare
```

#### Docker

The repo's own `docker-compose.yml` builds the image locally instead of
pulling it. From the cloned repo:

1. Open `docker-compose.yml` in an editor and, under `environment:`, replace
   the `ADMIN_PASSWORD` value with a password of your choice and the empty
   `SECRET` value with a fresh random one. Generate it with:

   ```sh
   openssl rand -hex 32
   ```

2. Build and start it:

   ```sh
   docker compose up -d --build
   ```

3. Open http://localhost:3300 (admin panel at `/admin`, using the password
   you set above).

Day-to-day commands:

```sh
docker compose up -d --build      # start (or apply config/source changes)
docker compose logs -f            # logs
docker compose down               # stop
```

Prefer to keep secrets out of the tracked `docker-compose.yml`? Put just the
keys you're changing in a `docker-compose.override.yml` next to it (gitignored);
Compose merges it in automatically:

```yaml
services:
  roeshare:
    environment:
      ADMIN_PASSWORD: hunter2
      SECRET: <output of `openssl rand -hex 32`>
```

To also publish a different host port from the override, add `ports:
!override ["8080:3300"]` under the service there - the `!override` tag
replaces the base port mapping instead of merging into it (needs Compose
v2.24+).

#### Run with Bun directly (no Docker)

From the cloned repo directory:

1. Install Bun (>= 1.1). See https://bun.sh for instructions.
2. Set at least `ADMIN_PASSWORD` (unlocks the admin panel) and `SECRET` (signs
   cookies and access tokens) as environment variables. Generate a secret
   with:

   ```sh
   bun -e "console.log(crypto.randomUUID()+crypto.randomUUID())"
   ```

3. Start the server with the variables set, e.g.:

   ```sh
   ADMIN_PASSWORD=hunter2 SECRET=<hex from above> bun run src/server.js
   ```

   (or `export` them first, then just run `bun run src/server.js`). Bun also
   auto-loads a `.env` file (plain `KEY=value` lines) from the working
   directory if you'd rather keep them in a file you write yourself.

The server listens on `http://0.0.0.0:3300` by default. Open it in a browser
to upload, visit `/s/:id` for a share, and `/admin` for the admin panel. The
data directory (SQLite db plus uploaded blobs) is created automatically.

##### Running as a systemd service

To keep it running and restart it automatically, install it as a service with
a unit like:

```ini
[Unit]
Description=RoeShare
After=network.target

[Service]
WorkingDirectory=/opt/roeshare
ExecStart=/usr/local/bin/bun run src/server.js
Environment=ADMIN_PASSWORD=hunter2
Environment=SECRET=change-this-to-a-real-secret
Restart=always

[Install]
WantedBy=multi-user.target
```

(`/opt/roeshare` is just an example install path - use whatever directory you
deployed the source to; the two `Environment=` values are placeholders, set
your own. `EnvironmentFile=/opt/roeshare/.env` still works too, if you'd
rather maintain a hand-written `KEY=value` file there.) Use `Restart=always`
(not `on-failure`): the admin panel's **Restart** button exits the process
cleanly (exit 0), so only `always` relaunches it. The Docker
`docker-compose.yml` already uses `restart: unless-stopped`, which behaves
the same way.

#### Single compiled binary

Bun can compile RoeShare into a standalone executable that bundles the runtime:

```sh
bun build --compile src/server.js --outfile roeshare
```

Ship the resulting `roeshare` binary alongside the `public/` directory, with
the env vars set (or a hand-written `.env` next to it, which Bun auto-loads),
then run `./roeshare`. This is handy for environments where you'd rather ship
one file than install Bun or Docker.

### Behind a reverse proxy (TLS)

RoeShare speaks plain HTTP; for a public deployment, terminate TLS at a
reverse proxy (nginx, Caddy, or similar) in front of it and set
`TRUST_PROXY=1` so RoeShare trusts the proxy's forwarded client IP and
protocol for rate limiting, audit logging, and marking the admin cookie
`Secure`. Without a trusted proxy in front, leave `TRUST_PROXY=0` (the
default) - otherwise a direct client could spoof its IP and defeat rate
limits.

**nginx** - minimal example (forward whatever host port you published; 3300 by default):

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

**No reverse proxy yet?** If you run RoeShare with Compose, add Caddy as a
second service in the same compose file for automatic HTTPS:

```yaml
  caddy:
    image: caddy:2
    restart: unless-stopped
    command: caddy reverse-proxy --from share.example.com --to roeshare:3300
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - caddy-data:/data # certificates persist here
```

Add `caddy-data:` under `volumes:`, set `TRUST_PROXY: "1"` and
`BASE_URL: https://share.example.com` on the `roeshare` service, and remove
its `ports:` mapping so only Caddy is reachable from outside.

#### Optional: sendfile byte offload

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
| `ADMIN_PASSWORD` | (empty)                  | Admin panel password. Required for admin access; if unset, admin is locked. |
| `SECRET`         | (ephemeral)              | Secret used to sign cookies and access tokens. Required in production.       |
| `TRUST_PROXY`    | `0`                      | Honor X-Forwarded-For/X-Real-IP for client IP. On ONLY behind a trusted proxy; off when exposed directly (else IPs are spoofable). |
| `DATA_DIR`       | `./data`                 | Directory holding the SQLite db and uploaded blobs.                         |
| `MAX_FILE_SIZE`  | `5368709120` (5 GiB)     | Max size of a single file, in bytes.                                        |
| `MAX_SHARE_SIZE` | `10737418240` (10 GiB)   | Max total size of one share, in bytes.                                      |
| `MAX_TOTAL_SIZE` | `0`                      | Total storage cap across all shares, in bytes. 0 = unlimited.              |
| `CHUNK_SIZE`     | `8388608` (8 MiB)        | Upload chunk size advertised to clients, in bytes.                         |
| `MAX_FILES_PER_SHARE` | `10000`             | Max number of files in a single share.                                      |
| `MAX_PASSWORD_LENGTH` | `1024`              | Max length of a share/upload password, in characters (bounds argon2 cost).  |
| `UPLOAD_PASSWORD`| (empty)                  | Require a password to create shares. Empty = open uploads.                  |
| `DEFAULT_EXPIRY` | `604800` (7 days)        | Default expiry for new shares, in seconds. 0 = never.                       |
| `DEFAULT_E2E`    | `1` (true)               | Whether new shares default to end-to-end encryption in the upload UI. 0 = default to server-managed shares. |
| `ENCRYPT_AT_REST`| `1` (true)               | Whether server-managed (non-E2E) blobs are AES-256-CTR encrypted at rest. 0 = store them as plaintext (no server crypto, lighter to serve). E2E shares are unaffected either way. |
| `THEME_PRIMARY`  | (empty)                  | Hex colour (e.g. `#3b82f6`) to recolour the UI's primary/button accent. No CSS edit needed. See [CUSTOMIZING.md](CUSTOMIZING.md). |
| `THEME_ACCENT`   | (empty)                  | Hex colour (e.g. `#22c55e`) to recolour links/highlights. No CSS edit needed. See [CUSTOMIZING.md](CUSTOMIZING.md). |
| `X_ACCEL_REDIRECT`| (empty)                 | nginx internal `location` prefix for sendfile byte offload (advanced, optional). See [Behind a reverse proxy](#behind-a-reverse-proxy-tls). |
| `X_SENDFILE`     | `0`                      | Set to `1` to use the Apache/Lighttpd `X-Sendfile` header for byte offload (advanced, optional). See [Behind a reverse proxy](#behind-a-reverse-proxy-tls). |
| `ABANDONED_UPLOAD_TTL` | `86400` (24 hours) | How long an upload that was never finalized is kept before the background sweep deletes it, in seconds. |
| `SWEEP_INTERVAL` | `3600` (1 hour)          | How often the background sweep deletes expired shares' files from disk, in seconds. Expiry itself is enforced at access time — an expired share stops being served the moment it expires, regardless of this interval. |

If `SECRET` is unset, RoeShare generates an ephemeral key and warns at startup;
all sessions and access tokens reset on restart, so set a stable secret in
production.

### App-managed settings (admin panel)

The admin panel has a **Server** section that can edit most of the settings
above, copy a quick-access upload link, restart the server, and view recent
logs. Panel edits are saved to `${DATA_DIR}/settings.env` (inside the data
volume) and **applied on the next restart** — they are not live. A few things to
know:

- **They override the environment.** At boot, the managed file is layered over
  whatever you set in `docker-compose.yml` (or the host env) for its keys, so a
  value set once in the panel wins over the compose file forever. To hand a key
  back to the environment, remove it from `settings.env` (or use the editor's
  Clear control where available) and restart. `HOST`, `PORT`, and `DATA_DIR`
  are intentionally **not** editable (they're pinned by the container/compose).
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
- **Health**: `GET /health` returns `{ ok, uptime }` for load balancers and the
  container healthcheck.
- **Reverse-proxy sendfile offload**: see
  [Behind a reverse proxy](#behind-a-reverse-proxy-tls) for `X_ACCEL_REDIRECT` /
  `X_SENDFILE`, which let nginx/Apache serve eligible blobs directly instead of
  streaming them through the app.

## Security notes

- **Encryption at rest.** Server-managed blobs are stored as AES-256-CTR
  ciphertext keyed from `SECRET`, decrypted only in memory for an authorized
  request (CTR keeps downloads seekable). **Back up `SECRET`** - without it the
  files are unrecoverable.
  - The "raw disk / backup access can't read the files" guarantee holds when
    `SECRET` comes from the environment (the compose file or host env), kept
    outside the data volume. If
    you set or rotate `SECRET` via the admin panel it is written to
    `${DATA_DIR}/settings.env` inside the volume, next to the ciphertext - so
    protect and encrypt volume backups (see
    [App-managed settings](#app-managed-settings-admin-panel)).
  - CTR gives confidentiality, not integrity - it won't detect tampering. The
    authorization boundary is the app's access control and unguessable ids, not
    the ciphertext itself.
  - Set `ENCRYPT_AT_REST=0` to store server-managed blobs as plaintext (lighter
    for high-concurrency video). End-to-end shares are always client-encrypted
    regardless, and existing files keep decrypting via their own stored IV.
- End-to-end encryption: E2E shares are encrypted in the browser; the key lives
  only in the link `#fragment` and never reaches the server, which stores and
  serves ciphertext it cannot read. New shares default to E2E (`DEFAULT_E2E`).
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
Create keys in the admin panel under **API keys**: each is a bearer token
`rsk_<id>_<secret>`, shown in full once at creation (only a SHA-256 hash is
stored). Keys can be scoped below the instance limits - per-file/share byte caps,
a lifetime share cap, a max share lifetime, and slug/password toggles - and
expired, revoked, or deleted; over-cap or out-of-scope requests are rejected
(`413` for size, `403` for scope). The panel's **API docs** page lists every
endpoint with copy-ready examples and the instance's current limits.

Authenticate with `Authorization: Bearer rsk_...` (or `X-Api-Key`). Two upload flows:

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

`GET /api/v1/me` verifies a key. A key can also list, fetch, and delete the
shares it created (`GET`/`DELETE /api/v1/shares[/:id]`, range-aware downloads) -
enough to drive an external backup: push with `expiresIn=0` (and don't set a max
share lifetime on the key, which would force-expire them), and the owner's own
restores never count against a download cap or burn a one-time share. The **API
docs** page has the full backup workflow (push, list, restore, rotate).

Key holders can also sign in at **`/api`** with the key name and token to list,
download, and delete that key's shares from the browser - no admin access needed.
