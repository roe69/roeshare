# Example: CI-driven deploys with GitHub Actions

> This is one optional way to automate deploys; see [README.md](README.md) for
> all the manual/Docker/reverse-proxy setup methods. Nothing here is required
> to run RoeShare - it's a starting point if you want pushes to `main` to
> redeploy automatically.

Pushes to `main` first run `.github/workflows/publish.yml`, which builds the
image once and pushes it to `roe69/roeshare:latest` on Docker Hub. When that
succeeds, `.github/workflows/deploy.yml` runs on a **self-hosted runner on
the target server**, pulls the freshly published image, and swaps the
container onto it - the server never builds anything and runs the exact image
users get. The server itself holds no config at all: instance settings (port,
domains) live in the tracked [`deploy/production.yml`](deploy/production.yml)
overlay, and the secret values are GitHub **repository secrets** injected as
environment variables at deploy time, interpolated into the overlay by
Compose. Nothing is written to disk on the host.

## One-time setup

1. **Docker Engine + Compose v2 plugin** on the server - `docker compose
   version` must work for the runner's user (add it to the `docker` group, or
   run the runner as a user that can reach the Docker socket).

2. **A registered self-hosted runner** for `YOUR-ORG/YOUR-REPO`
   (*Settings → Actions → Runners → New self-hosted runner*), installed as a
   service so it survives reboots. To pin deploys to this specific box, give the
   runner an extra label (e.g. `roeshare`) and change the workflow's
   `runs-on: [self-hosted]` to `runs-on: [self-hosted, roeshare]`.

3. **Repository secrets** (*Settings → Secrets and variables → Actions*):

   | Secret               | Value                                                        |
   | -------------------- | ------------------------------------------------------------ |
   | `DOCKERHUB_USERNAME` | Docker Hub account the publish workflow pushes as.           |
   | `DOCKERHUB_TOKEN`    | Docker Hub access token (read & write scope).                |
   | `BASE_URL`           | Public URL(s), comma-separated; first entry is canonical.    |
   | `ADMIN_PASSWORD`     | Admin panel login.                                           |
   | `SECRET`             | `openssl rand -hex 32` - signs tokens, derives the at-rest encryption key. |
   | `UPLOAD_PASSWORD`    | Optional; unset/empty = open uploads.                        |

   > **Back up `SECRET` somewhere outside GitHub too.** It derives the at-rest
   > encryption key - lose it and every uploaded file becomes unrecoverable
   > (GitHub secrets cannot be read back out).

4. **Instance config** - edit [`deploy/production.yml`](deploy/production.yml)
   for the published host port (`!override` replaces the base mapping; prefix
   it with `127.0.0.1:` if your reverse proxy runs directly on the host, so
   nothing else can reach the app).

The first push publishes the image and starts it on the server
(or run the two workflows manually via *Run workflow*, publish first).

## Reverse proxy

`TRUST_PROXY=1` requires a proxy in front that forwards the real host. One server
block per domain (or both in one), each forwarding `Host` and `X-Forwarded-Proto`
to the host port published in `deploy/production.yml`. Caddy example:

```
share.example.com, files.example.com {
    reverse_proxy 127.0.0.1:6968
}
```

For nginx, a full example, and the optional sendfile byte-offload setup, see
the "HTTPS (reverse proxy)" section in [README.md](README.md) and
[`deploy/nginx.example.conf`](deploy/nginx.example.conf) /
[`deploy/Caddyfile.example`](deploy/Caddyfile.example).

## Resetting the database (schema changes)

RoeShare has no migration code - `src/db.js` declares the full schema and a
fresh data directory gets it in one pass. There is no in-place upgrade, so a
**schema change requires starting from an empty database**. Two ways to do it:

- **From the Actions UI (no SSH):** run the **Deploy RoeShare** workflow manually
  (*Actions -> Deploy RoeShare -> Run workflow*) with **"Wipe the data volume"**
  checked. It runs `docker compose down -v` before `up`, so the container comes
  back on an empty db with the current schema. This deletes all shares, uploads,
  and stats.
- **On the host:** `docker rm -f roeshare && docker volume rm roeshare_roeshare-data`,
  then re-run the deploy.

A normal push deploy never resets - it reuses the volume (below).

## How redeploys stay safe and fast

- **Data persists** in the named volume `roeshare_roeshare-data`. A deploy
  recreates only the container; uploads and the SQLite db are untouched.
- **Fast and light**: the image is built once on GitHub's runners; the server
  only pulls it and restarts. `concurrency` cancels superseded deploys, and
  the previous image is pruned after the swap.
- **Deterministic**: `COMPOSE_PROJECT_NAME=roeshare` fixes the container and
  volume names regardless of which runner or checkout path runs the job, so you
  can swap the runner to a fresh box and redeploy with no renaming surprises.

> **Swapping to a different server.** The named volume is local to each Docker
> engine, so a brand-new box starts empty. To carry data across boxes, either
> back up/restore the volume (`docker run --rm -v roeshare_roeshare-data:/d -v
> "$PWD":/b alpine tar czf /b/roeshare-data.tgz -C /d .`) or switch the compose
> volume to a bind mount on shared/persistent storage.

> **Secrets in the volume.** If you edit settings via the admin panel, they're
> saved to `settings.env` inside the data volume, and that file can hold
> `SECRET`/passwords (written `0600`). A volume backup therefore may contain your
> master key, so protect/encrypt those backups. Settings changed in the panel
> override the deploy-time environment (repository secrets and
> `deploy/production.yml`) on the next restart; to revert a key, remove it
> from `settings.env` and restart.
