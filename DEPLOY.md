# Example: CI-driven deploys with GitHub Actions

> This is one optional way to automate deploys; see [README.md](README.md) for
> all the manual/Docker/reverse-proxy setup methods. Nothing here is required
> to run RoeShare - it's a starting point if you want pushes to `main` to
> redeploy automatically.

Pushes to `main` trigger `.github/workflows/deploy.yml`, which runs on a
**self-hosted runner on the target server** and rebuilds/restarts the container.
CI never holds secrets: all config lives in a `.env` you place on the host once.

## One-time host setup

The runner box needs three things. Docker + the runner are assumed present; the
only RoeShare-specific step is the config file.

1. **Docker Engine + Compose v2 plugin** — `docker compose version` must work
   for the runner's user (add it to the `docker` group, or run the runner as a
   user that can reach the Docker socket).

2. **A registered self-hosted runner** for `YOUR-ORG/YOUR-REPO`
   (*Settings → Actions → Runners → New self-hosted runner*), installed as a
   service so it survives reboots. To pin deploys to this specific box, give the
   runner an extra label (e.g. `roeshare`) and change the workflow's
   `runs-on: [self-hosted]` to `runs-on: [self-hosted, roeshare]`.

3. **The persisted config** at `/opt/roeshare/.env` (an example path — use
   whatever directory you like, and override it with a repo Variable named
   `ENV_PATH`). Create it once — CI reads it but never generates or overwrites it:

   ```sh
   sudo install -d -m 700 /opt/roeshare
   sudo tee /opt/roeshare/.env >/dev/null <<EOF
   HOST=0.0.0.0
   PORT=3300
   # Multi-domain: comma-separated, first is canonical. Links are built from
   # whichever of these the visitor is on.
   BASE_URL=https://share.example.com,https://files.example.com
   TRUST_PROXY=1
   ADMIN_PASSWORD=$(openssl rand -hex 9)
   UPLOAD_PASSWORD=
   SECRET=$(openssl rand -hex 32)
   EOF
   sudo chmod 600 /opt/roeshare/.env
   ```

   > **Back up `SECRET`.** It derives the at-rest encryption key — lose it and
   > every uploaded file becomes unrecoverable. Note the generated
   > `ADMIN_PASSWORD` too (`sudo grep ADMIN_PASSWORD /opt/roeshare/.env`).

That's it. The first push (or a manual *Run workflow*) builds and starts it.

## Reverse proxy

`TRUST_PROXY=1` requires a proxy in front that forwards the real host. One server
block per domain (or both in one), each forwarding `Host` and `X-Forwarded-Proto`
to the container's published `PORT` (3300). Caddy example:

```
share.example.com, files.example.com {
    reverse_proxy 127.0.0.1:3300
}
```

For nginx, a full example, and the optional sendfile byte-offload setup, see
the "Behind a reverse proxy (TLS)" section in [README.md](README.md) and
[`deploy/nginx.example.conf`](deploy/nginx.example.conf) /
[`deploy/Caddyfile.example`](deploy/Caddyfile.example).

## How redeploys stay safe and fast

- **Data persists** in the named volume `roeshare_roeshare-data`. `up -d --build`
  recreates only the container; uploads and the SQLite db are untouched.
- **Fast**: the Docker layer cache is reused (no `--no-cache`), so an unchanged
  tree rebuilds in seconds; `concurrency` cancels superseded deploys.
- **Deterministic**: `COMPOSE_PROJECT_NAME=roeshare` fixes the container and
  volume names regardless of which runner or checkout path runs the job — so you
  can swap the runner to a fresh box and redeploy with no renaming surprises.

> **Swapping to a *different* server?** The named volume is local to each Docker
> engine, so a brand-new box starts empty. To carry data across boxes, either
> back up/restore the volume (`docker run --rm -v roeshare_roeshare-data:/d -v
> "$PWD":/b alpine tar czf /b/roeshare-data.tgz -C /d .`) or switch the compose
> volume to a bind mount on shared/persistent storage.

> **Secrets in the volume.** If you edit settings via the admin panel, they're
> saved to `settings.env` inside the data volume — and that file can hold
> `SECRET`/passwords (written `0600`). A volume backup therefore may contain your
> master key, so protect/encrypt those backups. Settings changed in the panel
> override `/opt/roeshare/.env` on the next restart; to revert a key to `.env`
> control, remove it from `settings.env` and restart.
