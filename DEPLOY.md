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

`TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128` (or the back-compat `TRUST_PROXY=1`,
equivalent when unset) requires a proxy in front that forwards the real host.
One server block per domain (or both in one), each forwarding `Host` and
`X-Forwarded-Proto` to the host port published in `deploy/production.yml`.
Caddy example:

```
share.example.com, files.example.com {
    reverse_proxy 127.0.0.1:6968
}
```

For nginx, a full example, and the optional sendfile byte-offload setup, see
the "HTTPS (reverse proxy)" section in [README.md](README.md) and
[`deploy/nginx.example.conf`](deploy/nginx.example.conf) /
[`deploy/Caddyfile.example`](deploy/Caddyfile.example).

### `TRUSTED_PROXY_CIDRS` / `TRUSTED_PROXY_HOPS`: verify, don't assume

`TRUSTED_PROXY_HOPS` (default `1`) is how many of X-Forwarded-For's trailing
entries to skip (a relaying proxy's own appended address) before taking the
real client. `TRUSTED_PROXY_CIDRS` is who's allowed to set that header at
all - checked against the actual TCP socket peer of the request, which a
client can never spoof.

**Don't guess these from the deployment's architecture on paper - verify
against the real request.** Two things can make the socket peer NOT be what
you'd expect from a diagram:

- A **local reverse proxy on the same host** (nginx/Caddy per the examples
  above) normally appends its own peer address via
  `$proxy_add_x_forwarded_for` or equivalent, making the default `HOPS=1`
  correct, with `TRUSTED_PROXY_CIDRS` set to wherever that proxy's own
  connection to the app actually originates from - which, behind Docker's
  published-port NAT, is often the Docker bridge gateway, not literally
  `127.0.0.1`; check `docker network inspect <project>_default`.
- A **CDN/edge network connecting straight to the host's published port**
  (no local reverse proxy) doesn't necessarily mean the app sees the CDN's
  own edge IP as the socket peer, or that X-Forwarded-For has only one entry
  - some cloud providers NAT all inbound traffic onto a private per-VM
  address before Docker ever sees it, and some CDNs (Cloudflare included)
  can present an internal relay address as a second X-Forwarded-For entry
  rather than setting a single one outright. Assuming `HOPS=0` and a
  CDN-published CIDR list here was tried on this project's own production
  instance and was wrong on both counts.

The reliable way to get this right: temporarily add a diagnostic route that
reports `server.requestIP(req)` and the incoming forwarding headers back to
the caller (nothing about any other visitor - just the requester's own
connection), deploy it, hit the public URL once, read the real values, then
remove it. Set `TRUSTED_PROXY_CIDRS` to the exact peer address(es) you
observed and `TRUSTED_PROXY_HOPS` to whatever count actually lands on the
real client in the header you saw.

**Whatever the peer turns out to be, if it's not something an outside
attacker can be excluded from presenting as** (e.g. it's a NAT address shared
by all inbound traffic to the host, not something CDN-specific), trusting it
is only as safe as the host firewall. Restrict the provider firewall/security
group for the published port to the CDN's published IP ranges (for
Cloudflare: https://www.cloudflare.com/ips/ - re-check occasionally, they
change rarely but do change) so a direct hit against the host's real IP is
dropped before it reaches Docker at all - otherwise anyone who finds that IP
can present the same trusted peer address and have a forged
X-Forwarded-For fully believed.

## Schema changes migrate automatically - you never need to reset

`src/db.js` declares the full schema once and migrates an existing database
forward to it on every boot: a new column is added in place automatically,
and anything a plain column-add can't express (a rename, a backfill, a
value-format change) ships as a small named migration that runs exactly
once. Before either kind of migration changes anything, the live database is
snapshotted to `DATA_DIR/backups` (the last few are kept), so a migration bug
is always recoverable from disk. A normal push deploy just reuses the volume
and boots the new image against it - **no manual reset step, no downtime for
a schema change.**

This path (a fresh install, an already-current database, and a simulated
pre-migration one) is covered by `test/migrations.test.js`, which CI runs
before every image is published - a change that would break upgrading an
existing installation fails the build rather than reaching a deploy.

### Resetting the database anyway (a genuine, intentional wipe)

This is for throwing away all data on purpose - not something a schema change
should ever require. Two ways to do it:

- **From the Actions UI (no SSH):** run the **Deploy RoeShare** workflow manually
  (*Actions -> Deploy RoeShare -> Run workflow*) with **"Wipe the data volume"**
  checked. It runs `docker compose down -v` before `up`, so the container comes
  back on an empty db. This deletes all shares, uploads, and stats.
- **On the host:** `docker rm -f roeshare && docker volume rm roeshare_roeshare-data`,
  then re-run the deploy.

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

> **Panel settings never shadow the environment.** Every key this deploy sets
> (`BASE_URL`, `TRUST_PROXY`, and the secrets) is locked in the admin panel -
> the environment always wins, so rotating a secret happens in the GitHub
> repository secrets, never on the box. The panel's `settings.env` (in the
> data volume, written `0600`) only holds panel-set values for keys the
> environment leaves unset, such as the size limits.

## Storage volume isolation

The app creates the storage directory `0700` and every blob file `0600`, and
refuses to follow a symlink planted anywhere under it (see `lib/storage.js`) -
but that only protects against another *unprivileged* process on the same
host. Never share the storage volume (or a bind mount backing it) as
writable with any other process or container: anything that can write into
it can plant a symlink or otherwise race the app's own writes, and ambient
root/host-level access still bypasses the app's own checks entirely. Where
your deployment supports it, mount the volume with `nodev,nosuid,noexec` -
none of `roeshare`'s own writes need device nodes, setuid execution, or to
execute anything from the data volume, so those options cost nothing and
close off a class of post-compromise escalation.
