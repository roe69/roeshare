# Customizing RoeShare

RoeShare ships under that name by default, but every visible piece of branding
- the wordmark, its colours, the UI accent, and the icons - is designed to be
replaced without editing any code or CSS. This guide covers all of it.

## 1. App name & wordmark colours (`APP_NAME`)

The name shown in the sidebar, page titles, and browser tab comes from the
`APP_NAME` environment variable. It is plain text with a small set of
OSRS-style tags for inline colour and bold:

- `<col=RRGGBB>` colours the text that follows, until the next `<col>` or
  `</col>`.
- `<b>...</b>` bolds the wrapped text.

Tags can be combined and nested to colour different parts of the name
independently. Examples:

```sh
# Default: cream "Roe" + bold orange "Share"
APP_NAME=<col=e4e4ce>Roe<b><col=ff6b35>Share</b>

# Your own two-tone name, blue + bold green
APP_NAME=<col=5b9dff>Acme<b><col=34d27b>Drop</b>

# Single flat colour, no bold
APP_NAME=<col=ffffff>FileVault

# Plain text, no colour at all
APP_NAME=DropZone
```

Set it in `docker-compose.yml` (or your process manager's environment) and
restart - no CSS edit, no rebuild.

`APP_TITLE` is *not* a separate setting: the plain-text `<title>` used for the
browser tab and the PWA name is derived automatically from `APP_NAME` by
stripping its tags. So `<col=5b9dff>Acme<b><col=ff6b35>Drop</b>` renders the
coloured wordmark in the UI and shows plain `AcmeDrop` as the page title.

## 2. Accent colours the easy way (`THEME_PRIMARY` / `THEME_ACCENT`)

For a quick recolour of the whole UI without touching CSS, set one or both of:

```sh
THEME_PRIMARY=#3b82f6   # buttons, primary actions
THEME_ACCENT=#22c55e    # links, highlights
```

Both accept a hex colour and are injected as a small `<style>` override on
every page. Leave either blank to keep the default palette.

**Before** (defaults, gold/orange):

```sh
THEME_PRIMARY=
THEME_ACCENT=
```

**After** (blue/green):

```sh
THEME_PRIMARY=#3b82f6
THEME_ACCENT=#22c55e
```

Restart the server after changing either value; there is no build step.

## 3. Deep theming (`public/css/tokens.css`)

`THEME_PRIMARY`/`THEME_ACCENT` only override two semantic tokens. For full
control over the palette - every colour scale, surfaces, text, borders,
shadows, radii, spacing, and motion - edit `public/css/tokens.css` directly.
It is the single source of truth the rest of the stylesheet is built from, and
it is plain CSS custom properties, so there is nothing to compile.

Editing files under `public/` (this one included) requires a **restart** to
take effect - static assets are read once and cached in memory for
performance, they are not watched for changes.

## 4. Favicon, app icons, and PWA name

Replace these files in `public/` with your own artwork (keep the same
filenames and sizes so every reference to them keeps working):

- `favicon.ico`
- `favicon-16x16.png`
- `favicon-32x32.png`

`public/site.webmanifest` (used when the app is installed as a PWA) does not
need editing - its `name` and `short_name` fields are templated from
`APP_TITLE` at request time, so they follow `APP_NAME` automatically. It
references `favicon-32x32.png` as the PWA icon, which you've already replaced
above.

Replacing these files requires running from source (the prebuilt
`roe69/roeshare` image bakes in the default icons) - or bind-mount
your own files over `/app/public/favicon.ico` etc. in the container.

## 5. Public URL / domains (`BASE_URL`)

`BASE_URL` is the public origin used to build share links, QR codes, and
absolute URLs. Set it to wherever you're actually serving the app:

```sh
BASE_URL=https://share.example.com
```

To serve the same instance on more than one domain, comma-separate them; the
first entry is the canonical fallback (used for the startup log and for
requests that arrive on a host that isn't in the list), and links are built
from whichever listed domain the visitor is actually on:

```sh
BASE_URL=https://share.example.com,https://files.example.com
```

Multi-domain serving requires `TRUST_PROXY=1` and a reverse proxy in front
that forwards the `Host` header (and ideally `X-Forwarded-Proto`) - see the
"Behind a reverse proxy" section in [README.md](README.md).
