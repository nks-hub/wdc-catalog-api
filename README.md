# NKS WDC Catalog API

Cloud-hosted binary catalog + per-device config sync for **NKS WebDev
Console**. The C# daemon pulls release metadata (Apache, PHP, MySQL,
Redis, Caddy, cloudflared, …) from this service and backs up local
site/service configuration so a fresh install hydrates from the last
known good snapshot.

## Features

- **Public JSON catalog** — `/api/v1/catalog` served in the exact shape
  `CatalogClient.cs` expects. Drop in a URL and the daemon refreshes
  on startup.
- **Full HTML admin panel** at `/admin` — dashboard, user management
  (role + suspend + reset password), audit log (+ CSV export), invites
  (mint + redemption history), device browser, snapshot history with
  RFC 6902 diff, backup import / ZIP export, retention policy, global
  settings, self-service password change, revoked-token viewer.
- **RBAC** with six roles (owner → admin → operator → support → user →
  readonly) and account-level login lockout after 5 failed attempts.
- **Envelope-encrypted snapshots** with AES-256-GCM + optional Variant
  B (passphrase-derived KEK for zero-knowledge mode).
- **URL auto-generators** — one click scrapes the upstream release
  listing (GitHub Releases API for cloudflared / caddy / mailpit /
  redis-windows, HTML listings for php.net / apachelounge / nginx.org)
  and inserts new releases into SQLite.
- **Config sync** — per-device JSON upload/download keyed by device ID
  for seamless re-install.
- **Observability**: `/healthz` (liveness), `/readyz` (DB + S3 deps),
  `/metrics` (Prometheus; optionally bearer-authed).
- **SQLite by default**, swappable to Postgres via `DATABASE_URL`.
- **Docker-ready** with `Dockerfile` + `docker-compose.yml`; GHCR
  images tagged per release (`v0.4.0`, `latest`).

## Quickstart (local)

```cmd
run.cmd
```

That creates a venv in `.venv/`, installs dependencies, and starts
uvicorn on `http://127.0.0.1:8765` with hot-reload. First run bootstraps
an `admin` / `admin` account (dev mode — env var
`NKS_WDC_CATALOG_DEV=1` is set by the script).

POSIX / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
NKS_WDC_CATALOG_DEV=1 uvicorn app.main:app --host 127.0.0.1 --port 8765
```

## Quickstart (Docker)

```bash
docker compose up -d
```

Service listens on `http://localhost:8765`. Catalog data mounts from
`./app/data/apps` so you can edit JSONs and `POST /api/v1/catalog/reload`
without rebuilding.

Pre-built images are published to GHCR on every tag:
`ghcr.io/nks-hub/wdc-catalog-api:latest`.

## Pointing NKS WDC at this service

In NKS WebDev Console → Settings → Advanced:

- **Catalog URL**: `http://127.0.0.1:8765` (local)
  or `https://wdc.nks-hub.cz` (public NKS instance)

Or via env var when launching the daemon:

```
NKS_WDC_CATALOG_URL=http://127.0.0.1:8765
```

The daemon's `CatalogClient` fetches `/api/v1/catalog` on startup and
caches the full release list in memory for the session. Use
`POST /api/binaries/catalog/refresh` (authenticated) to pull a newer
version without restarting the daemon.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///state/catalog.db` | SQLAlchemy connection string |
| `NKS_WDC_CATALOG_STATE_DIR` | `./state` | Where SQLite + uploads live |
| `NKS_WDC_CATALOG_ADMIN_USER` | `admin` | Bootstrap admin username |
| `NKS_WDC_CATALOG_ADMIN_PASS` | — (dev: `admin`) | Bootstrap admin password |
| `NKS_WDC_CATALOG_DEV` | — | `1` enables `admin`/`admin` fallback + verbose logs |
| `NKS_WDC_JWT_SECRET` | _required in prod_ | HS256 signing key for desktop-client JWTs |
| `NKS_WDC_SESSION_SECRET` | _required in prod_ | `itsdangerous` signer key for admin UI session cookies |
| `NKS_WDC_CATALOG_SECRET` | — | Legacy combined secret, used as fallback for both dedicated vars (deprecated) |
| `NKS_WDC_CATALOG_ALLOW_CORS` | — | `1` emits permissive CORS headers |

In production **the secret env vars must be set** to independent random 32+ byte values
(`openssl rand -base64 48`). The service refuses to start otherwise. Setting
`NKS_WDC_CATALOG_DEV=1` overrides the check and generates ephemeral random keys —
local development only.

## API

### Catalog (public)

```
GET  /healthz
GET  /api/v1/catalog
GET  /api/v1/catalog/{app_name}
```

### Config sync (public, runs behind reverse-proxy auth in prod)

```
POST   /api/v1/sync/config              body: { device_id, payload }
GET    /api/v1/sync/config/{device_id}
GET    /api/v1/sync/config/{device_id}/exists
DELETE /api/v1/sync/config/{device_id}
```

### Admin UI (session cookie auth)

```
GET  /login
POST /login
POST /logout

# Overview
GET  /admin                              dashboard (live counters)

# Catalog
GET  /admin/catalog                      apps list
GET  /admin/new                          new-app form
POST /admin/new
GET  /admin/apps/{app_id}                app + releases
GET  /admin/apps/{app_id}/edit
POST /admin/apps/{app_id}/edit
POST /admin/apps/{app_id}/delete
POST /admin/apps/{app_id}/releases       add release (manual)
POST /admin/apps/{app_id}/auto-generate  scrape upstream + insert
POST /admin/releases/{id}/delete
POST /admin/releases/{id}/downloads      add download URL
POST /admin/downloads/{id}/delete

# Users + auth
GET  /admin/users[?q=…&role=…]           filterable list
GET  /admin/users/{id}                   detail
POST /admin/users/{id}/role              change role (+ token version bump)
POST /admin/users/{id}/suspend
POST /admin/users/{id}/resume
POST /admin/users/{id}/reset-password    renders new password once
POST /admin/users/{id}/revoke-tokens
POST /admin/users/{id}/delete

# Invites
GET  /admin/invites                      mint form
POST /admin/invites
GET  /admin/invites/history              consumed nonces

# Devices + snapshots
GET  /admin/devices                      list scoped to caller's account
GET  /admin/devices/{id}                 metadata + current payload
POST /admin/devices/{id}/delete
GET  /admin/devices/{id}/snapshots       browser w/ kind + label filter
GET  /admin/devices/{id}/snapshots/{sid} detail + diff vs HEAD
POST /admin/devices/{id}/snapshots/{sid}/restore
GET  /admin/devices/{id}/snapshots/export.zip
GET  /admin/devices/{id}/import          paste JSON envelope
POST /admin/devices/{id}/import

# Operations
GET  /admin/audit                        filterable log
GET  /admin/audit.csv                    CSV export (same filters)
GET  /admin/revoked-tokens               JWT denylist
GET  /admin/retention                    policy editor
POST /admin/retention/policy
POST /admin/retention/run-now
GET  /admin/settings                     GlobalPolicy editor
POST /admin/settings
GET  /admin/account                      self-service page
POST /admin/account/password
```

## Supported auto-generators

| App | Source |
| --- | --- |
| cloudflared | `github.com/cloudflare/cloudflared` releases |
| mailpit | `github.com/axllent/mailpit` releases |
| caddy | `github.com/caddyserver/caddy` releases |
| redis | `github.com/redis-windows/redis-windows` releases |
| php | `windows.php.net/downloads/releases/` HTML listing |
| apache | `www.apachelounge.com/download/` HTML listing |
| nginx | `nginx.org/en/download.html` HTML listing |

MySQL / MariaDB generators are TODO (their download pages gate by
session cookies so scraping is fragile — for now use the seed JSON
`app/data/apps/{mysql,mariadb}.json` which ships with known versions).

## Deployment

For production:

1. Set `NKS_WDC_CATALOG_ADMIN_PASS` and `NKS_WDC_CATALOG_SECRET` (random 32+ chars).
2. Run behind a TLS-terminating reverse proxy (Caddy, Traefik, nginx).
3. Mount `/state` as a persistent volume so the SQLite DB and config
   snapshots survive container restarts.
4. Restrict `/api/v1/sync/config*` behind an API key / Cloudflare
   Access header unless you want every device on the internet to
   write to your store.
