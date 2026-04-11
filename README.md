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
- **Admin UI** with bcrypt-hashed session login at `/login` → `/admin`.
- **URL auto-generators** — one click scrapes the upstream release
  listing (GitHub Releases API for cloudflared / caddy / mailpit /
  redis-windows, HTML listings for php.net / apachelounge / nginx.org)
  and inserts new releases into SQLite.
- **Config sync** — per-device JSON upload/download keyed by device ID
  for seamless re-install.
- **SQLite by default**, swappable to Postgres via `DATABASE_URL`.
- **Docker-ready** with `Dockerfile` + `docker-compose.yml`.

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
cd services/catalog-api
docker compose up -d
```

Service listens on `http://localhost:8765`. Catalog data mounts from
`./app/data/apps` so you can edit JSONs and `POST /api/v1/catalog/reload`
without rebuilding.

## Pointing NKS WDC at this service

In NKS WebDev Console → Settings → Advanced:

- **Catalog URL**: `http://127.0.0.1:8765` (local)
  or `https://catalog.wdc.nks-hub.cz` (when deployed)

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
| `NKS_WDC_CATALOG_SECRET` | dev fallback | `itsdangerous` signer key for session cookies |
| `NKS_WDC_CATALOG_ALLOW_CORS` | — | `1` emits permissive CORS headers |

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
GET  /admin                              list all apps
GET  /admin/new                          new-app form
POST /admin/new
GET  /admin/apps/{app_id}                app + releases
GET  /admin/apps/{app_id}/edit           edit form
POST /admin/apps/{app_id}/edit
POST /admin/apps/{app_id}/delete
POST /admin/apps/{app_id}/releases       add release (manual)
POST /admin/apps/{app_id}/auto-generate  scrape upstream + insert
POST /admin/releases/{id}/delete
POST /admin/releases/{id}/downloads      add download URL
POST /admin/downloads/{id}/delete
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
