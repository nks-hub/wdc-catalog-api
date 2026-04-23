[![CI](https://github.com/nks-hub/wdc-catalog-api/actions/workflows/ci.yml/badge.svg)](https://github.com/nks-hub/wdc-catalog-api/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/nks-hub/wdc-catalog-api?label=release)](https://github.com/nks-hub/wdc-catalog-api/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.11-3776AB.svg)](https://python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-2496ED)](https://github.com/nks-hub/wdc-catalog-api/pkgs/container/wdc-catalog-api)

# NKS WDC Catalog API

Cloud-hosted binary catalog + per-device config sync for [NKS WebDev Console](https://github.com/nks-hub/webdev-console). The C# daemon pulls release metadata (Apache, PHP, MySQL, Redis, Caddy, cloudflared, …) from this service and backs up local site/service configuration so a fresh install hydrates from the last known good snapshot.

## Features

- ✅ **Public JSON catalog** — `/api/v1/catalog` served in the exact shape `CatalogClient.cs` expects; drop in a URL and the daemon refreshes on startup
- ✅ **Full HTML admin panel** — dashboard, user management (role + suspend + reset password), audit log + CSV export, invites (mint + redemption history), device browser, snapshot history with RFC 6902 diff, backup import / ZIP export, retention policy, global settings, revoked-token viewer
- ✅ **RBAC with six roles** — owner → admin → operator → support → user → readonly; account-level login lockout after 5 failed attempts
- ✅ **Envelope-encrypted snapshots** — AES-256-GCM with optional Variant B (passphrase-derived KEK for zero-knowledge mode)
- ✅ **URL auto-generators** — one-click scraping of upstream release listings (GitHub Releases API, php.net, apachelounge, nginx.org) with HEAD-probe verification before insertion
- ✅ **Config sync** — per-device JSON upload/download keyed by device ID for seamless re-install
- ✅ **Observability** — `/healthz` (liveness), `/readyz` (DB + S3 deps), `/metrics` (Prometheus; optionally bearer-authed); structured JSON logs via `python-json-logger` with `X-Request-ID` round-trip
- ✅ **OpenAPI 3.1** — auto-generated spec at `/openapi.json`; drift checker (`scripts/check-catalog-drift.mjs`) validates `CatalogClient.cs` against the published contract
- ✅ **SQLite by default** — swappable to Postgres via `DATABASE_URL`
- ✅ **Docker-ready** — published to GHCR on every tag (`ghcr.io/nks-hub/wdc-catalog-api:latest`)

## Requirements

- Python 3.11 or higher (tested on 3.11 and 3.12)
- SQLite 3.35+ (included with Python) — or PostgreSQL 14+ for production
- Docker 24+ (optional, for containerised deployment)

## Installation

### Local development

```cmd
run.cmd
```

Creates a venv in `.venv/`, installs dependencies, and starts uvicorn on `http://127.0.0.1:8765` with hot-reload. First run bootstraps an `admin` / `admin` account (dev mode — env var `NKS_WDC_CATALOG_DEV=1` is set by the script).

POSIX / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
NKS_WDC_CATALOG_DEV=1 uvicorn app.main:app --host 127.0.0.1 --port 8765
```

### Docker

```bash
docker compose up -d
```

Service listens on `http://localhost:8765`. Catalog data mounts from `./app/data/apps` so you can edit JSONs and `POST /api/v1/catalog/reload` without rebuilding.

Pre-built images are published to GHCR on every tag: `ghcr.io/nks-hub/wdc-catalog-api:latest`.

## Configuration

### Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///state/catalog.db` | SQLAlchemy connection string |
| `NKS_WDC_CATALOG_STATE_DIR` | `./state` | Where SQLite + uploads live |
| `NKS_WDC_CATALOG_ADMIN_USER` | `admin` | Bootstrap admin username |
| `NKS_WDC_CATALOG_ADMIN_PASS` | _required in prod_ | Bootstrap admin password (dev fallback: `admin`) |
| `NKS_WDC_CATALOG_DEV` | — | `1` enables `admin`/`admin` fallback + verbose logs + ephemeral keys |
| `NKS_WDC_JWT_SECRET` | _required in prod_ | HS256 signing key for desktop-client JWTs |
| `NKS_WDC_SESSION_SECRET` | _required in prod_ | `itsdangerous` signer key for admin UI session cookies |
| `NKS_WDC_CATALOG_SECRET` | — | Legacy combined secret, fallback for both dedicated vars (deprecated) |
| `NKS_WDC_CATALOG_ALLOW_CORS` | — | `1` emits permissive CORS headers |

In production **the secret env vars must be set** to independent random 32+ byte values (`openssl rand -base64 48`). The service refuses to start otherwise. Setting `NKS_WDC_CATALOG_DEV=1` overrides the check and generates ephemeral random keys — local development only.

### Pointing NKS WDC at this service

In NKS WebDev Console → **Settings → Advanced**:

- **Catalog URL**: `http://127.0.0.1:8765` (local) or `https://wdc.nks-hub.cz` (public NKS instance)

Or via env var when launching the daemon:

```
NKS_WDC_CATALOG_URL=http://127.0.0.1:8765
```

The daemon's `CatalogClient` fetches `/api/v1/catalog` on startup and caches the full release list in memory for the session. Use `POST /api/binaries/catalog/refresh` (authenticated) to pull a newer version without restarting the daemon.

## API

### Catalog (public)

```
GET  /healthz
GET  /readyz
GET  /metrics
GET  /api/v1/catalog
GET  /api/v1/catalog/{app_name}
GET  /api/v1/plugins/catalog
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
GET  /login                              POST /login                     POST /logout

# Overview
GET  /admin                              dashboard (live counters)

# Catalog
GET  /admin/catalog                      apps list
GET  /admin/new                          new-app form
GET  /admin/apps/{app_id}                app + releases
POST /admin/apps/{app_id}/edit           POST /admin/apps/{app_id}/delete
POST /admin/apps/{app_id}/releases       add release (manual)
POST /admin/apps/{app_id}/auto-generate  scrape upstream + insert
POST /admin/releases/{id}/delete
POST /admin/releases/{id}/downloads      add download URL
POST /admin/downloads/{id}/delete

# Users + auth
GET  /admin/users[?q=…&role=…]           filterable list
GET  /admin/users/{id}                   detail
POST /admin/users/{id}/role              change role (+ token version bump)
POST /admin/users/{id}/suspend           POST /admin/users/{id}/resume
POST /admin/users/{id}/reset-password    renders new password once
POST /admin/users/{id}/revoke-tokens     POST /admin/users/{id}/delete

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
POST /admin/devices/{id}/import

# Operations
GET  /admin/audit                        filterable log
GET  /admin/audit.csv                    CSV export (same filters)
GET  /admin/revoked-tokens               JWT denylist
GET  /admin/retention                    policy editor
POST /admin/retention/policy             POST /admin/retention/run-now
GET  /admin/settings                     GlobalPolicy editor
POST /admin/settings
GET  /admin/account                      self-service page
POST /admin/account/password
```

## Supported auto-generators

| App         | Source                                              |
| ----------- | --------------------------------------------------- |
| cloudflared | `github.com/cloudflare/cloudflared` releases        |
| mailpit     | `github.com/axllent/mailpit` releases               |
| caddy       | `github.com/caddyserver/caddy` releases             |
| redis       | `github.com/redis-windows/redis-windows` releases   |
| php         | `windows.php.net/downloads/releases/` HTML listing  |
| apache      | `www.apachelounge.com/download/` HTML listing       |
| nginx       | `nginx.org/en/download.html` HTML listing           |
| mariadb     | `archive.mariadb.org/` open-directory listing + `nks-hub/webdev-console-binaries` macOS probe |
| mysql       | `dev.mysql.com/downloads/mysql/` + `nks-hub/webdev-console-binaries` macOS probe |

## Development

### Tests

```bash
pytest                    # 550+ tests, coverage 85%+
pytest --cov=app          # with coverage report
ruff format app/ tests/   # format
ruff check app/ tests/    # lint
```

CI runs `pytest + ruff + postgres compatibility` on every push.

### Production deployment

1. Set `NKS_WDC_CATALOG_ADMIN_PASS`, `NKS_WDC_JWT_SECRET`, `NKS_WDC_SESSION_SECRET` to independent 32+ byte random values
2. Run behind a TLS-terminating reverse proxy (Caddy, Traefik, nginx)
3. Mount `/state` as a persistent volume so SQLite DB + config snapshots survive container restarts
4. Restrict `/api/v1/sync/config*` behind an API key or Cloudflare Access header unless you want every device on the internet to write to your store
5. Scrape `/metrics` into Prometheus; ingest JSON logs with correlation IDs via your log aggregator

## Contributing

Contributions are welcome! For major changes please open an issue first.

1. Fork the repository
2. Create your feature branch (`git checkout -b feat/amazing-feature`)
3. Keep `pytest` + `ruff check` + `ruff format --check` green
4. Commit your changes — one-line conventional commit messages, no AI attribution
5. Open a Pull Request

## Support

- 📧 **Email:** dev@nks-hub.cz
- 🐛 **Bug reports:** [GitHub Issues](https://github.com/nks-hub/wdc-catalog-api/issues)
- 🔗 **Main project:** [nks-hub/webdev-console](https://github.com/nks-hub/webdev-console)

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/nks-hub">NKS Hub</a>
</p>
