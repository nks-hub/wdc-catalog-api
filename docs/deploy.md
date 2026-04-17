# Deploy runbook — `wdc.nks-hub.cz`

Operational steps for rolling the public NKS WDC catalog API at
`https://wdc.nks-hub.cz`. The service is Dockerized, stateless apart
from the SQLite volume, and released via `ghcr.io/nks-hub/wdc-catalog-api`.

## Prerequisites

On the production VPS:

- Docker 24+ + docker-compose v2 available to the deploy user.
- `/opt/wdc-catalog-api/` directory owned by the deploy user, containing:
  - `docker-compose.yml` (see below)
  - `.env` with secrets (mode `0600`, never committed)
  - `state/` persistent volume mount for `catalog.db`
- TLS-terminating reverse proxy (Caddy/Traefik/nginx) forwarding
  `wdc.nks-hub.cz` → `127.0.0.1:8765`.
- GHCR login for the deploy account:
  `echo $GHCR_PAT | docker login ghcr.io -u nks-hub --password-stdin`.

## Required environment variables

Generate with `openssl rand -base64 48`:

```env
# /opt/wdc-catalog-api/.env — chmod 0600, owner = deploy user
NKS_WDC_JWT_SECRET=<random 48+ bytes>
NKS_WDC_SESSION_SECRET=<random 48+ bytes, different from JWT>
NKS_WDC_MASTER_KEY=<random 32+ bytes, used for snapshot encryption KEK>
NKS_WDC_CATALOG_ADMIN_USER=admin
NKS_WDC_CATALOG_ADMIN_PASS=<strong random password>
NKS_WDC_CATALOG_AUTO_MIGRATE=1
NKS_WDC_LOG_LEVEL=INFO
```

Never set `NKS_WDC_CATALOG_DEV=1` in production — it unlocks the
`admin` / `admin` bootstrap fallback.

## Production `docker-compose.yml`

```yaml
services:
  catalog-api:
    image: ghcr.io/nks-hub/wdc-catalog-api:${IMAGE_TAG:-latest}
    container_name: nks-wdc-catalog-api
    restart: unless-stopped
    env_file: .env
    ports:
      - "127.0.0.1:8765:8765"
    volumes:
      - ./state:/state
      - /etc/timezone:/etc/timezone:ro
    healthcheck:
      test: ["CMD", "python", "-c",
             "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz').read()"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "10"
```

## Roll forward

1. Pick the target tag (e.g. `v0.2.1`) from GitHub Releases.
2. On the host:
   ```bash
   cd /opt/wdc-catalog-api
   export IMAGE_TAG=v0.2.1
   docker compose pull
   docker compose up -d
   ```
3. Alembic migrations run automatically on startup when
   `NKS_WDC_CATALOG_AUTO_MIGRATE=1` is set. Tail the logs:
   ```bash
   docker compose logs -f --tail=200 catalog-api
   ```
4. Smoke-test from the host:
   ```bash
   curl -fsS https://wdc.nks-hub.cz/healthz | jq .
   curl -fsS https://wdc.nks-hub.cz/api/v1/catalog | jq '.apps | keys'
   ```
5. Run the drift check locally (or let the monorepo CI do it) against
   the tagged release’s `openapi.json`:
   ```bash
   CATALOG_API_VERSION=0.2.1 node scripts/check-catalog-drift.mjs
   ```

## Rollback

The SQLite volume is image-agnostic, so flipping the tag reverts the
application layer without losing data.

```bash
cd /opt/wdc-catalog-api
export IMAGE_TAG=v0.2.0   # previous known-good tag
docker compose pull
docker compose up -d
```

If the Alembic migration introduced by the bad release is incompatible
with the rollback image, run the targeted downgrade first:

```bash
docker run --rm --env-file .env \
  -v $(pwd)/state:/state \
  ghcr.io/nks-hub/wdc-catalog-api:v0.2.1 \
  alembic downgrade -1
```

## Backup

Nightly SQLite snapshot to off-host storage (example with restic):

```bash
docker compose exec catalog-api sqlite3 /state/catalog.db \
  ".backup /state/catalog-$(date +%Y%m%d).bak"
restic -r s3:… backup /opt/wdc-catalog-api/state
```

Schedule via systemd timer or cron on the host; keep 14 days of
snapshots, test a restore quarterly.

## Secret rotation

`NKS_WDC_JWT_SECRET` and `NKS_WDC_SESSION_SECRET`:

1. Generate new random value, append to a new line in `.env` with a
   grace-period name (`NKS_WDC_JWT_SECRET_NEXT`) — *future feature*.
2. Until dual-secret support ships, plan a 30-second cut-over window:
   set the new secret, `docker compose up -d`, existing JWTs become
   invalid at once. Admin users must re-login.
3. `NKS_WDC_MASTER_KEY` rotation is performed by creating a new
   `AccountEncryptionKey` row via the admin API (future endpoint) —
   do **not** simply change the env value or all existing encrypted
   snapshots become unreadable.

## Observability

- JSON logs land on Docker stdout → scrape with Loki / Promtail / CloudWatch.
- Prometheus scrape target: `http://127.0.0.1:8765/metrics` (exposed only on
  loopback — expose externally only if behind proxy auth).
- Request IDs: clients may send `X-Request-ID`; responses always carry one.
- Key counters: `nks_wdc_http_requests_total`, `nks_wdc_snapshot_created_total`,
  `nks_wdc_retention_deleted_total`.

## Disable list (when debugging)

- `NKS_WDC_DISABLE_SCHEDULER=1` — pause the APScheduler retention job.
- `NKS_WDC_DISABLE_RATE_LIMITS=1` — disable slowapi rate limits.
- `NKS_WDC_LOG_LEVEL=DEBUG` — verbose structured logs.

## Release candidate smoke script

```bash
#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${1:-https://wdc.nks-hub.cz}

curl -fsS "$BASE_URL/healthz" | jq -e '.ok == true' >/dev/null
curl -fsS "$BASE_URL/api/v1/catalog" | jq -e '.apps | length > 0' >/dev/null
curl -fsS -o /dev/null -w "%{http_code}" "$BASE_URL/api/v1/sync/config/nonexistent"
echo  # blank separator

echo "smoke ok"
```
