# Changelog

## v0.6.0 — 2026-04-17

Authentication expansion + security headers + design iteration. 8 commits on top of v0.5.0.

### Features

- **Personal Access Tokens** — user-owned long-lived API keys for CI +
  scripts that can't run the interactive login flow.
  - Model: `PersonalAccessToken` (bcrypt hash + 10-char public prefix)
  - JSON: `POST/GET /api/v1/auth/tokens`, `DELETE /api/v1/auth/tokens/{id}`
  - Bearer-auth integration: `nks_pat_` prefix accepted alongside JWTs
  - UI: `/admin/account` section for create/list/revoke
  - Prefix-narrowed candidate query — no full-table bcrypt scan per request
- **Dashboard audit sparkline** — inline SVG bar chart of events per hour
  over the last 24h. Each bar has a tooltip with the hour label + count.
- **Sticky data-table headers** — column labels stay pinned under the
  topbar on long audit/user pages.

### Security

- **Strict transport-level headers** on every response:
  - `Content-Security-Policy` — `default-src 'self'`, `frame-ancestors 'none'`, `form-action 'self'`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` (skipped in DEV)
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy` disabling camera/mic/geolocation/USB/etc
  - `/metrics` bypasses CSP so Prometheus scrapers stay happy

### Design

- Light mode forced unless the user explicitly toggles dark via the
  topbar button. The old `prefers-color-scheme: dark` auto-activation
  was creating a too-dark default on Macs.
- Brighter base background (`#fbfcfd`), stronger borders (`#d1d5db`),
  darker muted text (`--text-3: #334155` hits WCAG AA).
- Bumped card shadows + elevated primary CTA with indigo halo.

### Tests

- 268 passing (+6 PAT lifecycle suite).

## v0.5.0 — 2026-04-17

Admin UI polish + correctness. 14 commits on top of v0.4.0.

### Bugfixes

- **CSRF double-submit on first visit**: form rendered with an empty
  token while the middleware wrote a fresh one → every first POST 403.
  Fixed by minting the token in ``base_context`` via ``request.state``
  so the form and cookie carry the same value.
- **Snapshot detail route collision**: `/snapshots/compare` was matched
  by `/snapshots/{snapshot_id}` (422 when "compare" couldn't parse as
  int). Fixed with a `{snapshot_id:int}` path converter.
- **Apps page missing table styling** (old `.table` class, no borders).
- **Form-grid overflow** on Settings / Retention (4-column fixed grid
  crammed 6+ fields). Rewritten as `repeat(auto-fit, minmax(220px, 1fr))`.
- **Nav clipping** on the Settings tab — added wrap + `<880px` breakpoint.
- **Error page duplicated title as detail** when identical.

### Features

- **Snapshot compare** (`/admin/devices/{id}/snapshots/compare`) — RFC
  6902 diff between any two snapshots, not just vs HEAD.
- **Per-device retention overrides** — table + add-form below the
  account policy so specific devices can have tighter or looser rules.
- **Dashboard recent-activity widget** — last 10 audit events under the
  stats cards for at-a-glance operator awareness.
- **Theme toggle** — topbar button cycles auto → light → dark → auto
  via a `nks_wdc_theme` cookie; CSS supports both `prefers-color-scheme`
  and explicit overrides.

### Tests

- 260 passing (was 251 in v0.4.0); +6 deep-route tests, +1 CSRF
  regression, +2 theme-toggle tests.
- Full Playwright screenshot walkthrough of every admin page captured
  to `.playwright-mcp/`.

### Cosmetics

- Text contrast bumped — `--text-2/3/4` darkened to hit WCAG AA on the
  light surface.
- Submit buttons inside `.form-grid` span all columns with left align.
- Checkbox labels render horizontally by default.

## v0.4.0 — 2026-04-17

Full HTML admin panel — 16 working pages covering every backend feature.
11 commits on top of v0.3.0.

### New admin UI pages

| Path | Purpose |
|---|---|
| `/admin` | Dashboard with live counters (catalog / users / devices / audit) |
| `/admin/users` + `/admin/users/{id}` | User management: role change, suspend/resume, reset password, revoke all tokens, delete |
| `/admin/audit` + `/admin/audit.csv` | Audit log browser with filters + CSV export |
| `/admin/invites` + `/admin/invites/history` | Mint invites + redemption history |
| `/admin/devices` + `/admin/devices/{id}` | Device list + detail with current payload |
| `/admin/devices/{id}/snapshots` | Snapshot browser with kind + label filter |
| `/admin/devices/{id}/snapshots/{sid}` | Snapshot detail with payload + RFC 6902 diff vs HEAD |
| `/admin/devices/{id}/snapshots/export.zip` | Archive download of every snapshot |
| `/admin/devices/{id}/import` | Paste JSON envelope to import a backup |
| `/admin/retention` | Global + per-account retention policy editor |
| `/admin/settings` | `GlobalPolicy` editor (banner, registration, defaults) |
| `/admin/account` | Self-service password change |
| `/admin/revoked-tokens` | JWT denylist browser |
| `/admin/catalog` | Apps list (original) |

### Infrastructure

- **Auto-ALTER on startup**: `db.create_all` now `ALTER TABLE ADD COLUMN` for any columns missing on pre-existing tables. Fixes silent-drop of role system columns on legacy deployments.
- **HTML/JSON content negotiation** on error handler: browser clients get templated error pages, `/api/v1/*` and machine endpoints keep Problem+JSON.
- **Starlette 404 fallback**: router-level path misses (not just handler-raised) flow through the HTML handler.
- **Banner**: `GlobalPolicy.banner_message` renders on every admin page.
- **Active-nav highlighting** with path-based `.active` class.
- **Signed flash cookies** (itsdangerous + session secret) — MITM can't inject flash messages.
- **`scripts/deploy.sh`** — one-shot tarball upload + rebuild + volume chown fix for the non-git-tracked prod host.

### Tests

- 251 passing (+18 from v0.3.0 baseline of 233)
- New suites: admin UI smoke (16 tests), account lockout, security regressions, audit FK integrity

### Architecture (carried over)

`app/main.py` final size: 317 lines. Seven router modules mounted:
`api_catalog.py`, `api_health.py`, `api_sync.py`, `api_auth_ui.py`,
`admin_ui.py`, `templating.py`, `device_ids.py`.

## v0.3.0 — 2026-04-17

Major security hardening + performance + architecture refactor. 40 commits
since v0.2.0.

### Breaking changes

- **JWT tokens invalidated on deploy** — new `iss="nks-wdc-catalog"` claim +
  required `exp`/`sub`/`jti`. All existing tokens must re-issue via
  `/auth/login`.
- **`POST /api/v1/sync/config` requires auth** — anonymous device-id squat
  vector closed. Clients without a token get 401.
- **`Idempotency-Key` reuse with different body → 422** (was silent replay).
- **Admin session shortened from 7 days to 24h absolute + 2h idle timeout**
  with rolling refresh. Long-idle admin users will be bounced to `/login`.
- **`NKS_WDC_MASTER_KEY` minimum 32 bytes** — shorter values refused unless
  `NKS_WDC_MASTER_KEY_ALLOW_WEAK=1`.
- **Variant-B passphrases now require ≥12 chars** (old 8-char ones still
  decrypt, only new encrypts are gated).
- **`DELETE /api/v1/sync/config/{id}` requires auth, returns 404 for
  non-owned rows** — existence-leak parity with read paths.

### Security (24 items)

- Invite `exp` enforced per-invite (was clamped to module default)
- Consumed invite nonces persisted → replay impossible even after account
  delete
- Constant-time login with dummy bcrypt burn on unknown emails
- Per-account failed-login lockout (5→1m, 10→5m, 15→30m)
- Rate-limit on HTML `/login` (was API-only)
- `/metrics` bearer auth via `NKS_WDC_METRICS_TOKEN`
- AAD pinned to `kid` for defence-in-depth on snapshot envelopes
- Flash cookie signed with session secret
- Trusted-proxy `X-Forwarded-For` via `NKS_WDC_TRUSTED_PROXIES=<CIDR,…>`
- Argon2id `time_cost` 3 → 4
- `NKS_WDC_BCRYPT_ROUNDS` override (10–14 clamp)
- `readonly` role login rejection
- RBAC 403 events emitted to `audit_events`
- Blob-URI bucket allowlist on delete (catches corrupted rows)
- Every `device_id` path param normalized (400 on malformed, not silent 404)
- `DEV=1` startup banner + refusal when `NKS_WDC_ENV=production`
- SQLite `PRAGMA foreign_keys=ON` — `SET NULL` cascades now actually fire
- Account-deletion no longer orphans `audit_events.actor_id`
- Idempotency body-hash (`Idempotency-Key` + body sha256)
- Request-ID response header + structured JSON logs
- Partial unique index on active encryption key per account
- Rate-limit storage can be Redis (`NKS_WDC_RATELIMIT_REDIS`) for
  multi-worker deployments

### Performance

- Retention uses `ROW_NUMBER()` CTE — no more in-memory materialization
  per account
- zstd compressor/decompressor reused module-level (was instantiated per
  call)
- Admin stats dashboard: 9 separate `COUNT(*)` → 4 composite SELECTs
- Catalog ETag via `model_dump_json(exclude={"generated_at"})` — single
  pydantic walk instead of double
- Revoked-JTI TTL cache on auth hot path
- `list_snapshots` skips COUNT query on page 1 when results fit
- Encrypted-snapshot path skips the throwaway `_pack_from_raw` call
- New indexes: `device_configs.last_seen_at`, `revoked_tokens.expires_at`

### Observability

- `/healthz` is now liveness-only (no DB probe)
- `/readyz` is new — DB `SELECT 1` + optional S3 `HeadBucket`
- `nks_wdc_auth_failures_total{reason}` counter (bad_password /
  unknown_email / invalid_token / permission_denied)
- `nks_wdc_blob_orphan_total` counter for retention-path S3 failures

### Architecture

`app/main.py` shrunk 1070 → 317 lines (-70%) via seven new focused modules:

| module | role |
|---|---|
| `api_catalog.py` | public `GET /api/v1/catalog*` |
| `api_sync.py` | `/api/v1/sync/config*` JSON endpoints |
| `api_auth_ui.py` | `/`, `/login`, `/logout` HTML routes |
| `api_health.py` | `/healthz` + `/readyz` |
| `admin_ui.py` | `/admin/*` HTML + flash helpers |
| `templating.py` | shared Jinja + base context |
| `device_ids.py` | `normalize_device_id` helper |

### Alembic migrations (auto-applied on boot via `create_all`)

- `7c9f1e8a4b21` — `idempotency_records.body_hash` + `consumed_invites`
- `8a3d2c5f1e9b` — perf indexes + `ux_active_key_per_account` partial
  unique index
- `a7f2c9e4d3b1` — `accounts.failed_login_count` +
  `accounts.locked_until`

### Tests

- 233 passing (was 222 at v0.2.0)
- 11 new regression suites: account lockout, metrics auth, invite replay,
  XFF trust, audit FK integrity

## v0.2.0 — 2026-04-17 (earlier)

First agentic-review pass: 4 critical findings fixed (retention session
leak, blob-separator collision, snapshot idempotency TOCTOU, RBAC
permission bypass). Released initial standalone repo with GHCR image.
