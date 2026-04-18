# Changelog

## v0.15.0 — 2026-04-18

Audit bulk JSONL export — completes the audit forensics story.

- New `GET /admin/audit/export.jsonl.gz` — streams compressed NDJSON
  (one JSON object per line, gzip-wrapped) honoring the same `action`,
  `resource_type`, `resource_id`, `actor_id` filter params as the
  HTML audit page. Default limit 50 000 rows, hard cap 200 000.
  Shape: `{id, created_at, actor_id, actor_email, action,
  resource_type, resource_id, ip, user_agent, detail}`. Trivially
  ingestible by `jq` / logstash / SIEM pipelines:
  `curl … | gunzip | jq -c .`.
- `_audit_filter_stmt` helper extracted so HTML, CSV, and JSONL
  handlers share identical filter logic — can't drift.
- UI: "Export JSONL.gz" button next to the existing Export CSV.

4 new tests (gzip headers, decompress + NDJSON shape, filter honoured,
auth gate) — 364 passing, up from 360.

## v0.14.0 — 2026-04-18

Global search (`/admin/search`).

- New `GET /admin/search?q=<term>` — runs substring (ILIKE)
  lookups across three categories and renders grouped results:
  Users (match email), Apps (match id or display_name), Audit
  events (match action, resource_id, or actor_email). Top 10 per
  category. Deep-links into `/admin/users/{id}`,
  `/admin/apps/{id}`, and a "see all audit events matching" link
  into `/admin/audit?action=<q>`.
- Topbar gains a compact search input (visible on ≥ 881 px;
  hidden on the mobile drawer) that posts straight into the
  results page. Focus widens the input from 180 → 260 px via a
  CSS `width` transition.
- Empty-query renders an explainer; no-match renders a proper
  empty state with the query echoed.

5 new tests — 360 passing, up from 355.

## v0.13.0 — 2026-04-18

Audit-log retention — configurable per instance.

- `GlobalPolicy.audit_retention_days` (default 365). Auto-ALTER on
  startup handles legacy DBs.
- Nightly retention runner now sweeps `audit_events` older than the
  configured window via the existing `_batched_delete` helper; the
  summary dict gains `audit_events_purged` for the manual-run flash
  + the `retention.manual_run` audit event detail picks it up
  automatically. `0 = never purge` as an escape hatch for external
  SIEM setups; capped at 3650 days (10 years).
- Settings surface: new "Audit retention" fieldset between "Snapshot
  defaults" and "Quotas" with a single "Keep audit events for (days)"
  input. Changes flow through the existing `settings.updated` audit
  diff.

4 new tests (retention sweep + default behaviour + 0-means-never +
settings save) — 355 passing, up from 351.

## v0.12.0 — 2026-04-18

Invite-history filter + CSV export.

- `/admin/invites/history` gains `email` (substring, case-insensitive),
  `since` (YYYY-MM-DD, inclusive), `until` (YYYY-MM-DD, inclusive
  end-of-day) query params; filters applied by a shared
  `_invites_history_stmt` helper so the HTML and CSV endpoints can't
  drift.
- New `GET /admin/invites/history.csv` — up to 10 000 rows with a
  4-column CSV (email, consumed_at, account_id, nonce), attachment
  filename `invite-history.csv`, `Cache-Control: no-store`. Cells
  escaped by `csv.writer` so commas / quotes in email-local-parts
  round-trip cleanly.
- UI: filter form above the table with `clear` + `Export CSV` buttons,
  matching the `/admin/audit` pattern.

4 new tests (CSV content, email filter, date filter, unauth redirect)
— 351 passing, up from 347.

## v0.11.0 — 2026-04-18

**Global 2FA enforcement for admin UI users.**

v0.8.0 shipped opt-in TOTP. v0.11.0 lets an owner flip a single
checkbox that forces every admin without TOTP to pair an authenticator
before touching any other admin page.

### Shipped

- **`GlobalPolicy.require_2fa_for_admins`** — new `Boolean` column,
  default `False`. Auto-ALTER on startup handles legacy DBs.
- **Gate dependency** `current_user_with_2fa_gate` wired as a
  router-level `Depends` on the admin router via
  `app.include_router(..., dependencies=[...])` — zero per-handler
  surgery, FastAPI deduplicates the nested `Depends(current_user)`.
  Returns 302 `/admin/account?flash=totp-required` for ungated admins
  on gated paths.
- **Allowlist** — `/admin/account`, `/admin/account/totp/*`,
  `/admin/theme`, `/static/*`, and (naturally) `/logout` (not on the
  admin router) remain reachable so a freshly-enrolled admin can
  actually complete setup.
- **Warning banner** on `/admin/account` explains the forced setup.
- **Settings checkbox** under the "Access" fieldset. Changes flow
  through the existing `settings.updated` audit diff — no new event
  action needed.

### Totals

3 commits (schema + gate → settings toggle → release). 347 tests
passing, up from 340.

## v0.10.0 — 2026-04-18

**Admin session management — per-session revocation for the admin UI.**

Previously, admin-UI session cookies were stateless (`itsdangerous`-signed);
there was no way to enumerate active sessions or kill one without
rotating the global signing secret (nukes everyone). v0.10.0 adds a
session store with fingerprint-based lookup so each browser login is
trackable and individually revocable.

### Shipped

- **`admin_sessions` table** — `id, user_id (FK users.id), fingerprint
  (sha256 of the signed cookie, unique), ip, user_agent, created_at,
  last_seen_at, revoked_at`. Auto-ALTER on startup; no migration needed.
- **Session tracking** — `issue_session()` writes a row on login
  (best-effort; DB failure never breaks the cookie handshake).
  `current_user` dependency looks up the row on every admin request,
  rejects if `revoked_at IS NOT NULL`, updates `last_seen_at`.
  Legacy pre-v0.10 cookies with no row auto-create one on first hit —
  zero-breakage rollout for sessions in flight.
- **"Active sessions" section on `/admin/account`** — compact table
  with IP, user-agent, created, last-seen. Current browser marked
  with a `this browser` pill. Per-row "kill" button for the others,
  plus "Kill all other sessions" bulk button when any non-current
  sessions exist.
- **Handlers** — `POST /admin/account/sessions/{id}/kill` and
  `POST /admin/account/sessions/kill-others` — CSRF-gated,
  scoped to the current user's rows, emit audit events
  `session.killed` (detail: ip + ua) and `session.killed_others`
  (detail: count).

### Totals

3 commits (schema + auth core → UI + kill handlers → release). 340
tests passing, up from 334.

## v0.9.1 — 2026-04-18

- **User activity timeline** — `/admin/users/{id}` now carries a
  20-row audit feed of events involving that user (as actor or
  as the account resource). Reuses the existing `.data.compact`
  table + `.json-tint` detail rendering; "View full log" link
  deep-links into `/admin/audit?actor_id={id}` for paginated
  browsing. 1 new regression test (total 334 passing).

## v0.9.0 — 2026-04-18

**Live audit tail via Server-Sent Events.**

Audit log was pull-only — reload the page, re-submit the filter. Not
ideal mid-incident. v0.9.0 adds a real-time stream backed by an
in-process async pub/sub bus, gated by RBAC + CSP-clean client.

### Shipped

- **Event bus** (`app/event_bus.py`) — process-local async pub/sub,
  `asyncio.Queue` per subscriber (size 128, drop-oldest on overflow
  so a slow client can't pin memory), subscriber cap
  `MAX_SUBSCRIBERS=32`, `threading.Lock` around the subscriber set
  for MT-safety under FastAPI's thread pool. Sync `publish()`, async
  `subscribe()` context manager. 5 unit tests.
- **Audit publish hook** — `audit.emit()` publishes each flushed row
  to the bus inside `try/except` so bus failure never breaks the
  audit write path. 2 regression tests (successful publish +
  graceful-degrade when the bus raises).
- **SSE endpoint** `GET /admin/audit/stream` — session-auth gated,
  `text/event-stream` with `Cache-Control: no-cache` +
  `X-Accel-Buffering: no` for nginx/Caddy passthrough. Opens with
  a `connected` event, emits `audit` events per row, comment
  heartbeat every 15 s so idle proxies don't drop. Returns 503 on
  subscriber-cap saturation. 3 tests (unauth denial, event delivery,
  connected frame) — TestClient required anyio portal gymnastics to
  drive an infinite SSE generator deadlock-free.
- **Live toggle UI** — pill on `/admin/audit` with a pulsing red dot
  when active (`@keyframes live-pulse` respecting
  `prefers-reduced-motion`). Click opens `EventSource`, prepends
  new rows as `<tr class="audit-row-new">` with a 600 ms accent
  fade-in. Filter-aware: URL params (`action`, `resource_type`,
  `resource_id`, `actor_id`) drop non-matching events client-side.
  CSP-clean (no inline scripts, no `innerHTML` with user data;
  every cell built via `document.createElement` + `.textContent`).
  1 smoke test.

### Totals

5 commits (event bus → publish hook → SSE endpoint → Live toggle →
v0.9.0 release). 333 tests passing, up from 322.

## v0.8.3 — 2026-04-18

Audit coverage follow-through — snapshots, auto-generate, JSON auth.

- `snapshot.imported` — admin UI `/admin/devices/{id}/import` now
  records the label, set_head flag, and payload size.
- `snapshot.restored` — captures `previous_head_id` so a rollback chain
  is reconstructable from the audit log alone.
- `app.auto_generated` — release-scraper runs carry limit + scraped
  count + actually-inserted count.
- `account.registered` — self-registration via JSON API now audited.
- `login.ok` — successful JSON-API logins emit an event tied to
  the authenticating account.
- Four new quick-filter chips on `/admin/audit`: Logins, Registrations,
  Settings, App deletions.

5 new audit actions · 5 new tests (total 322 passing).

## v0.8.2 — 2026-04-18

Audit-log coverage sweep — every mutation path emits a named event.

Previously, an admin could:
- Rewrite instance-wide policy via `/admin/settings`
- Toggle the snapshot retention policy or add device overrides
- Create / edit / delete apps, releases, downloads
- Change their own password
- Delete a device

…with **zero audit trail**. Each of those paths now emits an audit
event with before/after detail where relevant.

### New audit events
- `settings.updated` (detail: `changed` diff per field)
- `retention.policy_saved` (before/after)
- `retention.manual_run` (summary counts)
- `retention.device_override_added`, `retention.device_override_removed`
- `password.changed`, `password.change_failed`
- `device.deleted`
- `app.created`, `app.updated` (field diff), `app.deleted`
- `release.created`, `release.deleted`
- `download.added`, `download.deleted`

### Tests
`test_settings_retention_audit.py` (5 cases) +
`test_catalog_audit_events.py` (4 cases) — total 317 tests passing.

## v0.8.1 — 2026-04-18

Observability + audit coverage follow-up to v0.8.0.

- **Saved audit-query presets** — per-account named filter presets at
  `/admin/audit`. Save current filter with one click, re-apply with
  another, delete inline. Active preset renders as a filled-accent
  chip. Unique `(account_id, name)` so re-saving under the same label
  upserts. 8 new e2e tests.
- **PAT audit events** — `pat.created` + `pat.revoked` now fire from
  both the admin UI and the JSON API (`POST/DELETE /api/v1/auth/tokens`).
  Previously a PAT mint on a compromised admin account left zero
  audit trail — real security-observability gap. Detail payload
  carries the token name and prefix. New "PATs" quick-filter chip.
- **Ops artifacts** — `ops/prometheus/alerts.yml` (7 rules: 5xx
  spike, p99 latency, admin-idle detection, auth-failure + RBAC-denial
  spikes, blob-orphan growth, retention-runner stall),
  `ops/grafana/dashboard.json` (4 KPI stats + 4 timeseries + top-10
  routes table), `ops/README.md` with setup instructions and metric
  catalogue.

3 new test files · 11 new tests · total 308 tests passing.

## v0.8.0 — 2026-04-18

Two-factor authentication for the admin UI.

- **TOTP core** (`app/totp.py`) — RFC 6238 HMAC-SHA1 TOTP implemented
  inline (no pyotp dep). 160-bit base32 secrets, ±1 window drift
  tolerance, constant-time verify. Confusable-free 10-char recovery
  codes (`abcde-fghij`). 12 unit tests incl. RFC 6238 Appendix B
  reference vectors.
- **Account schema** — `totp_enabled`, `totp_secret`,
  `totp_recovery_hashes` (newline-joined bcrypt hashes),
  `totp_enabled_at`. Auto-ALTER on startup handles legacy DBs.
- **Admin UI** — `/admin/account/totp/{setup,confirm,disable}`. Setup
  renders a hero token block with the `otpauth://` URI + raw base32
  secret so any authenticator app pairs in one paste. Confirm mints
  8 one-time recovery codes, shown once in a hero copy block.
  Disable requires a live TOTP code or a recovery code.
- **Login flow** — `/login` now redirects to `/login/2fa` for 2FA-
  enabled accounts via a short-lived (5 min) signed pending cookie;
  session cookie is only minted after the second factor verifies.
  Recovery codes accepted on `/login/2fa` and burned on use.
- **Audit events** — `totp.setup_started`, `totp.enabled`,
  `totp.disabled`, `totp.login_ok`, `totp.login_failed`. The
  `used_recovery` detail flag marks recovery-code-based auths.
- **Flash cookie fix** — `_redirect()` now base64-wraps signed flash
  bytes so non-ASCII message text (arrows, em-dashes) doesn't crash
  cookie serialization.

12 commits · 12 new tests (5 admin + 7 login flow) · total 297 tests passing.

## v0.7.2 — 2026-04-17

P1 design polish — fieldset-grouped configuration forms, dashboard
hero KPI card, hero token block with copy button.

- **Fieldset-grouped settings + retention forms** — Global settings
  now splits into "Access / Snapshot defaults / Quotas / Admin UI"
  fieldset cards; retention splits its policy editor and "add device
  override" form similarly. Each input gets a `<span class="hint">`
  explainer below (Gestalt: labels name, hints reduce ambiguity).
  Primary action lives in a `.form-actions` row with top border,
  matching Linear / Stripe's modern config surface pattern.
- **Dashboard hero KPI** — full-width card leads the page with a
  2.5 rem mono "events last 24h" figure and a 96 px-tall area-fill
  sparkline. Supporting Catalog / Users / Devices stats sit in a 3-col
  grid beneath. Bottom wide card adds a horizontal bar chart for
  top-8 actions in the last 24h.
- **Hero token block + copy button** — minting a PAT or invite now
  renders a visually loud success card: dashed mono token field,
  "Copy token" button (clipboard API with select-all fallback),
  success-tinted gradient, explicit "shown once" warning.
  Implemented via a CSP-safe external `/static/admin.js` progressive
  enhancement (no inline scripts).

## v0.7.1 — 2026-04-17

P2 design-review polish. 5 commits on top of v0.7.0.

- **Login brand moment** — real SVG logomark, tagline ("Catalog &
  config sync"), warm radial gradient behind the card, topbar/footer
  hidden on login surface. First-impression moment matters (Lindgaard
  et al., 2006: 50 ms credibility judgement).
- **Mobile nav drawer** (<720 px) — no-JS `<details>` hamburger drawer
  drops down from topbar; CSP stays strict.
- **Active chip state** — filter chips at `/admin/audit` render filled
  accent when the current query matches, instead of only hover color.
- **`prefers-reduced-motion` guard** — transitions and button-active
  translateY skip for users who asked the OS for reduced motion.
- **JSON syntax tinting** in audit details — server-side Jinja filter
  tokenises the JSON and wraps keys/strings/numbers/literals in
  `<span class="jsx-*">`. Keys get accent-indigo, numbers burnt orange,
  booleans/null warning-yellow italic. HTML and XSS payloads in
  detail bodies are escaped (4 new tests lock it in).

## v0.7.0 — 2026-04-18

Design review implementation — warm palette, refined tables, friendlier
empty states + helper text. 10 commits on top of v0.6.0.

### Design

- **Warm paper palette** — `--bg #f5f3ee` (warm off-white) instead of
  cold slate `#fbfcfd`. Neutral warm black `#1a1a1a` text. Cards stay
  pure white so they out-bright the page.
- **Navy topbar** kept from v0.6.0, now contrasted against the warm page.
- **Tables redesigned** — zebra stripes on even rows, single 2 px
  `--border-strong` underline under header row (was per-row 1 px
  borders), sentence-case column names (was 10 px uppercase
  micro-caps), hover row gets `inset 3px 0 0 var(--accent)` left-edge
  indicator.
- **Form labels sentence-case** — drop the uppercase + letter-spacing
  styling on `.form-grid label` to match Linear / Stripe / Vercel.
- **Mono stat numbers** — `.stat-row b` now `font-mono +
  tabular-nums + 1.286rem` so KPIs are the visual hero of the card.
- **Sparkline polish** — 64 px tall (was 40 px), area fill under the
  stroke, dotted baseline, per-hour hover circles with `<title>`
  tooltips, end-dot marker for "now".
- **`.empty-state` block** — icon + headline + max-42ch copy + CTA.
  Applied to users list, devices list, audit log (filter-aware:
  "No matching users" vs "No accounts yet").
- **`.hint` class** — helper text under form inputs (Invites page
  uses it for email/role/TTL explanations).
- **Split accent token** — `--accent` stays for structural indigo,
  new `--action #c2410c` burnt orange ready for future CTA separation.

### `app_detail` redesign (the page the user flagged as "za hovno")

Full rewrite from `page-head/card/card-header` to
`section-head + release-block` cards. Release metadata is a
`.pill-row` (version pill / channel / date), Downloads is now a
proper `.data.compact` table with OS pills, mono code cells for arch
/ archive_type, and a URL cell with word-break + mono. "Add download"
became a collapsible `<details>` with a proper form-grid.
Add-release-manually got labeled 3-col grid instead of 3 stretched
full-width inputs.

### Bugfixes

- Sticky `.data thead th` disabled inside `.release-block` cards —
  was causing the thead to overlap the first tbody row inside nested
  tables.

### Tests

- 269 passing (was 268 in v0.6.0). Ruff + format clean.

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
