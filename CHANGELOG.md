# Changelog

## v0.48.0 — 2026-04-18

PAT rotation with atomic revoke + replacement mint.

- New `POST /api/v1/auth/tokens/{id}/rotate` revokes the given
  PAT and issues a replacement carrying over its name, `read_only`
  flag, `ip_allowlist` and expiry timestamp. Response returns the
  new plaintext once, same contract as mint.
- Expiry is carried over as an absolute timestamp — rotation does
  not silently extend a caller's access window.
- Emits `pat.rotated` audit event (distinct from `pat.created` /
  `pat.revoked`) with `old_token_id` + new row attributes in the
  detail payload, so forensics can distinguish rotations from
  ad-hoc mints during incident triage.
- Added `pat.rotated` to `SECURITY_ACTION_ALLOWLIST` for Prometheus
  + Grafana coverage.
- 404 on foreign tokens and on already-revoked rows — no silently
  reviving dead PATs.

## v0.47.0 — 2026-04-18

Webhook delivery manual retry.

- New `POST /admin/ops/webhooks/{delivery_id}/retry` re-dispatches
  a webhook event whose original delivery failed. Useful when the
  receiver was transiently down and the operator wants to confirm
  it's back without waiting for the next real event.
- Inline `Retry` button on the `/admin/ops/webhooks` page, shown
  only on failed rows. CSRF-guarded.
- Minimal payload reconstruction (original event body isn't stored
  on the delivery row) — test is "does the URL come back online",
  not "replay exact bytes". Documented in handler docstring.
- Emits `webhook.retried` audit event; added to
  `SECURITY_ACTION_ALLOWLIST` for Prometheus + Grafana coverage.

## v0.46.0 — 2026-04-18

Global session kill — emergency panic button.

- New `POST /admin/security/kill-all-sessions` revokes every
  `AdminSession` (except the caller's) and bumps `token_version`
  on every non-suspended account (invalidates every outstanding
  JWT bearer token). Gated by CSRF + admin auth + a typed
  confirmation phrase `KILL-ALL` to prevent misclicks.
- Emits a new `admin.global_session_kill` audit event with
  `admin_sessions_killed` / `token_versions_bumped` counts in
  the detail payload; added to `SECURITY_ACTION_ALLOWLIST`.
- Danger-styled form on `/admin/ops` ties the control into the
  existing ops page where the incident-response operator is
  already looking when a breach is suspected.

## v0.45.0 — 2026-04-18

`/admin/accounts/locked` — operator view + one-click unlock.

- New page at `/admin/accounts/locked` lists every account with
  `locked_until > now` OR `failed_login_count >= 5`, sorted by most
  recently locked. Each row has a CSRF-guarded unlock button that
  reuses the existing `/admin/users/{id}/unlock` handler and bounces
  the operator back to the list via a safe-prefixed `next=` param
  (open-redirect guard: only `/admin/` prefixes accepted).
- `user.unlocked` added to `SECURITY_ACTION_ALLOWLIST` so the
  closing-signal (operator short-circuited a lockout) rides the
  v0.41 Prometheus counter + v0.42 Grafana panels automatically.
- Ties the victim-axis together with the lockout-signal series:
  v0.43 `login.locked_out` (attempts vs. locked door) → v0.44
  `login.lockout_armed` (threshold fires) → v0.45 aggregated
  operator view to act on the state those two signals produce.

## v0.44.0 — 2026-04-18

`login.lockout_armed` audit event.

- `_record_failed_login()` now returns the `lock_minutes` it just
  applied. The login handler catches the non-zero return and emits
  a **`login.lockout_armed`** audit row with `lock_minutes` and
  `failed_login_count` in the detail payload. This captures the
  transition moment (threshold fires, lockout arms) — distinct from
  `login.failed` (every bad password) and `login.locked_out` (attempts
  against an already-locked account from v0.43.0).
- Added to `SECURITY_ACTION_ALLOWLIST`; the v0.41.0 Prometheus counter
  and v0.42.0 Grafana security panels pick it up automatically.
- Enables ops alerting on "account X just got locked out" moments
  rather than drowning in bounce-traffic against locked doors.

## v0.43.0 — 2026-04-18

`login.locked_out` audit event.

- `POST /api/v1/auth/login` emits a new **`login.locked_out`** audit
  action when the target account has `locked_until > now` (from the
  existing failed-login backoff). Distinct from `login.failed` —
  means someone is pounding on a known-locked door, worth a
  separate Prometheus series for alerting.
- Added to the `SECURITY_ACTION_ALLOWLIST`, so the v0.41.0
  `nks_wdc_security_events_total{action="login.locked_out"}` counter
  increments automatically and the v0.41.0 failed-login Alertmanager
  rule naturally folds it in via the regex filter.
- Audit-trail commit happens before the 423 response so the event
  survives the HTTPException rollback of the caller's session.
- `/admin/audit` filter-chip row gains a "Lockouts" shortcut next to
  "Logins" for quick forensic filtering.
- `_inc_auth_failure("locked")` runs alongside so the pre-existing
  `nks_wdc_auth_failures_total{reason="locked"}` continues to track
  the same event at the middleware layer.

3 new tests (locked account emits event, unlocked account doesn't,
allowlist sanity) — 495 passing, up from 492.

## v0.42.0 — 2026-04-18

Grafana dashboard — security signals row.

- `ops/grafana/dashboard.json` gains a `Security signals` collapsible
  row containing four stat panels and one time-series chart:
  - **Failed logins · 5m** (password + TOTP summed) — green/yellow/red
    thresholds at 0 / 5 / 25.
  - **RBAC denials · 5m** — green/yellow/red at 0 / 3 / 15.
  - **Session kills · 30m** — green/yellow/orange at 0 / 3 / 10.
  - **Token revocations · 30m** — green/yellow/red at 0 / 1 / 5.
  - **Security events by action** — per-action rate timeseries so
    operators can spot which category is driving a paged alert.
- New regression test suite (`tests/test_grafana_dashboard.py`)
  validates JSON syntax, presence of the security row, grid-position
  non-overlap within each row, and that every non-row panel has
  `gridPos` + non-empty `targets`. A corrupt dashboard JSON breaks
  the Grafana import silently; catching it in CI is cheaper than
  catching it in production.

4 new tests — 492 passing, up from 488.

## v0.41.0 — 2026-04-18

`nks_wdc_security_events_total` Prometheus counter.

- **New Counter** with a single `action` label. Incremented from
  `audit.emit` for a curated allowlist of security-significant
  action names (login.failed, totp.login_failed, permission.denied,
  password.change_failed, user.suspended, user.deleted,
  user.tokens_revoked, session.killed, session.killed_others,
  totp.disabled, backup.exported).
- **Cardinality discipline** — the allowlist is explicit; arbitrary
  admin actions (e.g. `app.updated`) do NOT increment, keeping the
  Prometheus series count bounded. Unit-tested with a sanity check
  that core security actions stay in the allowlist across refactors.
- **Alert rules** — `ops/prometheus/alerts.yml` gains three rules
  under a new `nks-wdc-security` group: failed-login spike
  (warning, >5/min sustained 10m), sustained RBAC denials (critical,
  >3/min sustained 10m), and a mass-session-kill info alert
  (>5 kills in 30m — usually incident response).
- **Best-effort** — metric increment is wrapped so a broken
  prometheus_client never breaks the audit write path.
- Complementary to the existing `nks_wdc_auth_failures_total` which
  tracks pre-audit rejections (bad_password etc.); the new counter
  tracks post-audit, fully-recorded events.

4 new tests (allowlist increments, non-allowlist doesn't, /metrics
exposes counter, core-actions sanity) — 488 passing, up from 484.

## v0.40.0 — 2026-04-18

Dashboard security signals card — companion to v0.39.0 ops card.

- `/admin` landing page renders a `Security signals · last 24h`
  card when ANY of the three signals (failed logins, RBAC denials,
  password-change failures) is at warn-or-bad severity. Reuses the
  `_security_signals_last_24h` helper shipped in v0.39.0 — same
  thresholds, same three rows, same pills + view-deep-links.
- **Quiet days keep the dashboard calm** — the entire card
  short-circuits via a Jinja `{% if %}` when every signal is at ok
  severity. No silent row of zeros to desensitize operators to
  warning pills.
- Small muted footer links to `/admin/ops` for the always-visible
  full breakdown.

4 new tests (calm-omits-card, warn-surfaces, bad-surfaces,
drill-down-links) — 484 passing, up from 480.

## v0.39.0 — 2026-04-18

Security-signals card on `/admin/ops` — last-24h threat indicators.

- Full-width card surfaces three rolling 24 h counts with threshold
  pills:
  - **Failed logins** (`login.failed` + `totp.login_failed` summed):
    amber at ≥ 5, red at ≥ 20.
  - **RBAC denials** (`permission.denied`): amber at ≥ 3, red at ≥ 10.
  - **Password-change failures** (`password.change_failed`): amber at
    ≥ 3, red at ≥ 10.
- Each row has a `view →` deep-link into the appropriate filtered
  `/admin/audit` page so operators can drill from count to rows in
  one click.
- Thresholds chosen for typical single-tenant admin deployments —
  operators running public-facing APIs with heavier login traffic
  can raise via env override in a future release (left hardcoded
  for now to avoid yet another GlobalPolicy knob).
- Zero counts render as plain numbers; threshold pills kick in
  only when there's actually something to look at.

6 new tests (card renders, zero-counts, amber threshold, red
threshold, login+TOTP aggregated, RBAC red threshold) — 480
passing, up from 474.

## v0.38.0 — 2026-04-18

Scheduler-failure banner on every admin page.

- When any `SchedulerRun(job=*)` within the last 48 h has a non-null
  `error` AND is the most-recent row for its job (i.e. not
  superseded by a later successful run), every admin page renders
  a red `.banner-error` at the top with the job name, age
  ("3h 14m ago"), truncated error message, and an "investigate →"
  link deep-linking into `/admin/ops/scheduler?status_filter=failed`.
- Picks the **newest unattended** failure so a broken retention job
  isn't drowned out by a subsequent successful backup run — the
  operator sees the first alert that still matters.
- Survives the 48 h window silently — ancient failures don't keep
  nagging forever.
- Threaded via `base_context(...)`, so the banner shows on `/admin`,
  `/admin/audit`, `/admin/ops`, etc., without per-handler plumbing.
- New `.banner-error` CSS (red variant of the amber `.banner` with
  flex layout for left-aligned message + right-aligned link).

5 new tests (no-failures, recent-failure, old-failure-suppressed,
success-supersedes-failure, banner-on-every-admin-page) — 474
passing, up from 469.

## v0.37.0 — 2026-04-18

Dashboard KPI delta chips.

- The hero KPI and the Webhooks card's Sent row gain a compact
  `▲ +N` / `▼ -N` / `—` chip showing current-24h minus prior-24h
  counts for audit events and webhook deliveries. Operators see
  "today busier than yesterday" at a glance without navigating
  into `/admin/ops`.
- Both the current-24h and prior-24h counts queried fresh in the
  handler — NOT mixed with the 30-s cached
  `stats.audit.events_last_24h` — so the arrow direction always
  matches the visible count math.
- Zero-delta renders as a muted em-dash so a flat period doesn't
  show up as a misleading arrow.
- New `.kpi-delta` / `.kpi-delta-up/-down/-flat` CSS using the
  existing success / danger / surface-2 tokens.

3 new tests (positive, negative, flat) — 469 passing, up from 466.

## v0.36.0 — 2026-04-18

`user.tokens_revoked` audit event.

- **`POST /admin/users/{id}/revoke-tokens`** — the mass-JWT-revocation
  button on the user detail page has been in the codebase since the
  early admin UI, but never emitted an audit event. A security-
  critical admin action leaving no trail was a real gap.
- **New `user.tokens_revoked` audit action** — detail carries
  `target_email`, `token_version_before`, `token_version_after` so
  operators reconstruct the chain (who revoked, whose tokens, when,
  from which TV to which TV) without database spelunking.
- **404 path suppressed** — an attempt against a missing user_id
  returns 404 without writing a phantom audit row.

2 new regression tests (happy path + 404 no-audit) — 466 passing,
up from 464.

## v0.35.0 — 2026-04-18

Audit free-text search.

- `/admin/audit?q=<substring>` runs a case-insensitive ILIKE across
  `action`, `resource_id`, `actor_email`, AND the JSON-cast `detail`
  column. The detail cast catches "magic strings" stored in event
  payloads (a user's IP, a cookie fragment, a specific error token)
  without needing to know which structured field holds it.
- Threaded through `_audit_filter_stmt` so the same `q` param flows
  through `/admin/audit.csv` and `/admin/audit/export.jsonl.gz`
  automatically — every export obeys the same filter surface.
- Template gains a wider `q` input alongside the existing structured
  filter fields. `any_filter_active` includes `q` so the "clear"
  button appears.
- URL-encoding on `qs` pagination links so a `q=with spaces` round-
  trips cleanly.
- Combines (AND) with structured filters — a row must match every
  non-empty filter AND the free-text term.

5 new tests (matches action, actor_email, resource_id, JSON detail,
combined with structured filter) — 464 passing, up from 459.

## v0.34.0 — 2026-04-18

Auto-revoke idle admin sessions.

- **`GlobalPolicy.admin_session_idle_days`** — default 0 (disabled).
  Auto-ALTER on startup handles legacy rows.
- **Nightly retention sweep** — an `UPDATE admin_sessions SET
  revoked_at=now WHERE last_seen_at < cutoff AND revoked_at IS NULL`
  runs inside `_do_retention` after the webhook-deliveries sweep.
  When an admin forgets to log out from a coffee-shop laptop, the
  session dies on its own at the next 03:00 UTC sweep.
- **Summary dict** gains `admin_sessions_auto_revoked`; the manual-
  run flash + `retention.manual_run` audit event detail + the
  `SchedulerRun(job="retention")` row all carry the count.
- **Settings UI** — new "Auto-revoke idle admin sessions after
  (days)" input in the Access fieldset alongside the v0.32.0
  admin_ip_allowlist textarea.
- **Default 0 = disabled** — explicit opt-in so legacy deployments
  don't log admins out immediately after upgrade.
- **Revoked sessions stay revoked** — the sweep only flips
  `revoked_at` on rows where it's currently NULL.

Complements the v0.10.0 manual session-kill: operators don't need
to chase down stale sessions by hand.

4 new tests (sweep revokes stale, zero disables, already-revoked
untouched, settings save diff) — 459 passing, up from 455.

## v0.33.0 — 2026-04-18

PAT last-used source tracking.

- **`PersonalAccessToken.last_used_ip`** (`String(45)` — IPv6-ready)
  + **`last_used_ua`** (`String(256)`) — stamped on every successful
  authentication alongside the existing `last_used_at`.
  Auto-ALTER handles legacy rows; NULL until next use.
- **`try_authenticate_pat`** gains a `request=None` kwarg. When
  provided, pulls `request.client.host` + `request.headers['user-agent']`
  (capped at 256 chars, matching the `admin_sessions.user_agent`
  convention).
- **`get_current_account`** passes `request` through.
- **`/admin/account`** — the "Last used" PAT column gains an inline
  `<details>` toggle revealing `<code>IP</code>` + truncated UA.
  Hover shows full UA via the title attribute.
- **No audit event** — stamping per-auth-request would balloon the
  audit table; the row itself is the record.

Forensic win for the v0.30.0/v0.31.0 scope stack: operators can now
spot a read-only PAT suddenly used from a new IP without digging
through audit.

4 new tests (auth stamps IP+UA, missing-UA-header, UA truncation,
account page shows source details) — 455 passing, up from 451.

## v0.32.0 — 2026-04-18

Global admin-UI IP allowlist.

- **`GlobalPolicy.admin_ip_allowlist`** — nullable JSON list of
  CIDR strings. Empty / NULL = no restriction (back-compat).
  Auto-ALTER handles legacy DBs.
- **`current_user` CIDR check** — after the v0.10.0 fingerprint
  lookup, compare the request's client IP against every configured
  CIDR via stdlib `ipaddress`. No match → `HTTPException(302,
  Location=/login)` — the same response a cookie-less admin
  request would get, so scanners can't distinguish the two.
- **Fail-OPEN on unexpected errors** — opposite of v0.31.0's
  per-PAT fail-closed stance. Breaking the gate while it's broken
  (DB unreachable, parse error) is better than locking every admin
  out of the UI globally.
- **Settings UI** — textarea in the "Access" fieldset accepts
  newline/comma-separated CIDRs. Changes flow through the
  existing `settings.updated` audit diff.
- **No per-account allowlist** — too risky (home IP changes lock
  you out). Operators who need per-principal scope use PAT +
  v0.31.0's `ip_allowlist`.

Defense-in-depth layers: (v0.11) global 2FA enforcement, (v0.30)
PAT read-only, (v0.31) PAT IP allowlist, (v0.32) global admin-UI
IP allowlist.

6 new tests (no-allowlist works, matching CIDR 200, non-matching
302, malformed fail-closed at enforce time, settings save, login
page outside gate) — 451 passing, up from 445.

## v0.31.0 — 2026-04-18

PAT IP allowlist — per-token network scope.

- **`PersonalAccessToken.ip_allowlist`** — nullable JSON column
  storing a list of CIDR strings. Empty / NULL = no restriction
  (back-compat). Auto-ALTER handles legacy rows.
- **`get_current_account` CIDR check** — after the v0.30.0
  read-only enforcement, the handler compares the request's client
  IP against every CIDR in the allowlist using stdlib `ipaddress`.
  Match → proceed; no match → HTTP 401 (not 403, to avoid hinting
  that the same token would work from another IP).
- **Graceful handling of malformed CIDRs** — individual bad entries
  in the stored list are silently skipped during enforcement;
  only if ZERO valid entries match → 401. The JSON API validates
  CIDR syntax at POST time via a Pydantic validator so operators
  get immediate feedback.
- **Admin UI** — mint form gains a textarea (newline / comma
  separated). PAT list shows a `🌐 N IPs` amber pill with the full
  list in the tooltip title.
- **JSON API** — `POST /api/v1/auth/tokens` body accepts
  `ip_allowlist: list[str] | null`.
- **Audit** — `pat.created` detail gains `ip_allowlist_count`.

IPv4 + IPv6 both supported via `ipaddress`. Complements the v0.30.0
read-only flag: scope-by-method + scope-by-network-origin layered
on top of the existing PAT primitive.

8 new tests (no-list works anywhere, matching CIDR succeeds,
non-matching 401, multiple CIDRs any-match, malformed skipped,
all-malformed fails, UI textarea parse, API validator rejects
bad CIDR) — 445 passing, up from 437.

## v0.30.0 — 2026-04-18

PAT read-only flag.

- **`PersonalAccessToken.read_only`** — new Boolean column,
  default False. Auto-ALTER handles legacy rows.
- **`try_authenticate_pat`** now returns `(Account, PAT) | None`
  so the caller can inspect the matched token's flags.
- **`get_current_account`** stashes `pat_id` + `pat_read_only` on
  `request.state` and rejects write-method (POST/PUT/PATCH/DELETE)
  requests with HTTP 403 when the matched PAT is `read_only=True`.
  Invalid/expired/revoked tokens still return 401 — the 401/403
  split cleanly separates authentication from authorization.
- **Admin UI** — mint form gains a "Read-only" checkbox; PAT list
  row shows an amber `read-only` pill alongside status.
- **JSON API** — `POST /api/v1/auth/tokens` body accepts
  `read_only: bool` (defaults to False).
- **Audit** — `pat.created` detail gains a `read_only` boolean.

Scope is HTTP-method-based on purpose: simpler to reason about
than per-endpoint scopes, harder to misconfigure. If a future
release needs finer control, a scope string column can layer on
top without breaking this contract.

7 new tests (RW allows POST, RO allows GET, RO rejects write
methods, invalid-still-401, admin UI mint with flag, account page
pill) — 437 passing, up from 428.

## v0.29.0 — 2026-04-18

PAT hygiene pill on `/admin/account`.

- Active (non-revoked, non-expired) Personal Access Tokens now
  render a `⚠ unused Nd` amber pill next to their status when they
  haven't seen use in ≥ 30 days. "Unused" counts either:
  - last-used-at older than 30 days, OR
  - never used and created more than 30 days ago.
- Hover-title spells out the specific case (`Last used N days ago`
  vs `Never used since creation N days ago`).
- Revoked tokens never get the pill — they're already effectively
  gone and the noise would distract from real issues.
- 30-day threshold is hardcoded; no settings knob yet. The pill
  visually teaches the threshold.

5 new tests (recent use skipped, old never-used flagged, used long
ago flagged, recently created not stale, revoked not flagged) —
428 passing, up from 423.

## v0.28.0 — 2026-04-18

Backup management page — `/admin/ops/backups`.

- **`GET /admin/ops/backups`** — lists files matching
  `nks-wdc-backup-*.zip` in the configured `backup_directory`.
  Shows filename, size (MB), mtime, plus a dir-totals header row.
  Three distinct empty states: "no directory configured",
  "directory not found", "empty directory".
- **`POST /admin/ops/backups/prune-now`** — operator-triggered
  version of the nightly retention sweep. Reuses
  `backup._prune_disk_backups`; emits `backup.pruned` audit
  event with `directory`, `kept`, `removed` detail.
- **`POST /admin/ops/backups/delete`** — per-file delete with
  belt-and-braces path-traversal guard. Filename must be a plain
  basename matching the backup naming convention; any slash or
  prefix mismatch rejects before touching the filesystem.
  Emits `backup.deleted` audit event.
- **Ops card** — gains a "Manage files →" link when the directory
  is configured.
- Restore-from-file remains intentionally out-of-band (matches the
  v0.20.0 stance).

6 new tests (empty-dir listing, files listed, prune removes old,
delete single file, traversal rejection, ops-page link) — 423
passing, up from 417.

## v0.27.0 — 2026-04-18

Scheduled nightly backup + on-disk retention — completes the backup
trilogy (v0.20 download → v0.26 manual-to-disk → v0.27 scheduled).

- **`GlobalPolicy.backup_enabled`** (default False) + **`backup_retention_count`**
  (default 7). Auto-ALTER handles legacy DBs.
- **APScheduler cron** — daily 02:30 UTC (override via env
  `NKS_WDC_BACKUP_CRON`), fires 30 min before the 03:00 retention
  sweep so the ZIP captures pre-sweep state.
- **`backup.run_scheduled_backup()`** — mirrors
  `retention.run_retention` structure. Writes the ZIP via the
  v0.26 `generate_backup_bytes` helper, prunes the oldest files
  beyond `backup_retention_count`, ALWAYS records a
  `SchedulerRun(job="backup")` row (success + skip + error) so
  operators see "job fired but skipped because disabled" on the
  scheduler-runs history page.
- **`/admin/ops` Backup card** — gains last-run pill + size + pruned
  count when at least one scheduled run has fired.
- **Settings UI** — Backup fieldset gets the enable checkbox +
  retention count input alongside the v0.26 directory field.

5 new tests (writes file when enabled, skipped when disabled,
skipped when no dir, prune keeps last-N, settings save) — 417
passing, up from 412.

## v0.26.0 — 2026-04-18

Backup-to-disk — server-side manual snapshot write.

- **`app/backup.py::generate_backup_bytes`** — the v0.20.0 ZIP
  assembly extracted into a pure function (no HTTP concerns)
  returning `(zip_bytes, filename, manifest_dict)`. The download
  endpoint `GET /admin/backup/export.zip` becomes a thin wrapper.
- **`GlobalPolicy.backup_directory`** — server-side path. Blank /
  NULL disables the feature. Auto-ALTER handles legacy DBs.
- **`POST /admin/backup/run-now-to-disk`** — writes the ZIP to
  `<backup_directory>/<filename>`. Emits `backup.saved_to_disk`
  audit event with `path`, `bytes`, per-table `counts`. Redirects
  to `/admin/ops` with a success flash.
- **Settings UI** — new "Backup" fieldset with the directory
  input; changes flow through the existing `settings.updated`
  audit diff.
- **Ops card** — the Backup card gains a "Save to disk" button
  next to "Download ZIP" when the directory is configured.

Retention / pruning of on-disk backups + APScheduler automation
are deferred to a later release — ops-critical but orthogonal to
this scope.

4 new tests (helper shape, disk write, no-dir error flash, audit
event) — 412 passing, up from 408.

## v0.25.0 — 2026-04-18

Dashboard webhook health card.

- The `/admin` dashboard stat-grid gains a 5th card surfacing the
  last-24h webhook delivery health. Shows `Sent`, `Failed`,
  `Failure rate %`. The failed count renders as:
  - plain number when 0 failures;
  - amber `pill pill-warn` when 0 < rate < 5%;
  - red `pill pill-suspended` when rate >= 5%.
- Deep-links: "Triage failed →" appears only when there ARE failures
  and jumps into `/admin/ops/webhooks?status_filter=failed`. The
  empty-state variant (0 deliveries in 24 h) promotes
  `/admin/settings` as a "configure" call-to-action instead.
- Reuses the v0.24.0 aggregation shape. Zero new CSS, zero new JS,
  zero new deps — the 5th card slots into the existing
  `auto-fill, minmax(230px, 1fr)` grid.

3 new tests (empty state, counts + rate render, triage-link
conditional) — 408 passing, up from 405.

## v0.24.0 — 2026-04-18

Webhook delivery stats on `/admin/ops`.

- The Webhooks card gains two new rows — **Sent · 24h** and
  **Failed · 24h** (the failed count renders as a red pill when > 0,
  a plain `0` otherwise) — plus an inline 64 px SVG sparkline of
  deliveries per hour over the last 24 h. The sparkline only
  renders when there's at least one delivery; an all-zero grid
  would be visually dishonest.
- When there are failures, a third deep-link button lights up under
  the card — "Failed →" jumps straight into
  `/admin/ops/webhooks?status_filter=failed` for triage.
- Reuses the audit-sparkline SVG pattern shipped in v0.7.2 —
  zero new CSS, zero new JS, zero new deps.

3 new tests (no-data hides sparkline, counts render correctly,
sparkline present when non-zero) — 405 passing, up from 402.

## v0.23.0 — 2026-04-18

`webhook_deliveries` retention — closes the explicit debt called out
in v0.22.0's CHANGELOG.

- `GlobalPolicy.webhook_delivery_retention_days` (default 30).
  Auto-ALTER handles legacy DBs.
- Nightly retention runner now sweeps `webhook_deliveries` older
  than the configured window via the existing `_batched_delete`
  helper. Summary dict gains `webhook_deliveries_purged`; flash
  text + `retention.manual_run` audit detail pick it up
  automatically.
- Settings UI: "Retention windows" fieldset gains a third
  "Keep webhook deliveries for (days)" input beside the existing
  audit + scheduler retention knobs. Changes flow through the
  existing `settings.updated` audit diff.
- `0 = never purge` escape hatch mirrors v0.13.0 + v0.21.0.

3 new tests (sweep, zero-means-never, settings save + diff) — 402
passing, up from 399.

## v0.22.0 — 2026-04-18

Webhook delivery log — confirm dispatches, debug receiver errors.

- **`webhook_deliveries` table** — `id, url, event_action,
  status_code, duration_ms, error, created_at`. One row per outbound
  POST attempt (both audit-event dispatches and the Settings
  "Send test webhook" button). Auto-ALTER on startup. `status_code
  IS NULL + error populated` for connection-refused / timeouts;
  `status_code` set (including 4xx/5xx) when the HTTP round-trip
  completes.
- **`_post` instrumentation** — timing via `time.monotonic`, status
  capture from `urlopen` response, caught `URLError` / unexpected
  exceptions go into the `error` column (capped at 512 chars).
  Recording is best-effort in a try/except so a failing DB write
  never crashes the worker thread.
- **`/admin/ops/webhooks`** — paginated history page mirroring the
  v0.19.0 scheduler-runs layout. Filter by ok / failed. Pill shows
  `ok · 204` or `failed · 503` so operators see the receiver-side
  status at a glance.
- **`/admin/ops`** — Webhooks card gains a "History →" link
  alongside the existing "Configure →".

Retention of these rows is deferred — rows accumulate today. A follow-
up patch will mirror the v0.21.0 scheduler-runs retention.

6 new tests (success recorded, connection-failure recorded, 5xx
recorded, history page, status filter, ops page link) — 399
passing, up from 393.

## v0.21.1 — 2026-04-18

Test-stability patch.

- `test_kill_others_preserves_current` was order-sensitive in the full
  suite: if `test_2fa_enforcement.py` ran first and left
  `GlobalPolicy.require_2fa_for_admins=True` (e.g. between the save
  and the teardown), the later kill-others POST bounced off the
  `current_user_with_2fa_gate` redirect to
  `/admin/account?flash=totp-required`. The redirect satisfied the
  `status in (302, 303)` assertion but the SQL UPDATE never ran, so
  the synthetic session rows stayed un-revoked and the
  `revoked_at is not None` check failed.
- Fix: extend the `_reset_totp` helper in `tests/test_admin_sessions_mgmt.py`
  to ALSO clear `require_2fa_for_admins` on GlobalPolicy. Every test
  in this file already calls `_reset_totp()`, so one change fixes
  them all. Three consecutive full-suite runs green after the patch.

No production code changed. 393 tests passing (unchanged from v0.21.0).

## v0.21.0 — 2026-04-18

`scheduler_runs` retention — closes the unbounded-growth debt from
v0.18.0 + v0.19.0.

- `GlobalPolicy.scheduler_run_retention_days` (default 90).
  Auto-ALTER handles legacy DBs.
- Nightly retention runner now sweeps `scheduler_runs` older than
  the configured window via the existing `_batched_delete` helper.
  Summary dict gains `scheduler_runs_purged`; the `retention.manual_run`
  audit event detail picks it up automatically; the manual-run flash
  string includes the count alongside audit_events_purged.
- Settings UI: the v0.13.0 "Audit retention" fieldset is renamed
  "Retention windows" and gains a second "Keep scheduler runs for
  (days)" input beside audit_retention_days. Both changes flow
  through the existing `settings.updated` audit diff — no new event
  action.
- `0 = never purge` escape hatch mirrors v0.13.0.

3 new tests (sweep, zero-means-never, settings save + diff) — 393
passing, up from 390.

## v0.20.0 — 2026-04-18

Full-state backup ZIP export — DR-friendly point-in-time dumps.

- **`GET /admin/backup/export.zip`** — one click downloads a ZIP
  containing JSON dumps of every human-editable table plus a
  gzipped NDJSON audit stream (`audit.jsonl.gz`). Bundled files:
  `apps.json`, `releases.json`, `downloads.json`, `accounts.json`,
  `users.json`, `invites_consumed.json`, `scheduler_runs.json`,
  `settings.json`, `audit.jsonl.gz`, `manifest.json`.
- **Manifest with per-file SHA-256** — each entry in `manifest.json`
  carries `{name, size, sha256}` so integrity can be verified
  without trusting the archive envelope.
- **Secret-field omission** — accounts.json explicitly omits
  `password_hash`, `totp_secret`, `totp_recovery_hashes`.
  `admin_sessions` entirely absent (session fingerprints are
  sensitive + ephemeral). A leaked backup is not a credential
  weapon.
- **`backup.exported` audit event** — records who exported, when,
  byte count, and per-table row counts so operators have a trail
  of who pulled a dump.
- **Ops card** — new "Backup" full-width stat card on `/admin/ops`
  with the download link + inline description.

Restore path is intentionally out-of-band (stop container,
`sqlite3 .read` / `psql -f`, restart) — one-click restore needs a
separate transaction/safety story.

6 new tests (magic bytes, file presence, manifest checksums, secret
omission, audit event, auth gate) — 390 passing, up from 384.

## v0.19.0 — 2026-04-18

Scheduler runs history page — browse the audit trail v0.18.0 started
recording.

- New `GET /admin/ops/scheduler` — paginated table of every
  `SchedulerRun` row with job + status + duration columns. Job
  dropdown sourced from distinct values so new job types surface
  automatically. Status filter (`ok` / `failed` / any). Summary
  column uses the same JSON syntax tinting as the audit log;
  error column shows plain stack-trace text inside a `<details>`.
- `/admin/ops` Retention scheduler card grows a "History →" link
  that deep-links into `/admin/ops/scheduler?job=retention`.
- Empty-state covers "no runs yet" + "filter didn't match"
  separately (the retention job fires nightly — first run shows up
  on day 2 of a fresh deploy).

5 new tests (renders rows, empty state, job filter, status filter,
ops page links) — 384 passing, up from 379.

## v0.18.0 — 2026-04-18

Persistent retention last-run tracking — closes the `/admin/retention`
`last_run=None` hardcode + surfaces last run on `/admin/ops`.

- **`scheduler_runs` table** — `id, job, started_at, finished_at,
  duration_ms, summary (JSON), error (Text)`. Auto-ALTER on startup.
  One row per non-skipped retention run (manual + cron). Advisory-
  lock losers don't record — they didn't actually do anything.
- **`run_retention` instrumentation** — wraps the work with
  `time.monotonic()` + writes the row on both success and failure.
  Error-path record goes to a fresh session after rollback so a
  broken pass never masks the original exception.
- **`/admin/retention`** — the `last_run` panel now shows real data:
  started_at, finished_at, duration_ms, summary dict, error string
  if any.
- **`/admin/ops`** — "Retention scheduler" card gains a "Last run"
  row with an `ok` / `failed` pill + human age ("3h 14m ago") + a
  "Purged X snapshots, Y audit rows" summary line.

4 new tests (row written on manual run, retention page shows last
row, ops page surfaces it, duration recorded) — 379 passing, up
from 375.

## v0.17.0 — 2026-04-18

`/admin/ops` — single-glance diagnostics page.

- Read-only operator surface aggregating live state from already-
  existing tables: process (version, uptime, DB backend + size),
  accounts + sessions (total accounts, admin-UI users, active
  sessions), audit (total events + last-24h), retention scheduler
  state + cron, webhook configuration status, and quick links into
  `/metrics`, `/healthz`, `/readyz`.
- Module-level `_PROCESS_START = time.time()` captures boot time so
  uptime is exact; formatted as `Xd Yh Zm`. DB size via `os.stat`
  on the sqlite file (Postgres shows `—` to avoid superuser perms).
- Nav link "Ops" between "Settings" and "JSON".
- 5 new tests (render, version stamp, sessions count, auth gate,
  nav link) — 375 passing, up from 370.

## v0.16.0 — 2026-04-18

Outbound webhook notifications — push-notify for critical audit events.

- **`app/webhooks.py`** — stdlib-only dispatcher (`urllib` + a bounded
  `ThreadPoolExecutor(max_workers=4)`). `fire(event, *, db=None)` is
  non-blocking from the audit write path. `_matches` implements
  prefix semantics: trailing-dot (`session.`) matches children,
  exact (`login.ok`) matches itself only. 5-second HTTP timeout;
  failures logged, never raised.
- **`GlobalPolicy.webhook_url` + `webhook_event_prefixes`** — single
  URL per instance (Slack-compatible incoming webhook format works
  out of the box). Default prefix list: `permission.denied,
  login.failed, session.killed, user.suspended, user.deleted,
  totp.login_failed`. Auto-ALTER handles legacy DBs.
- **`audit.emit` hook** — publishes to the bus AND to webhooks, each
  behind its own try/except so neither can break the audit write.
- **Settings UI** — new "Outbound notifications" fieldset with URL +
  prefixes inputs. `POST /admin/settings/webhook-test` enqueues a
  synthetic `webhook.test` event for immediate feedback.
- **`NKS_WDC_DISABLE_WEBHOOKS=1`** env-flag short-circuits delivery
  (CI isolation).

6 new tests (fire-on-match, skip-on-mismatch, disabled-when-blank,
failure-doesn't-break-audit, wildcard prefix, settings test button)
— 370 passing, up from 364.

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
