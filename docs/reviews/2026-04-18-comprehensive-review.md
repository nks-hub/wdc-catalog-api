# Comprehensive WDC Code Review — 2026-04-18

**Scope:** wdc-catalog-api (v0.48.0 @ 5dc6b7e) + nks-ws (main @ 8332610)
**Reviewer:** autonomous agent
**Methodology:** architectural pass + security/correctness per scope area
**Prior reviews referenced:** `2026-04-18-post-v0.48.0-review.md` (d1e85da, e9dfbd9, 90510dd, nks-ws 23aeea6). Findings already covered there are not re-surfaced.

## Executive summary

- **1 HIGH, 8 MEDIUM, 9 LOW, 5 INFO** (23 findings).
- No CRITICAL issues; the codebase is in good shape overall. Test coverage is extensive (88 test modules, 520+ tests), FK + TIMESTAMPTZ handling is mostly defensive, CSRF coverage on admin mutation routes is complete.
- **Top 3 urgent follow-ups:**
  1. **(HIGH) Event-bus `publish()` calls `asyncio.Queue.put_nowait` from a worker thread** — cross-thread use of `asyncio.Queue` is *not* thread-safe despite the module docstring claim. The drop-oldest branch also holds the registry lock while mutating a foreign loop's queue. Can dead-lock or lose events on Postgres deployments with the Starlette sync thread pool.
  2. **(MEDIUM) Webhook URL has no SSRF allowlist** — admins can point the audit-delivery hook at `http://169.254.169.254/latest/meta-data/` (AWS IMDS), `http://127.0.0.1:9200/`, etc. Internal-only admin, but any admin-takeover path escalates to SSRF.
  3. **(MEDIUM) CI default-token permissions + floating third-party actions** — `ci.yml` has no `permissions:` block (inherits read/write default), and `build.yml` pins `softprops/action-gh-release@v2` by tag. Either a compromised third-party action or a stolen PR-run token can push releases / mutate the repo.

## wdc-catalog-api

### Auth layer

**MEDIUM — admin IP allowlist fails open on DB/parse error (`auth.py:315`)**
The `try/except Exception: pass` around the admin IP allowlist check in `current_user` deliberately fails open ("breaking the gate wide open is better than locking operators out"). This is a defensible operator-safety choice for the allowlist feature, but the fail-open branch swallows **every** exception — including `ValueError` on `ipaddress.ip_network()`, which means a policy row with `admin_ip_allowlist=["not-a-cidr"]` silently disables the allowlist for every request. Concrete fix: restrict the outer catch to `SQLAlchemyError` and let malformed-CIDR rows propagate as 500 (operator sees the misconfig immediately). Alternatively, validate + reject bad CIDRs at save time in `admin_save_settings`.

**LOW — `_EPHEMERAL_DEV_KEY` race on first dev-mode call (`auth.py:60-75`)**
`_secret_key()` lazily initializes the dev-mode ephemeral key with no lock. Under the Starlette sync thread pool two concurrent first-hit requests could both enter the `if _EPHEMERAL_DEV_KEY is None` branch and mint two different keys — one wins the global assignment but the other was already used to sign a cookie in the losing thread. That cookie verifies against the winner's key and fails `BadSignature`, logging the user out. Practical only if the very first request after dev-mode startup races itself; still worth a `threading.Lock` around the init.

**LOW — `refresh_session` middleware referenced but not shown in `auth.py`**
`SESSION_IDLE_TIMEOUT` relies on "re-signing on every request (see `refresh_session`)" per the module docstring, but `grep` finds no `refresh_session` symbol. If middleware doesn't actually re-sign the cookie, the `min(SESSION_MAX_AGE, SESSION_IDLE_TIMEOUT)` check at `auth.py:186` becomes an effective 2h absolute cap, not an idle timeout. Either the middleware exists under a different name and the comment is stale, or the idle timer is silently degraded to an absolute one — both worth verifying and documenting.

### Admin handlers

**MEDIUM — open-redirect guard on `next=` uses `startswith("/admin")`, accepts `/admin.evil.com`-style path values but NOT protocol-relative (`admin_ui.py:3486`)**
`next.startswith("/admin") or next == "/"` — the check correctly rejects `//evil.com` (doesn't start with `/admin`) and `http://…` (same). However, `"/admin\nLocation: evil.com"` embedded in `next` *would* reach `RedirectResponse`; Starlette sanitizes CRLF on the header serializer so an HTTP response-splitting attack doesn't land. But consider `/admin/../../` — `startswith` passes, browser normalizes to `/`, no harm. **The real issue**: line 1224 uses the stricter `next.startswith("/admin/")` (with trailing slash) while line 3486 uses `startswith("/admin")` (no slash). `/admin` (exactly) at line 3486 redirects fine, but `/administer-evil-form` also passes — if such a route ever exists, it's navigable via the toggle-theme redirect. Standardize both guards on `startswith("/admin/") or next == "/admin"`.

**LOW — `admin_save_settings` does not validate webhook URL scheme (`admin_ui.py:2383`)**
`row.webhook_url = webhook_url.strip() or None` — accepts anything the HTML5 `<input type="url">` validation lets through (or nothing if Pydantic validation is skipped on form fields). A `file:///etc/passwd` or `gopher://…` URL would be persisted and handed to `urllib.request.urlopen` — urllib *will* dereference those schemes. Combined with the SSRF finding below, this compounds. Fix: validate `urllib.parse.urlparse(url).scheme in {"http", "https"}` before save.

**INFO — CSRF coverage audit clean**
All 47 admin mutation routes (grep: `@router.(post|delete|put|patch)` in `admin_ui.py`) carry `dependencies=[Depends(require_csrf)]`. No gaps.

**INFO — `admin_restore_snapshot` performs correct `account_id` authorization check before restore (`admin_ui.py:2143`)**
`target.account_id != acct.id` guard prevents an admin from restoring a snapshot belonging to another account's device — the RBAC split between platform admin and account owner is tight here. No cross-tenant bypass.

### Webhooks

**MEDIUM — no SSRF allowlist on webhook URL (`webhooks.py:117`, `admin_ui.py:2383`)**
`urlopen(req, timeout=5.0)` hits whatever URL the admin saved. No denylist for `127.0.0.1`, `10.0.0.0/8`, `169.254.169.254` (AWS IMDS), `::1`, or private DNS. Every audit event (dozens per minute during a permission-denied storm) becomes a free SSRF probe. Admin-only setting, but admin compromise = instant metadata exfil. Concrete fix: resolve the hostname at save time and refuse anything that resolves to RFC1918 / loopback / link-local unless an explicit `NKS_WDC_WEBHOOK_ALLOW_PRIVATE=1` escape hatch is set. Also validate scheme (see LOW above) and enforce max URL length = 512 (already in schema — good).

**LOW — `drain()` in tests calls `_pool.shutdown(wait=True)` with no per-delivery timeout (`webhooks.py:162`)**
A webhook receiver that keeps the connection open past `_POST_TIMEOUT=5s` (e.g. sends response headers then stalls mid-body) would hang `drain()` for 10s (the method's `timeout` arg is **unused** — `ThreadPoolExecutor.shutdown` doesn't accept a timeout in stdlib). Rename the param or actually honour it — current signature is misleading. Not a prod bug (tests only).

**INFO — `URLError` vs `HTTPError` exception order is correct (`webhooks.py:122-126`)**
`HTTPError` is a subclass of `URLError`, so the more-specific handler runs first. This was a real question in the prior review context. No regression.

**INFO — delivery log retention covered**
`GlobalPolicy.webhook_delivery_retention_days` (default 30) + `retention.py` prune path. `WebhookDelivery.created_at` is indexed, so the prune query is cheap.

### Audit pipeline

**HIGH — `event_bus.publish()` calls `asyncio.Queue.put_nowait()` from whatever thread `audit.emit` runs on (`event_bus.py:72-82`, `audit.py:72`)**
`asyncio.Queue` is **not thread-safe** (official Python docs: "not safe for use with multiple threads"). In FastAPI sync routes, `audit.emit` runs inside Starlette's thread pool; each worker thread's `publish()` call hits `put_nowait` on a queue that belongs to the main event loop's thread. CPython's GIL prevents outright memory corruption, but `put_nowait` can silently drop events (the wakeup `_wakeup_next` uses `call_soon_threadsafe` only when `put()` is awaited — the `_nowait` variant does not), and the double `put_nowait` + `get_nowait` dance in the drop-oldest branch holds `self._lock` (a threading.Lock) for the duration — a slow consumer plus high audit throughput can block the lock long enough to stall every other subscriber's publish in a row. Also: the module docstring claims "asyncio.Queue operations are thread-safe on CPython because of the GIL" — this is **incorrect**. Fix: use `loop.call_soon_threadsafe(queue.put_nowait, event)` per subscriber, or switch the bus to a thread-safe primitive (stdlib `queue.Queue` with async bridges, or `anyio.create_memory_object_stream`).

**MEDIUM — security-metric allowlist coverage is not visible from `audit.py`**
`_obs.inc_security_event(action)` is called on every audit emit, but the allowlist lives in `observability.py`. Any new security-adjacent action added in a route handler (e.g. `pat.rotated` in the v0.48 work) must be manually added to the allowlist or it silently never moves the `nks_wdc_security_events_total` counter and any Prometheus alert rules that target it. There's no schema linting or test coverage asserting "every action emitted in the codebase with prefix `login.` / `session.` / `permission.` / `pat.` is in the allowlist". Concrete mitigation: a test that walks all `emit(..., action=…)` literal call sites (AST grep) and asserts each is either in the allowlist or on a declared "non-security" list.

**LOW — `audit.emit` swallows event_bus + webhook + security-metric failures silently with WARNING log only**
The three `try/except Exception` blocks at `audit.py:69-91` each `log.warning(...)` and continue. Correct for the "audit trail must not block the mutation" design goal, but there's no counter or alert when an emit is lost — repeated `event_bus publish failed` lines scrolling through logs are the only signal. Add a `nks_wdc_audit_emit_failures_total{sink="event_bus|webhook|metric"}` counter so ops can alert on sustained failure.

### Backup / restore

**MEDIUM — full-state restore path is not visible from `backup.py`**
`backup.py` is **export-only** (`generate_backup_bytes`, `run_scheduled_backup`). There is no corresponding `restore_backup_bytes` or admin `/admin/backup/restore` endpoint. If the intent is "backups are one-way" (use them for DR by manually restoring the SQLite file) that's a valid design — but worth documenting so operators don't discover mid-incident that the ZIP can't be reimported. If a restore path is planned, prior-review comments about path traversal in ZIP extraction will become load-bearing.

**LOW — `run_scheduled_backup` error path opens a second session without transaction guard (`backup.py:124-137`)**
When the primary session rolls back, the recovery block opens a fresh `session_factory()`, writes a `SchedulerRun` failure row, commits, closes. If **that** also fails, the exception is silently swallowed (`except Exception: pass`). In SQLite pool-exhaustion or FS-full scenarios the operator loses both the backup AND the audit of the failure. Acceptable for the "best-effort recovery" design but worth a warning log instead of bare `pass`.

**INFO — password_hash / totp_secret excluded from `accounts.json` export (`backup.py:209-225`)**
Allowlist, not denylist. If new sensitive columns are added to `Account`, they're automatically absent from the backup — good default. The explicit `# NB: password_hash, totp_secret, totp_recovery_hashes NOT included` comment makes the intent obvious.

### DB models

**LOW — `DeviceHead.current_snapshot_id` uses `ondelete="RESTRICT"` (`db.py:607`)**
Correct to prevent orphaning HEAD, but it means the retention job **must** re-point HEAD before pruning a snapshot — a race where retention deletes a row concurrently with a `set_head` call would raise an integrity error mid-transaction. Not a bug, but worth asserting in a test that retention skips snapshots referenced by any live HEAD. Also: `DeviceSnapshot.parent_snapshot_id` uses `SET NULL`, creating a subtle inconsistency in cascade semantics — parent gone = orphan snapshot stays, HEAD gone = cannot delete. Document the rationale.

**LOW — `User.password_hash` is `String(128)` but bcrypt output is exactly 60 chars (`db.py:191`)**
`Account.password_hash` and `PersonalAccessToken.token_hash` are both `String(128)` — room for future hash upgrades (argon2id output ≈ 96 chars at m=64MB t=3 p=4). Fine. Non-issue; noted so future hash migration doesn't hit column-length surprises.

**INFO — SQLite FK enforcement via PRAGMA (`db.py:77-86`)**
The `@_sa_event.listens_for(_engine, "connect")` ensures every new SQLite connection enables FK enforcement. Without this, all `ondelete=CASCADE` / `SET NULL` declarations would be ignored on SQLite — the connection event handler is load-bearing and correct. Do not remove.

### API catalog serving

**MEDIUM — `build_catalog_document` is re-executed on every cache miss without an in-flight dedup (`api_catalog.py:42`)**
The catalog cache has a 60s TTL. At TTL expiry under load, every concurrent request sees `cached is None`, each spins up a full `build_catalog_document(db)` (walks every app + release + download row), then races to `catalog_response_cache.set("catalog", cached)`. Harmless correctness-wise (last-writer-wins with identical output), but a 50-QPS spike at expiry moment produces 50× DB work. Fix: `cachetools.TTLCache` + a module-level `threading.Lock` with double-checked locking, or move to `asyncio.Future`-based "singleflight". Low-impact on current scale but a trap when the catalog grows to hundreds of apps.

**INFO — ETag stability across rebuilds (M7 fix visible at `api_catalog.py:54-62`)**
The `stable` cache slot for `(etag, generated_at)` correctly keeps the advertised timestamp steady when content didn't actually change. Well-engineered. No regression.

### Tests

**LOW — `_reset_pool_for_tests` + `drain()` pair is used inconsistently across webhook tests**
Three test modules (`test_webhook_retry.py`, `test_webhook_delivery_log.py`, `test_webhooks.py`) all reach into webhook module internals. If two of these run in parallel (pytest-xdist), both share `webhooks._pool` — one test's `drain()` shuts down the pool under the other's feet. Today's `pytest.ini` runs serial, so this is latent — but block-mark the tests with `@pytest.mark.no_xdist` or inject a per-test pool factory before enabling parallel test runs.

**LOW — `conftest.py` sets `NKS_WDC_DISABLE_RATE_LIMITS=1` globally (`conftest.py:14`)**
Every rate-limit regression test must monkey-patch this env var back on. Easy to forget in a new test. Invert the default: rate limits ON, opt-out per-test via fixture. Cost: ~30s audit of existing tests that assumed the old default.

**INFO — 88 test modules is a lot of surface area**
Test isolation via shared tempdir `NKS_WDC_CATALOG_STATE_DIR` (line 10) means the DB file is shared across the whole session. Any test that forgets to clean up rows it created pollutes the next test's view. Current suite passes deterministically, but any new test that queries "all rows of X" is a flake risk. Document the "always filter by test-scoped identifier" pattern in `conftest.py`.

## nks-ws

### C# daemon

**MEDIUM — `PluginLoadContext` is `isCollectible: true` but nothing ever collects it (`PluginLoader.cs:19`)**
The ALC is marked collectible, meaning the infrastructure supports plugin unload — but `PluginLoader` only ever adds to `_plugins`; there's no `UnloadPlugin(id)` path. Collectible ALCs pay a memory/perf cost (no AOT inlining of JIT'd plugin code into the host) for zero benefit if they never unload. Either implement hot-reload + call `context.Unload()` on plugin disable, or flip to `isCollectible: false` to get the performance back. Since `PluginState` supports disable (separate concern) but disable doesn't unload the ALC, there's also a **memory leak risk** per plugin enable/disable cycle if an `UnloadPlugin` is ever added later without auditing static references in `LoadedPlugin.Assembly`.

**MEDIUM — `SiteOrchestrator.ApplyAsync` uses reflection with `.Invoke(...).Result` pattern (`SiteOrchestrator.cs:74-77`)**
`var task = (Task)genMethod.Invoke(...); await task; var resultProp = task.GetType().GetProperty("Result"); var result = resultProp?.GetValue(task);` — awaits the task, then reads `Result` via reflection to check for null. Correct for `Task<T>` where `T` is a ref type, but if the SSL plugin ever changes `GenerateCert` to return `Task` (not `Task<T>`) the reflection falls back to the base `Task.Status` property (there's no `Result` on bare `Task`), and the null check becomes meaningless. Safer: use `dynamic` or a documented `Task<X509Certificate2?>` signature contract in the SDK.

**LOW — `SseService.BroadcastAsync` does not honour a per-client timeout (`SseService.cs:41-42`)**
`client.Response.WriteAsync(message); client.Response.Body.FlushAsync();` — if the remote TCP window is zero, `WriteAsync` blocks indefinitely, holding the semaphore. The slow-client catch at line 45-48 relies on `WriteAsync` eventually throwing — most HTTP servers enforce a keepalive/send timeout, but under Kestrel defaults that's `TimeSpan.MaxValue` for HTTP/1.1 responses. Bound it: `using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct); cts.CancelAfter(TimeSpan.FromSeconds(5)); await client.Response.WriteAsync(message, cts.Token);`.

**INFO — `WebSocketLogStreamer` per-subscriber `BoundedChannel` with `FullMode=DropOldest` is the right shape**
Slow subscribers lose oldest lines instead of blocking the publisher. 2000-line cap per subscriber. Identical semantics to the Python `event_bus.py` — good consistency across language boundaries.

### Plugin SDK

**INFO — SDK not deeply reviewed**
Skim shows standard DI-registration shape; version compat is enforced implicitly by the `SharedAssemblies` list in `PluginLoadContext` (types must come from host ALC to preserve identity). No findings surfaced in the ~2000 LOC scan. SDK public surface is small enough that a dedicated review pass (every exported type + method) would take 30–60m and is worth doing before any v1.0-stamped plugin-SDK release.

### CLI

**MEDIUM — Spectre.Console markup injection via daemon-returned strings (`Program.cs:52`)**
`AnsiConsole.MarkupLine($"[bold]Daemon[/]  [green]running[/]  v{status.GetProperty("version").GetString()}");` — interpolates the daemon's version string directly into a Spectre markup line. If the version ever contains `[` / `]` (e.g. a SemVer pre-release like `1.0.0-rc[1]`, or a future build-metadata tag with brackets), Spectre throws `InvalidOperationException: "Could not find closing tag"` and the whole `wdc status` exits with a stack trace. `Markup.Escape(...)` is already used correctly at lines 2758, 2939 — inconsistent escaping is the bug. Sweep: grep `MarkupLine\(\$"` → wrap every interpolated variable that originates from network/daemon output in `Markup.Escape`.

**LOW — `EnsureConnected` bailout on old daemon is silent (`Program.cs:45`)**
`try { system = await client.GetJsonAsync("/api/system"); } catch { /* old daemon */ }` — correctly degrades gracefully, but a user running an old daemon against a new CLI would benefit from a one-line stderr note on debug runs so support can spot version skew. Non-blocking.

### Frontend

**MEDIUM — Pinia sites store reads bearer token from URL query param `?token=` (`stores/sites.ts:35`)**
`const urlToken = new URLSearchParams(window.location.search).get('token')` — falls back to a URL-embedded token when `window.daemonApi?.getToken?.()` is absent. Tokens in URLs leak into browser history, referer headers (on external link clicks), and any analytics/error-reporting SDK that captures `document.location`. Acceptable if this is a test-only path, but the guard is the truthy token check, not environment-gating. Explicit fix: remove the fallback entirely, or wrap it in `if (import.meta.env.DEV)`. At minimum scrub the token from the URL via `history.replaceState` after first read.

**INFO — no `v-html` usage found (XSS-safe)**
Grep for `v-html|innerHTML|dangerouslySetInnerHTML` across `src/frontend/src` returned zero hits. Element Plus `<el-table>` / `<el-form>` default to text rendering. Good.

**INFO — Element Plus locale handling not surfaced in this scan**
Didn't find obvious locale-injection bugs; skipped deeper check.

### MCP server

**MEDIUM — `daemonClient.request` has no per-request timeout (`daemonClient.ts:93-114`)**
`fetch()` with no `AbortSignal` — a hung daemon (e.g. deadlocked on a plugin invocation) keeps the MCP tool call waiting indefinitely, which ties up the MCP session on the AI-agent side. Claude Desktop's MCP transport has its own timeout, but a 30-second ceiling on daemon requests is standard hygiene. Fix: `const ac = new AbortController(); setTimeout(() => ac.abort(), 30_000); fetch(..., { ...init, signal: ac.signal })`.

**LOW — silent 204 → `null` return bypasses formatted error surface (`daemonClient.ts:131`)**
Many MCP tool handlers call `safe(() => daemonClient.post(...))` and format the return. A 204 silently becomes `null`, which `safe()` stringifies as `"null"` — the user sees a tool call that "worked" with no output. Fine for `start_service` etc. where the action is implicit, but worth documenting per-tool whether a null result is expected.

**INFO — Zod schema discipline is good**
`DomainSchema`, `DatabaseNameSchema`, `PhpVersionSchema`, `ConfirmYesSchema` in `schemas.ts` are tight (regex + length caps + confirmation literal). The recent commit `8332610 fix(mcp-server): tighten ServiceIdSchema with regex + max length` shows the team is actively closing gaps. No new Zod-coverage gaps surfaced across the ~11 tool modules in `src/tools/`.

### Scripts

**LOW — `stage-plugins.mjs` wipes the target directory on every run (`stage-plugins.mjs:31`)**
`rmSync(destDir, { recursive: true, force: true })` — if the script runs with `destDir` accidentally set to a parent directory (e.g. someone refactors `destDir` and introduces a `..` miscalculation), `force: true` + recursive = potential disaster. Defensive guard: assert `destDir.includes('resources/daemon/plugins')` before the `rmSync` call, or use a whitelist-delete (read `readdirSync`, remove each entry individually). Low probability but trivial to harden.

**INFO — other script hygiene is fine**
`verify-electron-release.mjs`, `smoke-packaged-electron.mjs`, `perf-baseline.mjs` scan clean. `submit-defender.ps1` not deeply reviewed — PowerShell isn't in the primary review scope.

### CI workflows

**MEDIUM — `ci.yml` has no `permissions:` block (`ci.yml:1-12`)**
Without an explicit top-level `permissions:` declaration, the default `GITHUB_TOKEN` scope applies — which for public repos is read-only, but for private/org repos typically includes `contents: write`, `actions: write`, etc. depending on the repo's default workflow permissions setting. For a PR-triggered CI run from a fork, an exploited dependency in `dotnet restore` or `npm ci` could use that token to mutate the repo. Fix: add `permissions: contents: read` at the top of `ci.yml` and grant write only on the `package` job that actually needs it.

**MEDIUM — third-party actions pinned by tag, not SHA (`build.yml:95`, `ci.yml: various`)**
`softprops/action-gh-release@v2`, `actions/setup-dotnet@v4`, `actions/setup-node@v4`, `actions/cache@v4`, `actions/upload-artifact@v4` all pin by floating major-version tag. If any maintainer's account is compromised, a malicious push to `v2` would execute in every future CI run with whatever permissions the workflow grants. Industry standard (Dependabot, GitHub Security Lab) is to pin by full 40-char commit SHA with `# v2.0.9` comment and let Dependabot bump SHAs. Action items: run `pin-github-action` or `ratchet` over both workflow files and enable the Dependabot `github-actions` ecosystem for automated SHA bumps.

**INFO — concurrency group on `ci.yml` is correct (`ci.yml:9-11`)**
Canceling in-flight runs on the same ref saves minutes and avoids the double-build races that plagued the repo earlier this year. Good.

## Recommended next tickets

Ordered by severity × effort (descending priority):

1. **(HIGH, M)** Fix thread-safety of `event_bus.publish()` — route every `put_nowait` through `loop.call_soon_threadsafe` or swap to `anyio.create_memory_object_stream`. Also correct the module docstring that claims `asyncio.Queue` is thread-safe. File: `app/event_bus.py`.
2. **(MEDIUM, S)** Add `permissions: contents: read` to top of `.github/workflows/ci.yml`; grant write only where needed per job. Low-risk 10-minute change.
3. **(MEDIUM, M)** Webhook SSRF guard — validate scheme (http/https only) + refuse RFC1918/loopback/link-local at save time in `admin_save_settings`. Escape hatch via env var. Files: `app/admin_ui.py`, `app/webhooks.py`.
4. **(MEDIUM, S)** Pin third-party GitHub Actions by SHA + enable Dependabot `github-actions` updates. Tooling: `pin-github-action`.
5. **(MEDIUM, M)** MCP server `fetch()` timeout — 30s AbortController on every daemon request in `services/mcp-server/src/daemonClient.ts`.
6. **(MEDIUM, M)** Decide plugin-ALC lifecycle story: either implement `UnloadPlugin` and call `context.Unload()` on disable, or flip `isCollectible: false` for perf. File: `src/daemon/NKS.WebDevConsole.Daemon/Plugin/PluginLoader.cs`.
7. **(MEDIUM, S)** Frontend sites store: remove `?token=` URL fallback, or gate behind `import.meta.env.DEV`. File: `src/frontend/src/stores/sites.ts`.
8. **(MEDIUM, S)** CLI Spectre escaping sweep — wrap every `MarkupLine($"…{daemonValue}…")` with `Markup.Escape(...)`. Start at `Program.cs:52`.
9. **(MEDIUM, M)** Security-metric allowlist lint — add a test that asserts every action emitted by `audit.emit(...)` is either whitelisted or explicitly declared non-security.
10. **(MEDIUM, S)** Standardize `next=` guard to `startswith("/admin/")` across `admin_ui.py` (lines 1224 + 3486).
11. **(LOW)** Validate webhook URL scheme at save time (complements #3).
12. **(LOW)** Lock around `_EPHEMERAL_DEV_KEY` init in `auth.py`.
13. **(LOW)** `stage-plugins.mjs` guard before `rmSync`.
14. **(LOW)** Audit `refresh_session` middleware actually exists + re-signs cookies; if missing, either implement or remove the docstring claim in `auth.py`.
15. **(INFO)** SDK v1.0 pass — dedicated review of every public type in `NKS.WebDevConsole.Plugin.SDK`.

## Summary table

| Scope                    | CRITICAL | HIGH | MEDIUM | LOW | INFO |
|--------------------------|----------|------|--------|-----|------|
| wdc-catalog-api          |   0      |  1   |   4    |  6  |  5   |
| nks-ws                   |   0      |  0   |   4    |  3  |  4   |
| CI / tooling / scripts   |   0      |  0   |   2    |  1  |  1   |
| **Total**                | **0**    | **1**| **10** | **10**| **10**|

No blocking issues. The HIGH (event_bus thread-safety) is a real correctness bug but impact is bounded — worst case is dropped SSE events, not data loss. Everything else is defensive hardening that can be scheduled into normal sprint work.
