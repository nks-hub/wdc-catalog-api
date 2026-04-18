# Global 2FA Enforcement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** add a `require_2fa_for_admins` GlobalPolicy flag that forces any admin-UI account without TOTP to complete setup on their next login before touching any other page.

**Architecture:** one new boolean on `global_policies` (auto-ALTER on startup, default False). A small middleware-ish dependency layered on top of `current_user` — when the flag is on and `Account.totp_enabled` is False, redirect every admin request except the TOTP setup/confirm/logout routes to `/admin/account` with a flash. Logout always passes so a stuck user can get out.

**Tech stack:** SQLAlchemy column add, FastAPI `Depends` wrapper, existing settings form + audit pattern.

---

## File Structure

| Path | Role |
|---|---|
| `app/db.py` (edit) | Add `require_2fa_for_admins` column to `GlobalPolicy` |
| `app/admin_ui.py` (edit) | `current_user_with_2fa_gate` dep (wraps `current_user`); attach to every existing admin route except the 2FA setup/confirm/disable/logout/theme/account-GET allowlist. Extend `admin_save_settings` to persist the new flag + audit it. |
| `app/templates/settings.html` (edit) | New checkbox under the "Access" fieldset |
| `app/templates/account.html` (edit) | If gated, a warning banner above the 2FA section explaining why setup is mandatory |
| `tests/test_2fa_enforcement.py` (new) | Flag on + no TOTP → redirect; flag on + TOTP → normal access; flag off → no redirect; setup routes always accessible |

---

## Task 1: schema + gate (atomic commit)

**Files:** `app/db.py`, `app/admin_ui.py`, `app/templates/account.html` (banner), `tests/test_2fa_enforcement.py`

- [ ] **Schema** — in `GlobalPolicy`:
  ```python
  require_2fa_for_admins: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
  ```
  Auto-ALTER on startup handles legacy DBs.

- [ ] **Allowlist + gate dep** — in `app/admin_ui.py`, add (place near the existing `_admin_account` helper):
  ```python
  # Routes the user can reach even while the 2FA-enforcement gate is
  # active — without these we'd deadlock a freshly-enrolled admin who
  # hasn't paired an authenticator yet.
  _TOTP_GATE_ALLOWLIST_PREFIXES = (
      "/admin/account/totp/",       # setup + confirm + disable POST paths
      "/admin/theme",               # theme toggle is pure cosmetics
      "/static/",                   # JS + CSS
      "/logout",                    # always let the user escape
  )
  _TOTP_GATE_ALLOWLIST_EXACT = {
      "/admin/account",             # the setup form lives on this page
  }

  def current_user_with_2fa_gate(
      request: Request,
      username: Annotated[str, Depends(current_user)],
      db: Session = Depends(get_session),
  ) -> str:
      path = request.url.path
      if path in _TOTP_GATE_ALLOWLIST_EXACT:
          return username
      if any(path.startswith(p) for p in _TOTP_GATE_ALLOWLIST_PREFIXES):
          return username

      from sqlalchemy import select as _sel
      from .db import GlobalPolicy
      policy = db.get(GlobalPolicy, 1)
      if policy is None or not policy.require_2fa_for_admins:
          return username

      acct = _admin_account(db, username)
      if acct.totp_enabled and acct.totp_secret:
          return username

      # Gate activated: bounce to the account page with a flash.
      raise HTTPException(
          status_code=status.HTTP_302_FOUND,
          detail="2FA required",
          headers={"Location": "/admin/account?flash=totp-required"},
      )
  ```

- [ ] **Wire the gate** — FastAPI routers let you attach a dep globally. Cleanest: add a **module-level `Depends(current_user_with_2fa_gate)`** to every `@router.get/post` that currently depends on `current_user` (most already do for side-effect of authentication). Simpler option: edit the APIRouter registration in `app/main.py` so the admin router itself declares a router-level dependency:
  ```python
  admin_router = APIRouter(dependencies=[Depends(current_user_with_2fa_gate)])
  ```
  Router-level deps run on every route under the router. Pick whichever path is minimal given how the router is currently structured — inspect `app/main.py` to see.

  **If that's too invasive**, you can instead modify just `current_user` itself to call the gate logic inline — but that couples unrelated behaviour. Prefer a composable dep on the router.

  **Simplest of all if router surgery is messy**: add a FastAPI middleware that inspects `request.url.path`, reads the cookie, and performs the gate before the handler runs. Middleware signature: `@app.middleware("http")`. You'd put it in `app/main.py` next to the existing security headers middleware.

  Pick the least-invasive path. Document which you chose in the return summary.

- [ ] **Banner on `/admin/account`** — in `app/templates/account.html`, above the "Two-factor authentication" `<h2>`, add:
  ```html
  {% if totp_gate_active and not totp_enabled %}
  <div class="flash flash-error" style="margin-bottom: var(--space-4);">
    <strong>Two-factor authentication is required by instance policy.</strong>
    Set up an authenticator below before continuing to other pages.
  </div>
  {% endif %}
  ```
  The GET `admin_account` handler (and `_render_account`) must pass `totp_gate_active` into context:
  ```python
  policy = db.get(GlobalPolicy, 1)
  totp_gate_active = bool(policy and policy.require_2fa_for_admins)
  ```

- [ ] **Tests** — `tests/test_2fa_enforcement.py` with:
  1. `test_gate_off_allows_admin_paths`: flag False, no TOTP, GET `/admin` → 200.
  2. `test_gate_on_no_totp_redirects`: set flag True in DB, reset TOTP, GET `/admin` → 302 with `Location` header pointing at `/admin/account`.
  3. `test_gate_on_with_totp_allows`: flag True, enable TOTP on the admin account, GET `/admin` → 200.
  4. `test_gate_on_allows_totp_setup_routes`: flag True, no TOTP, POST `/admin/account/totp/setup` returns 200 (not a gate redirect).
  5. `test_gate_on_shows_banner_on_account_page`: flag True, no TOTP, GET `/admin/account` → 200, body contains "Two-factor authentication is required by instance policy".
  6. `test_logout_always_works_under_gate`: flag True, no TOTP, POST `/logout` → 303 `/login`.

  Reset the flag to False at the end of each test (fixture teardown) so later suites aren't affected.

- [ ] Run `pytest tests/test_2fa_enforcement.py -x -v` — 6 green.
- [ ] Run full suite `pytest -x -q` — 346 total (340 + 6).
- [ ] Commit: `feat(2fa): optional global enforcement gate for admin-UI users`

## Task 2: settings UI + audit (atomic commit)

**Files:** `app/admin_ui.py` (extend `admin_save_settings` handler), `app/templates/settings.html`

- [ ] **Settings handler** — in `admin_save_settings` (line ~1662 currently), add `require_2fa_for_admins: Annotated[str, Form()] = ""` to the param list, then:
  ```python
  row.require_2fa_for_admins = bool(require_2fa_for_admins)
  ```
  Include it in the `before` + `after` snapshots so the existing `settings.updated` audit diff picks up changes automatically — no new audit action needed.

- [ ] **Settings template** — in `app/templates/settings.html`, inside the "Access" `<fieldset>`, add under the existing `registration_enabled` checkbox:
  ```html
  <label class="checkbox span-all">
    <input type="checkbox" name="require_2fa_for_admins" value="1" {% if policy.require_2fa_for_admins %}checked{% endif %}>
    Require 2FA for admin UI
    <span class="hint">When on, admins without TOTP configured are forced to pair an authenticator before accessing any admin page except /admin/account and /logout.</span>
  </label>
  ```

- [ ] **Regression test** — append to `tests/test_2fa_enforcement.py`:
  `test_save_settings_toggles_flag`: POST `/admin/settings` with `require_2fa_for_admins=1` then re-load settings page, assert the checkbox is `checked`; then POST without the field, assert it's unchecked. Also assert the `settings.updated` audit event carries the diff.

- [ ] Run `pytest tests/test_2fa_enforcement.py -x -v` — 7 green.
- [ ] Run full `pytest -x -q` — 347 total.
- [ ] Commit: `feat(2fa): settings toggle for global 2FA enforcement`

## Task 3: release v0.11.0

- [ ] Bump `app/__init__.py` + `pyproject.toml` to `0.11.0`.
- [ ] Prepend CHANGELOG v0.11.0 section summarizing: `require_2fa_for_admins` flag on GlobalPolicy, gate dep via middleware (or router), setup-route allowlist, banner, settings checkbox, audit diff via existing `settings.updated`.
- [ ] Final `pytest -x -q` green.
- [ ] Commit + tag:
  ```
  git add -A && git commit -m "chore: v0.11.0 — global 2FA enforcement for admins"
  git tag -a v0.11.0 -m "v0.11.0 — optional global 2FA enforcement"
  git push origin main --tags
  ./scripts/deploy.sh
  curl -s https://wdc.nks-hub.cz/healthz  # expect "version":"0.11.0"
  ```

---

## Constraints

- **Escape hatch**: /logout + /admin/account + /admin/account/totp/* must ALWAYS resolve regardless of gate — a deadlocked admin is worse than an unenforced one.
- **Legacy sessions**: this is policy, not auth — sessions in flight don't need to be invalidated when the flag flips on; they just can't navigate anywhere else until they pair TOTP.
- **Owners**: no special-casing. An owner without 2FA is just as gated as anyone else. That's the point.
- **No new deps**, **no JS**, reuse existing CSS.
