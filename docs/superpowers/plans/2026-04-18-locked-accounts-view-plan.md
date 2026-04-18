# v0.45.0 — Locked Accounts Admin View

**Goal:** New `/admin/accounts/locked` page aggregating currently-locked accounts (one-click unlock), tying together the v0.43/v0.44 lockout audit signal series on the victim-axis.

**Scope:** Pure UI + one metric-allowlist addition. No schema changes. Existing `/admin/users/{id}/unlock` handler + `user.unlocked` audit action are reused.

---

## Task 1 — Handler + template

**Files:**
- Modify: `app/admin_ui.py` — add `GET /admin/accounts/locked`
- Create: `app/templates/accounts_locked.html`

Handler lists accounts where `locked_until > utcnow()` OR `failed_login_count >= 5` (threshold = signal). Sort by `locked_until DESC NULLS LAST`. Columns: email, role, failed_login_count, locked_until (humanized), last_login_at, unlock button (POST form to `/admin/users/{id}/unlock` with CSRF + hidden `next=/admin/accounts/locked`).

Empty state: "No accounts currently locked ✓" in `--ok` color.

RBAC: admin-only via existing `require_admin` dep.

## Task 2 — Audit allowlist sync

**File:** `app/observability.py`

Add `"user.unlocked"` to `SECURITY_ACTION_ALLOWLIST`. Makes the victim-axis closing-signal visible in Prometheus + Grafana panels.

## Task 3 — Ops card drill-down

**File:** `app/admin_ui.py` (ops handler) + `app/templates/ops.html`

Wire an href `/admin/accounts/locked` on the security-signals card when the count of locked accounts > 0.

## Task 4 — Redirect the existing unlock handler back to locked-view when `next=` provided

**File:** `app/admin_ui.py::admin_unlock`

Accept optional `next: str = Form(default=None)` and redirect there if the value starts with `/admin/` (safe-prefix guard — open-redirect avoidance).

## Task 5 — Tests

**File:** `tests/test_locked_accounts_view.py` (new)

- 401/303 unauth
- 403 non-admin
- Empty state renders
- Locked account shows in table
- Threshold account (`failed_login_count>=5` but `locked_until=NULL`) also shows
- POST unlock with `next=/admin/accounts/locked` → 303 back to the page, account cleared
- Regression: `user.unlocked` in `SECURITY_ACTION_ALLOWLIST`

## Task 6 — Release

- Bump `app/__init__.py` + `pyproject.toml` to `0.45.0`
- Prepend CHANGELOG entry
- `pytest -x -q`
- Commit: `feat(admin): /admin/accounts/locked view + one-click unlock`
- Tag `v0.45.0`, push
- `scripts/deploy.sh` + verify `/readyz`
