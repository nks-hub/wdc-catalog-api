# v0.46.0 — Global Session Kill (Panic Button)

**Goal:** Emergency admin action that revokes every active session (all users) in one click, for use during suspected breach / compromise response.

**Architecture:** New `POST /admin/security/kill-all-sessions`. Requires CSRF, admin role, and a typed confirmation phrase `KILL-ALL` in the form body (anti-misclick). Revokes every `AdminSession.revoked_at IS NULL` AND bumps `Account.token_version` on every Account (invalidating all outstanding JWT bearer tokens). Exempts the caller's own current session so they can land on the success page. Emits `admin.global_session_kill` audit event with the kill-counts; adds the action to `SECURITY_ACTION_ALLOWLIST`.

**Scope:** One route, one template update (small panic-styled form on `/admin/ops`), one audit-action addition, one allowlist addition, tests. No schema changes.

---

## Task 1 — Route + template

**Files:**
- Modify: `app/admin_ui.py` — add `POST /admin/security/kill-all-sessions`
- Modify: `app/templates/ops.html` — add a danger-styled form (red border + confirm input) that posts to the new endpoint

Endpoint behavior:
1. Admin-only auth (reuse existing `current_user` + role check pattern from `admin_users_list`).
2. CSRF via `require_csrf`.
3. Parse form field `confirm: str = Form(...)` — if `confirm != "KILL-ALL"`, redirect back with flash error `"Confirmation phrase mismatch — nothing revoked"`.
4. Count + revoke `AdminSession` rows where `revoked_at IS NULL AND fingerprint != current_fp`.
5. Count + bump `Account.token_version` on every Account where `suspended_at IS NULL` (suspended accounts already can't log in).
6. Emit `admin.global_session_kill` with `detail={"admin_sessions_killed": N, "token_versions_bumped": M}`.
7. Redirect to `/admin/ops` with success flash.

Form markup in `ops.html`:
- Wrapped in its own `<section class="danger">` card
- Heading "🚨 Emergency: revoke all sessions" (no emoji — text only, per code style)
- Explanation: "Revokes every admin session and invalidates every JWT. Your current admin session is preserved. Type `KILL-ALL` to confirm."
- `<input name="confirm" required pattern="KILL-ALL">` + submit button
- POST to `/admin/security/kill-all-sessions`

## Task 2 — Audit allowlist

**File:** `app/observability.py`

Add `"admin.global_session_kill"` to `SECURITY_ACTION_ALLOWLIST` — it's the highest-signal action we have, it MUST ride Prometheus + Grafana.

## Task 3 — Tests

**File:** `tests/test_global_session_kill.py` (new)

- Unauth → 303/401
- Non-admin → 403
- Wrong phrase → 303 back, no revocations
- Correct phrase → 303, every other AdminSession revoked, every Account's `token_version` bumped, audit row lands with `admin.global_session_kill`, detail counts match
- Caller's own session preserved (fingerprint match test)
- Regression: `admin.global_session_kill` in allowlist

## Task 4 — Release

- Bump `app/__init__.py` + `pyproject.toml` → `0.46.0`
- Prepend CHANGELOG entry
- `pytest -x -q`
- Commit: `feat(admin): global session kill panic button`
- Tag `v0.46.0`, push
- `scripts/deploy.sh`
