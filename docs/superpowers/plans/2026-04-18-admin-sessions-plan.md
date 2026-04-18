# Admin Session Management — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** make admin-UI sessions enumerable + individually revocable. Today the signed cookie is stateless; compromised sessions can only be nuked by rotating the global signing secret. v0.10.0 introduces a per-session store with fingerprint lookup, "kill this session" + "kill all other sessions" UI, and an audit trail.

**Architecture:** `admin_sessions` table keyed on `sha256(signed_cookie_bytes)`. `issue_session()` writes a row with ip + ua; `current_user` looks the fingerprint up on every request (cached via `request.state` within the same request) and rejects if `revoked_at` is set. Kill = UPDATE `revoked_at`; the next request's fingerprint lookup fails and the user bounces to `/login`.

**Tech stack:** SQLAlchemy row + auto-ALTER, FastAPI dependency rewrite, Jinja template, no new JS.

---

## File Structure

| Path | Role |
|---|---|
| `app/db.py` (edit) | New `AdminSession` model |
| `app/auth.py` (edit) | `issue_session(username, *, request=None, db=None) -> str` writes row; `current_user` looks up fingerprint + rejects revoked |
| `app/api_auth_ui.py` (edit) | Pass `request + db` into `issue_session` from login + 2FA confirm handlers |
| `app/admin_ui.py` (edit) | Add `/admin/account/sessions` list + POST kill handlers; extend `admin_account` to pass `sessions` context + current fingerprint |
| `app/templates/account.html` (edit) | "Sessions" section between 2FA and PATs |
| `tests/test_admin_sessions_mgmt.py` (new) | List, kill, kill-others, revoked-session-bounces |

---

## Task 1: schema + auth core (atomic commit)

**Files:** `app/db.py`, `app/auth.py`, `app/api_auth_ui.py`, `tests/test_admin_sessions_mgmt.py`

- [ ] **DB model** — in `app/db.py`, add:
  ```python
  class AdminSession(Base):
      __tablename__ = "admin_sessions"
      __table_args__ = (
          UniqueConstraint("fingerprint", name="uq_admin_sessions_fp"),
      )

      id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
      user_id: Mapped[int] = mapped_column(
          Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
      )
      fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256 hex
      ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
      user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
      created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
      last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, index=True)
      revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
  ```
  The existing `create_all()` auto-ALTER handles legacy DBs — no Alembic migration needed. Import `UniqueConstraint` if not already.

- [ ] **Helpers in `app/auth.py`**:
  ```python
  def _fingerprint(signed_cookie: str) -> str:
      import hashlib
      return hashlib.sha256(signed_cookie.encode("ascii")).hexdigest()
  ```

- [ ] **`issue_session` rewrite**: keep the old signature as a thin wrapper for back-compat, add a new signature that takes optional `request` + `db`:
  ```python
  def issue_session(
      username: str,
      *,
      request: "Request | None" = None,
      db: "Session | None" = None,
  ) -> str:
      signed = _signer.sign(username.encode("utf-8")).decode("ascii")
      if db is not None:
          # Best-effort session row write; a DB failure must not break
          # the login happy path (the cookie is valid regardless — the
          # row just won't track state for /admin/account/sessions).
          try:
              fp = _fingerprint(signed)
              from sqlalchemy import select as _sel
              from .db import AdminSession, User
              user = db.scalar(_sel(User).where(User.username == username))
              if user is not None:
                  ip = request.client.host if request and request.client else None
                  ua = request.headers.get("user-agent") if request else None
                  db.add(AdminSession(
                      user_id=user.id,
                      fingerprint=fp,
                      ip=ip,
                      user_agent=(ua or "")[:256] or None,
                  ))
                  db.flush()
          except Exception as exc:
              import logging
              logging.getLogger(__name__).warning("session row write failed: %s", exc)
      return signed
  ```

- [ ] **`current_user` extension** — accept the cookie, compute fingerprint, look it up in `admin_sessions`, reject if `revoked_at is not None`. Update `last_seen_at` on each hit (best-effort, unthrottled — the table stays small per admin).
  - Legacy sessions (issued before this commit) have no row — treat them as valid but unkillable; write a row on the next hit so the next kill works. This is the back-compat bridge.
  - `current_user` currently doesn't take `db`. Add `Session = Depends(get_session)` to its signature. All callers that use `Depends(current_user)` keep working — FastAPI resolves the nested dep automatically.

- [ ] **Wire login paths** — in `app/api_auth_ui.py`, replace both `issue_session(user.username)` calls (in `login_submit` and `login_2fa_submit`) with `issue_session(user.username, request=request, db=db)`.

- [ ] **Tests** — create `tests/test_admin_sessions_mgmt.py` with:
  1. `test_login_writes_session_row`: log in, assert an `AdminSession` row exists with matching user_id + ip (127.0.0.1 in tests).
  2. `test_revoked_session_bounces_to_login`: log in, mark `revoked_at` in DB, next admin page request must 302 or 303 to `/login`.
  3. `test_legacy_sessions_without_row_still_work`: issue a signed cookie via `_signer.sign(...)` directly (no DB row), set it on a TestClient, verify `/admin` works and that a row was created on first hit.

- [ ] Run `python -m pytest tests/test_admin_sessions_mgmt.py -x -v` — green.
- [ ] Run full suite `python -m pytest -x -q` — 337 total (334 + 3).
- [ ] Commit: `feat(sessions): admin session store with fingerprint revocation`

## Task 2: UI + kill handlers (atomic commit)

**Files:** `app/admin_ui.py`, `app/templates/account.html`, extend `tests/test_admin_sessions_mgmt.py`

- [ ] **Admin UI handlers** — add in `app/admin_ui.py`:
  ```python
  @router.post("/admin/account/sessions/{session_id}/kill",
               dependencies=[Depends(require_csrf)])
  def admin_kill_session(
      request: Request,
      session_id: int,
      username: Annotated[str, Depends(current_user)],
      db: Session = Depends(get_session),
  ) -> RedirectResponse:
      from datetime import datetime, timezone
      from sqlalchemy import select as _sel
      from . import audit as _audit
      from .db import AdminSession, User

      user = db.scalar(_sel(User).where(User.username == username))
      row = db.get(AdminSession, session_id)
      if row is None or row.user_id != (user.id if user else -1):
          return _redirect("/admin/account", "error", "Session not found")
      if row.revoked_at is None:
          row.revoked_at = datetime.now(timezone.utc)
      acct = _admin_account(db, username)
      _audit.emit(
          db, request=request, actor=acct,
          action="session.killed",
          resource_type="admin_session", resource_id=str(session_id),
          detail={"ip": row.ip, "user_agent": row.user_agent},
      )
      return _redirect("/admin/account", "success", "Session killed")


  @router.post("/admin/account/sessions/kill-others",
               dependencies=[Depends(require_csrf)])
  def admin_kill_other_sessions(
      request: Request,
      username: Annotated[str, Depends(current_user)],
      db: Session = Depends(get_session),
  ) -> RedirectResponse:
      from datetime import datetime, timezone
      from sqlalchemy import select as _sel, update as _upd
      from . import audit as _audit
      from .auth import _fingerprint, SESSION_COOKIE
      from .db import AdminSession, User

      user = db.scalar(_sel(User).where(User.username == username))
      current_fp = _fingerprint(request.cookies.get(SESSION_COOKIE, ""))
      q = _upd(AdminSession).where(
          AdminSession.user_id == (user.id if user else -1),
          AdminSession.revoked_at.is_(None),
          AdminSession.fingerprint != current_fp,
      ).values(revoked_at=datetime.now(timezone.utc))
      killed = db.execute(q).rowcount
      acct = _admin_account(db, username)
      _audit.emit(
          db, request=request, actor=acct,
          action="session.killed_others",
          resource_type="admin_session",
          detail={"count": int(killed)},
      )
      return _redirect("/admin/account", "success", f"Killed {killed} other session(s)")
  ```

- [ ] **Extend `admin_account`** to load the user's non-revoked sessions + mark the current one:
  ```python
  # inside admin_account handler
  from .auth import _fingerprint, SESSION_COOKIE
  from .db import AdminSession, User
  user_row = db.scalar(_sel(User).where(User.username == username))
  sessions = []
  if user_row is not None:
      current_fp = _fingerprint(request.cookies.get(SESSION_COOKIE, ""))
      rows = db.scalars(
          _sel(AdminSession)
          .where(AdminSession.user_id == user_row.id)
          .where(AdminSession.revoked_at.is_(None))
          .order_by(AdminSession.last_seen_at.desc())
      ).all()
      sessions = [
          {
              "id": r.id,
              "ip": r.ip,
              "user_agent": r.user_agent,
              "created_at": r.created_at.isoformat() if r.created_at else "",
              "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else "",
              "is_current": r.fingerprint == current_fp,
          }
          for r in rows
      ]
  ```
  Pass `sessions=sessions` into `_render_account(...)` and also into the `base_context(...)` call in the GET handler. Do the same in the mint-PAT + TOTP handlers that already use `_render_account` (add `sessions` kwarg). Cleanest: thread it through `_render_account` itself — have that helper compute `sessions` once from `db + username + request`.

- [ ] **Template** — in `app/templates/account.html`, add a new section between the 2FA block and "Personal access tokens":
  ```html
  <h2>Active sessions</h2>
  <p class="muted">Each browser that signs in gets its own session row. Kill a row to force that browser to log in again.</p>
  {% if sessions %}
  <table class="data compact">
    <thead>
      <tr><th>IP</th><th>Agent</th><th>Signed in</th><th>Last seen</th><th>Actions</th></tr>
    </thead>
    <tbody>
      {% for s in sessions %}
      <tr>
        <td class="nowrap"><code>{{ s.ip or '—' }}</code>{% if s.is_current %} <span class="pill pill-ok">this browser</span>{% endif %}</td>
        <td class="muted" style="max-width: 32ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ s.user_agent or '—' }}</td>
        <td class="nowrap">{{ s.created_at[:19] }}</td>
        <td class="nowrap">{{ s.last_seen_at[:19] }}</td>
        <td class="actions">
          {% if not s.is_current %}
          <form method="post" action="/admin/account/sessions/{{ s.id }}/kill" class="inline" onsubmit="return confirm('Kill this session? The other browser will be signed out.');">
            <input type="hidden" name="_csrf" value="{{ csrf_token }}">
            <button class="btn btn-sm btn-warn">kill</button>
          </form>
          {% else %}
          <span class="muted">—</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% if sessions | selectattr('is_current', 'equalto', false) | list | length %}
  <form method="post" action="/admin/account/sessions/kill-others" class="inline" onsubmit="return confirm('Kill every other active session? Other browsers will be signed out.');" style="margin-top: var(--space-3);">
    <input type="hidden" name="_csrf" value="{{ csrf_token }}">
    <button class="btn btn-warn">Kill all other sessions</button>
  </form>
  {% endif %}
  {% else %}
  <p class="muted">Just this session — no other active browsers.</p>
  {% endif %}
  ```

- [ ] **Extend tests** — in `tests/test_admin_sessions_mgmt.py`:
  4. `test_sessions_page_lists_current`: log in, hit `/admin/account`, assert "Active sessions" and "this browser" in response.
  5. `test_kill_other_session`: log in twice with two TestClients; use client-A to POST `/admin/account/sessions/{B's id}/kill`; assert client-B's next `/admin` request bounces.
  6. `test_kill_others_preserves_current`: spawn 3 sessions; call `/admin/account/sessions/kill-others`; assert the caller's session remains un-revoked, other two get `revoked_at`.

- [ ] Run suite `pytest -x -q` — 340 total (337 + 3).
- [ ] Commit: `feat(sessions): admin UI lists active sessions with kill buttons`

## Task 3: release v0.10.0

- [ ] Bump `app/__init__.py` + `pyproject.toml` to `0.10.0`.
- [ ] Prepend CHANGELOG v0.10.0 section summarizing: new `admin_sessions` store, fingerprint-based revocation, per-session + kill-others UI, `session.killed` + `session.killed_others` audit events.
- [ ] Final `pytest -x -q` — 340 green.
- [ ] Commit + tag:
  ```
  git add -A && git commit -m "chore: v0.10.0 — admin session management (list + kill)"
  git tag -a v0.10.0 -m "v0.10.0 — per-session kill for admin UI"
  git push origin main --tags
  ./scripts/deploy.sh
  curl -s https://wdc.nks-hub.cz/healthz  # expect "version":"0.10.0"
  ```

---

## Constraints + risks

- **Back-compat for legacy signed cookies without a session row** — the `current_user` code path must lazily insert a row on first hit, never 302 legacy users into a redirect loop.
- **`current_user` signature change** — it currently takes only the cookie. Adding `db: Session = Depends(get_session)` is a breaking signature change for tests that instantiate it directly (none should — it's a FastAPI dep). If any test calls `current_user(cookie)` directly, adjust.
- **Race on fingerprint collision** (astronomically unlikely: sha256 of a 200+ char signed string). Unique constraint catches it; the second login just gets 500 → treat as user-visible retry. Not worth elaborate handling.
- **Self-kill**: the "kill this" button is disabled for the current session by markup (the form only renders for non-current rows). Belt-and-braces: the handler also allows self-kill but it means "log out now" — acceptable semantics.

## What NOT to do

- No new JS, no CSS (reuse `.pill-ok`, `.data.compact`, `.btn-warn`, `.btn-sm`).
- No global logout-everywhere button — bulk revocation via `kill-others` is enough.
- No per-session kill on the JWT (bearer) side — that's `Account.token_version` and already shipped.
