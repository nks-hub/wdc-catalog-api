# Per-user activity timeline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** show a filtered audit event log for the currently-viewed user on `/admin/users/{id}`, turning the detail page into a one-click forensic view.

**Architecture:** extend the existing `admin_user_detail` handler to fetch the last N `AuditEvent` rows where `actor_id = user.id` OR `(resource_type = 'account' AND resource_id = str(user.id))`. Reuse the `.data.compact` + `.audit-row-new` CSS already shipped; no new JS, no SSE, no filter form on this surface.

**Tech stack:** FastAPI handler edit, Jinja template partial, SQLAlchemy OR filter via `sqlalchemy.or_`.

---

## File Structure

| Path | Role |
|---|---|
| `app/admin_ui.py` (edit) | Extend `admin_user_detail` with `user_events` + `user_events_total` context |
| `app/templates/user_detail.html` (edit) | New `<section class="user-activity">` with table + "view full log" link |
| `tests/test_admin_ui_deep.py` (edit) | Regression test: create an event with actor_id=N, assert it renders on `/admin/users/N` |

## Task 1: Plumbing + UI (single atomic commit)

**Files:**
- Modify: `app/admin_ui.py` — find `admin_user_detail` handler (≈line 550 in current revision). After the existing Account lookup, add:
  ```python
  from sqlalchemy import or_
  from .db import AuditEvent

  events_stmt = (
      select(AuditEvent)
      .where(
          or_(
              AuditEvent.actor_id == user.id,
              (AuditEvent.resource_type == "account")
              & (AuditEvent.resource_id == str(user.id)),
          )
      )
      .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
      .limit(20)
  )
  user_events = db.scalars(events_stmt).all()
  user_events_view = [
      {
          "id": e.id,
          "created_at": e.created_at.isoformat() if e.created_at else "",
          "actor_id": e.actor_id,
          "actor_email": e.actor_email,
          "action": e.action,
          "resource_type": e.resource_type,
          "resource_id": e.resource_id,
          "ip": e.ip,
          "detail": e.detail,
      }
      for e in user_events
  ]
  ```
  Pass into the template as `user_events=user_events_view`. Count total via the existing `count_query` helper.

- Modify: `app/templates/user_detail.html` — append a new section before the closing page block (or in whichever natural spot the existing template uses for related info):
  ```html
  <section class="user-activity">
    <header class="section-head">
      <h2>Activity ({{ user_events_total }})</h2>
      <a class="btn btn-ghost" href="/admin/audit?actor_id={{ user.id }}">View full log →</a>
    </header>
    {% if user_events %}
      <table class="data compact">
        <thead>
          <tr><th>When</th><th>Action</th><th>Resource</th><th>IP</th><th>Detail</th></tr>
        </thead>
        <tbody>
          {% for e in user_events %}
          <tr>
            <td class="nowrap">{{ e.created_at[:19] }}</td>
            <td><code>{{ e.action }}</code></td>
            <td>
              {% if e.resource_type %}<span class="pill">{{ e.resource_type }}</span>{% endif %}
              {% if e.resource_id %}<code>{{ e.resource_id }}</code>{% endif %}
            </td>
            <td class="muted">{{ e.ip or '—' }}</td>
            <td>
              {% if e.detail %}<details><summary>view</summary><pre class="detail json-tint">{{ e.detail | json_highlight }}</pre></details>
              {% else %}<span class="muted">—</span>{% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <div class="empty-state">
        <div class="empty-icon">📜</div>
        <h3>No activity yet</h3>
        <p>Events will land here as this user acts or is acted upon.</p>
      </div>
    {% endif %}
  </section>
  ```

- Modify: `tests/test_admin_ui_deep.py` — add one test:
  ```python
  def test_user_detail_shows_activity_timeline(admin_client: TestClient) -> None:
      # Provision an account we can inject events against.
      from app.db import Account, AuditEvent, session_factory
      from sqlalchemy import select as _sel
      from app.auth import hash_password

      with session_factory() as db:
          acct = Account(
              email="timeline-target@example.com",
              password_hash=hash_password("unused"),
              role="user",
          )
          db.add(acct)
          db.flush()
          db.add(AuditEvent(
              actor_id=acct.id,
              actor_email=acct.email,
              action="test.timeline_event",
              resource_type="account",
              resource_id=str(acct.id),
          ))
          db.commit()
          uid = acct.id

      r = admin_client.get(f"/admin/users/{uid}")
      assert r.status_code == 200
      assert "Activity" in r.text
      assert "test.timeline_event" in r.text
      assert "View full log" in r.text
  ```

- [ ] **Step 1: Handler + template + test edits** per the blocks above.
- [ ] **Step 2: Run focused test** — `pytest tests/test_admin_ui_deep.py -x -v`. Green.
- [ ] **Step 3: Run full suite** — `pytest -x -q`. Target 334 (333 + 1 new).
- [ ] **Step 4: Commit** — `feat(users): activity timeline section on user detail page`.

## Task 2: Release v0.9.1

- [ ] Bump `app/__init__.py` + `pyproject.toml` to `0.9.1`.
- [ ] Append CHANGELOG entry.
- [ ] `pytest -x -q` final green check.
- [ ] `git commit` + `git tag -a v0.9.1 -m "..." && git push origin main --tags`.
- [ ] `./scripts/deploy.sh`, verify `/healthz.version == "0.9.1"`.

---

## Constraints

- **One subagent**, two commits total (feat + chore).
- Reuse existing styles (`.data.compact`, `.pill`, `.empty-state`, `.section-head`, `.json-tint`). No new CSS.
- No new dependencies.
- Do not edit `admin.js`, `admin.css`, or any audit-page file.
