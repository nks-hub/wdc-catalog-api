# Global search (`/admin/search`) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** a single `GET /admin/search?q=<term>` that runs substring lookups across users, apps, and audit events, returning a results page grouped by entity type with deep links. Add a search box in the topbar.

**Architecture:** one route handler dispatches 3 small ILIKE queries (each capped at 10 rows) and renders `search.html`. Topbar gets a `<form method="get" action="/admin/search">` with a text input.

**Tech stack:** existing SQLAlchemy layer, Jinja template. No JS, no new CSS beyond layout tweaks.

---

## Task 1 — search route + template + topbar (atomic commit)

**Files:**
- Modify: `app/admin_ui.py` (new GET `/admin/search`)
- New: `app/templates/search.html`
- Modify: `app/templates/base.html` (topbar search form)
- New: `tests/test_global_search.py` (4 tests)

### Handler

Place near other admin GETs in `app/admin_ui.py`:

```python
@router.get("/admin/search", response_class=HTMLResponse)
def admin_global_search(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    q: str = "",
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel, or_
    from .db import Account, App, AuditEvent

    q_clean = (q or "").strip()
    users: list[dict] = []
    apps: list[dict] = []
    events: list[dict] = []

    if q_clean:
        like = f"%{q_clean}%"

        # Users — match email (case-insensitive)
        user_rows = db.scalars(
            _sel(Account)
            .where(Account.email.ilike(like))
            .order_by(Account.id.asc())
            .limit(10)
        ).all()
        users = [
            {"id": u.id, "email": u.email, "role": u.role,
             "suspended": u.suspended_at is not None}
            for u in user_rows
        ]

        # Apps — match id OR display_name
        app_rows = db.scalars(
            _sel(App)
            .where(or_(App.id.ilike(like), App.display_name.ilike(like)))
            .order_by(App.id.asc())
            .limit(10)
        ).all()
        apps = [{"id": a.id, "display_name": a.display_name, "category": a.category}
                for a in app_rows]

        # Audit — match action, resource_id, or actor_email
        evt_rows = db.scalars(
            _sel(AuditEvent)
            .where(or_(
                AuditEvent.action.ilike(like),
                AuditEvent.resource_id.ilike(like),
                AuditEvent.actor_email.ilike(like),
            ))
            .order_by(AuditEvent.id.desc())
            .limit(10)
        ).all()
        events = [
            {
                "id": e.id,
                "created_at": e.created_at.isoformat() if e.created_at else "",
                "action": e.action,
                "actor_email": e.actor_email,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
            }
            for e in evt_rows
        ]

    ctx = base_context(
        request, username,
        q=q_clean,
        users=users,
        apps=apps,
        events=events,
        total=len(users) + len(apps) + len(events),
    )
    return templates.TemplateResponse(request, "search.html", ctx)
```

### Template — `app/templates/search.html`

```html
{% extends "base.html" %}
{% block title %}Search — NKS WDC{% endblock %}
{% block content %}
<section class="section">
  <h1>Search</h1>
  <form method="get" action="/admin/search" class="inline-form">
    <input type="text" name="q" value="{{ q or '' }}" placeholder="Search users, apps, audit events…" autofocus style="min-width: 360px;">
    <button class="btn btn-primary">Search</button>
  </form>

  {% if not q %}
    <p class="muted">Enter a query — matches run substring-case-insensitive across user emails, app ids + names, audit actions + resource ids + actor emails. Top 10 hits per category.</p>
  {% elif total == 0 %}
    <div class="empty-state">
      <div class="empty-icon">🔍</div>
      <h3>No matches for “{{ q }}”</h3>
      <p>Try a shorter substring or a different category keyword.</p>
    </div>
  {% else %}
    <p class="muted">Showing up to top-10 per category. {{ total }} result{{ '' if total == 1 else 's' }}.</p>

    {% if users %}
    <h2>Users ({{ users|length }})</h2>
    <table class="data compact">
      <thead><tr><th>Email</th><th>Role</th><th>Status</th><th></th></tr></thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>{{ u.email }}</td>
          <td><span class="pill pill-role-{{ u.role }}">{{ u.role }}</span></td>
          <td>{% if u.suspended %}<span class="pill pill-suspended">suspended</span>{% else %}<span class="pill pill-ok">active</span>{% endif %}</td>
          <td class="actions"><a class="btn btn-sm" href="/admin/users/{{ u.id }}">open →</a></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}

    {% if apps %}
    <h2>Apps ({{ apps|length }})</h2>
    <table class="data compact">
      <thead><tr><th>Id</th><th>Display name</th><th>Category</th><th></th></tr></thead>
      <tbody>
        {% for a in apps %}
        <tr>
          <td><code>{{ a.id }}</code></td>
          <td>{{ a.display_name or '—' }}</td>
          <td class="muted">{{ a.category }}</td>
          <td class="actions"><a class="btn btn-sm" href="/admin/apps/{{ a.id }}">open →</a></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}

    {% if events %}
    <h2>Audit events ({{ events|length }})</h2>
    <table class="data compact">
      <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Resource</th></tr></thead>
      <tbody>
        {% for e in events %}
        <tr>
          <td class="nowrap">{{ e.created_at[:19] }}</td>
          <td>{{ e.actor_email or '—' }}</td>
          <td><code>{{ e.action }}</code></td>
          <td>
            {% if e.resource_type %}<span class="pill">{{ e.resource_type }}</span>{% endif %}
            {% if e.resource_id %}<code>{{ e.resource_id }}</code>{% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <p><a class="btn btn-ghost" href="/admin/audit?action={{ q }}">See all audit events matching this query →</a></p>
    {% endif %}
  {% endif %}
</section>
{% endblock %}
```

### Topbar — `app/templates/base.html`

Insert a compact search form inside the topbar, between the main `<nav>` and the `{% if username %}` user/logout block. Because the topbar has `display: flex`, add `class="topbar-search"` to a `<form>` wrapping a short `<input>`. Only render when `username` is set (non-login pages).

```html
{% if username %}
  <form method="get" action="/admin/search" class="topbar-search">
    <input type="text" name="q" placeholder="Search…" value="{{ request.query_params.get('q', '') if request and request.url.path == '/admin/search' else '' }}">
  </form>
{% endif %}
```

Place it BEFORE the `<div class="user">` block so the layout reads: brand — nav — search — user. If `base.html` doesn't currently use `{% if username %}` around the user block (it does — you can see it in the existing template), reuse the same condition.

### CSS — `app/static/admin.css`

Append:

```css
.topbar-search {
  display: inline-flex;
  align-items: center;
}
.topbar-search input[type="text"] {
  width: 180px;
  padding: 4px 10px;
  font-size: 0.821rem;
  background: var(--topbar-hover-bg);
  border: 1px solid var(--topbar-border);
  border-radius: var(--radius);
  color: var(--topbar-text);
  transition: background var(--t-fast), border-color var(--t-fast), width var(--t-base);
}
.topbar-search input[type="text"]::placeholder {
  color: var(--topbar-text-muted);
}
.topbar-search input[type="text"]:focus {
  outline: none;
  background: var(--surface);
  color: var(--text);
  border-color: var(--accent);
  width: 260px;
}
@media (max-width: 880px) {
  .topbar-search { display: none; }
}
```

Hide the topbar search on narrow screens — the drawer nav already crowds the bar on mobile.

### Tests — `tests/test_global_search.py`

Borrow the `admin_client` fixture pattern from `tests/test_invites_history_csv.py` (resets 2FA enforcement + TOTP before login).

1. `test_search_empty_query_renders_hint`: GET `/admin/search` (no `q`), status 200, body contains "Enter a query".
2. `test_search_finds_apps_by_id_substring`: seed app `id=search-target-app, display_name=Search Target`, GET `/admin/search?q=target`, body contains `search-target-app`.
3. `test_search_finds_users_by_email`: seed account `search-hit@example.com`, GET `?q=search-hit`, body contains that email.
4. `test_search_finds_audit_by_action`: seed an `AuditEvent(action="search.test.event")`, GET `?q=search.test`, body contains `search.test.event`.
5. `test_no_match_renders_empty_state`: GET `?q=zzz-no-match-xyz-never`, body contains "No matches" + the query in quotes.

## Run

- `pytest tests/test_global_search.py -x -v` — 5 green.
- `pytest -x -q` — 360 total (355 + 5).

## Commit

```
git add -A
git commit -m "feat(admin): global search across users, apps, audit events"
git push origin main
```

## Task 2 — release v0.14.0

- Bump to `0.14.0` in `app/__init__.py` + `pyproject.toml`.
- Prepend CHANGELOG.
- Final `pytest -x -q` green.
- Commit + tag + push + deploy; verify healthz `0.14.0`.

## Constraints

- **No full-text indexing** — ILIKE substring is fine for the current dataset scale (<10k rows each table). Re-evaluate if the user list crosses 100k.
- **No AJAX / live suggestions** — the topbar is a plain GET form. One round-trip, one results page.
- **Admin router's 2FA gate applies** — tests must disable enforcement before running, same as every other recent suite.
