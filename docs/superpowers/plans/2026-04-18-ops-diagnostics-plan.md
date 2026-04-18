# `/admin/ops` diagnostics page — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** a single operator page surfacing everything you'd want to glance at to decide "is this instance healthy?" — read-only, aggregated from already-existing state. No new schema, no new infra.

**Architecture:** module-level `_PROCESS_START` timestamp captured at import. Handler computes each panel synchronously. Template lays them out in stat cards reusing the dashboard `.stat-card` styling.

**Tech stack:** SQLAlchemy counts + `os.stat` for DB size (SQLite) + `time.time()` diff for uptime. No new deps.

---

## Task 1 — endpoint + template + nav + tests + release (single sweep)

**Files:**
- Modify: `app/admin_ui.py` — module-level `_PROCESS_START = time.time()`; new handler `GET /admin/ops`
- Modify: `app/templates/base.html` — nav link "Ops" between "Settings" and "JSON"
- New: `app/templates/ops.html`
- New: `tests/test_admin_ops.py` (4 tests)
- Release: version bump to 0.17.0 + CHANGELOG + tag + deploy

### Handler

```python
_PROCESS_START = time.time()  # module-level, captured on first import


@router.get("/admin/ops", response_class=HTMLResponse)
def admin_ops(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> HTMLResponse:
    import os
    import time as _time
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select as _sel, func

    from .db import (
        Account, AdminSession, AuditEvent, User, _database_url,
        count_query,
    )
    from . import __version__

    # --- version + uptime ---
    uptime_s = max(0.0, _time.time() - _PROCESS_START)
    uptime_str = _format_uptime(uptime_s)

    # --- sessions ---
    active_sessions = db.scalar(
        _sel(func.count()).select_from(AdminSession).where(
            AdminSession.revoked_at.is_(None)
        )
    ) or 0

    # --- accounts ---
    accounts_total = db.scalar(_sel(func.count()).select_from(Account)) or 0
    admin_users = db.scalar(_sel(func.count()).select_from(User)) or 0

    # --- audit ---
    events_total = db.scalar(_sel(func.count()).select_from(AuditEvent)) or 0
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    events_24h = db.scalar(
        _sel(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= cutoff)
    ) or 0

    # --- DB size ---
    url = _database_url()
    db_size_bytes = None
    db_backend = "postgres"
    if url.startswith("sqlite:"):
        db_backend = "sqlite"
        path = url.replace("sqlite:///", "", 1)
        try:
            db_size_bytes = os.path.getsize(path)
        except OSError:
            db_size_bytes = None

    # --- scheduler ---
    scheduler_on = os.environ.get("NKS_WDC_DISABLE_SCHEDULER") != "1"
    retention_cron = os.environ.get("NKS_WDC_RETENTION_CRON", "0 3 * * *")

    # --- webhooks ---
    from .db import GlobalPolicy
    policy = db.get(GlobalPolicy, 1)
    webhook_enabled = bool(policy and (policy.webhook_url or "").strip())

    ctx = base_context(
        request,
        username,
        version=__version__,
        uptime=uptime_str,
        active_sessions=active_sessions,
        accounts_total=accounts_total,
        admin_users=admin_users,
        events_total=events_total,
        events_24h=events_24h,
        db_backend=db_backend,
        db_size_bytes=db_size_bytes,
        db_size_human=_human_bytes(db_size_bytes) if db_size_bytes is not None else "—",
        scheduler_on=scheduler_on,
        retention_cron=retention_cron,
        webhook_enabled=webhook_enabled,
    )
    return templates.TemplateResponse(request, "ops.html", ctx)


def _format_uptime(secs: float) -> str:
    d, rem = divmod(int(secs), 86400)
    h, rem = divmod(rem, 3600)
    m, _s = divmod(rem, 60)
    if d: return f"{d}d {h}h {m}m"
    if h: return f"{h}h {m}m"
    if m: return f"{m}m {_s}s"
    return f"{int(secs)}s"


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
```

Place `_PROCESS_START` at the top of the module (near the other module-level helpers) and the handler with its companions in the admin-router section.

### Template — `app/templates/ops.html`

```html
{% extends "base.html" %}
{% block title %}Ops — NKS WDC{% endblock %}
{% block content %}
<section class="section">
  <h1>Ops diagnostics</h1>
  <p class="muted">Read-only instance health. Numbers are live at page-render; refresh to re-sample.</p>

  <div class="stat-grid stat-grid-3">
    <div class="stat-card">
      <h3>Process</h3>
      <div class="stat-row"><span>Version</span><b>{{ version }}</b></div>
      <div class="stat-row"><span>Uptime</span><b>{{ uptime }}</b></div>
      <div class="stat-row"><span>DB backend</span><b>{{ db_backend }}</b></div>
      <div class="stat-row"><span>DB size</span><b>{{ db_size_human }}</b></div>
    </div>

    <div class="stat-card">
      <h3>Accounts + sessions</h3>
      <div class="stat-row"><span>Accounts</span><b>{{ accounts_total }}</b></div>
      <div class="stat-row"><span>Admin UI users</span><b>{{ admin_users }}</b></div>
      <div class="stat-row"><span>Active sessions</span><b>{{ active_sessions }}</b></div>
    </div>

    <div class="stat-card">
      <h3>Audit</h3>
      <div class="stat-row"><span>Total events</span><b>{{ events_total }}</b></div>
      <div class="stat-row"><span>Last 24h</span><b>{{ events_24h }}</b></div>
      <div class="stat-sub">
        <a class="btn btn-ghost btn-sm" href="/admin/audit">View log →</a>
        <a class="btn btn-ghost btn-sm" href="/admin/audit/export.jsonl.gz" download>Export JSONL.gz →</a>
      </div>
    </div>
  </div>

  <div class="stat-grid stat-grid-3" style="margin-top: var(--space-4);">
    <div class="stat-card">
      <h3>Retention scheduler</h3>
      <div class="stat-row"><span>Enabled</span>
        <b>{% if scheduler_on %}<span class="pill pill-ok">yes</span>{% else %}<span class="pill pill-warn">no</span>{% endif %}</b>
      </div>
      <div class="stat-row"><span>Cron</span><b><code>{{ retention_cron }}</code></b></div>
      <div class="stat-sub"><a class="btn btn-ghost btn-sm" href="/admin/retention">Policy →</a></div>
    </div>

    <div class="stat-card">
      <h3>Webhooks</h3>
      <div class="stat-row"><span>Configured</span>
        <b>{% if webhook_enabled %}<span class="pill pill-ok">yes</span>{% else %}<span class="pill pill-warn">no</span>{% endif %}</b>
      </div>
      <div class="stat-sub"><a class="btn btn-ghost btn-sm" href="/admin/settings">Configure →</a></div>
    </div>

    <div class="stat-card">
      <h3>Observability</h3>
      <div class="stat-row"><span>Prometheus</span><b><a href="/metrics" target="_blank" rel="noopener">/metrics</a></b></div>
      <div class="stat-row"><span>Healthz</span><b><a href="/healthz" target="_blank" rel="noopener">/healthz</a></b></div>
      <div class="stat-row"><span>Readyz</span><b><a href="/readyz" target="_blank" rel="noopener">/readyz</a></b></div>
    </div>
  </div>
</section>
{% endblock %}
```

### Nav — `app/templates/base.html`

Between the "Settings" link and the "JSON" link, add:
```html
<a href="/admin/ops" class="{% if path.startswith('/admin/ops') %}active{% endif %}">Ops</a>
```

### Tests — `tests/test_admin_ops.py`

Borrow the `admin_client` fixture from `tests/test_global_search.py` (resets 2FA + TOTP + logs in).

1. `test_ops_page_renders`:
   ```python
   r = admin_client.get("/admin/ops")
   assert r.status_code == 200
   assert "Ops diagnostics" in r.text
   for marker in ["Version", "Uptime", "Active sessions", "Total events", "Enabled", "Cron"]:
       assert marker in r.text
   ```

2. `test_ops_page_shows_current_version`:
   ```python
   from app import __version__
   r = admin_client.get("/admin/ops")
   assert __version__ in r.text
   ```

3. `test_ops_page_reflects_active_sessions_count`:
   Insert a single unrevoked AdminSession row directly, fetch the page, assert that a value of at least 1 appears under "Active sessions" (regex match a >0 number next to the label, or just verify `1` or higher — the fixture login itself creates one).

4. `test_ops_page_requires_auth`:
   TestClient without session cookie, GET `/admin/ops`, expect 302/303 redirect containing `/login`.

5. `test_ops_nav_link_visible`:
   Fetch any admin page; assert `href="/admin/ops"` appears in the response.

### Run

- `pytest tests/test_admin_ops.py -x -v` — 5 green.
- `pytest -x -q` — 375 total (370 + 5).

### Commit #1

```
git add -A
git commit -m "feat(admin): /admin/ops diagnostics page with uptime, sessions, DB size"
git push origin main
```

### Release (Commit #2)

- Bump `app/__init__.py` + `pyproject.toml` to `0.17.0`.
- Prepend CHANGELOG entry.
- `pytest -x -q` — still 375.
- `git commit -m "chore: v0.17.0 — /admin/ops diagnostics page"`
- `git tag -a v0.17.0 -m "v0.17.0 — /admin/ops diagnostics"`
- `git push origin main --tags`
- `./scripts/deploy.sh`, verify `/healthz.version == "0.17.0"`.

---

## Constraints

- **Read-only** — no mutations on this page, no forms.
- **No new schema / migrations.**
- **No new deps** — `os.stat`, `time.time()`, SQLAlchemy `func.count()` all stdlib / already-imported.
- **Postgres-safe** — `db_size_bytes = None` for Postgres; template renders `—`. A proper Postgres DB-size query needs superuser perms — not worth it.
- **Performance** — all counts are indexed primary-key scans or equivalent (`func.count()` is fast on SQLite ≤1M rows). Single page render, acceptable.
- No pagination, no refresh button (browser Ctrl-R is enough), no JS.
