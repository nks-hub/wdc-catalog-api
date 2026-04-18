# Scheduler runs history page — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** browse historical `scheduler_runs` rows at `/admin/ops/scheduler`. Paginated table, status pill (ok / failed), duration, expandable summary + error. Deep-linked from the `/admin/ops` retention card.

**Architecture:** one new GET handler, one new template, link from existing ops page. No schema changes — v0.18.0 shipped the data.

**Tech stack:** SQLAlchemy `count_query` + pagination, existing `.data.compact` + `.json-tint` CSS.

---

## Task 1 — endpoint + template + nav link + tests + release (single sweep)

**Files:**
- Modify: `app/admin_ui.py` — `GET /admin/ops/scheduler` handler
- Modify: `app/templates/ops.html` — "See history" link under the Retention scheduler card
- New: `app/templates/scheduler_runs.html`
- New: `tests/test_scheduler_runs_history.py` (4 tests)
- Release: v0.19.0 bump + CHANGELOG + tag + deploy

### Handler

```python
@router.get("/admin/ops/scheduler", response_class=HTMLResponse)
def admin_scheduler_runs(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    job: str = "",
    status_filter: str = "",  # "" | "ok" | "failed"
    offset: int = 0,
    limit: int = 50,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel
    from .db import SchedulerRun, count_query

    stmt = _sel(SchedulerRun)
    if job:
        stmt = stmt.where(SchedulerRun.job == job)
    if status_filter == "ok":
        stmt = stmt.where(SchedulerRun.error.is_(None))
    elif status_filter == "failed":
        stmt = stmt.where(SchedulerRun.error.is_not(None))

    total = count_query(db, stmt)
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    rows = db.scalars(
        stmt.order_by(SchedulerRun.started_at.desc(), SchedulerRun.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()

    runs = [
        {
            "id": r.id,
            "job": r.job,
            "started_at": r.started_at.isoformat() if r.started_at else "",
            "finished_at": r.finished_at.isoformat() if r.finished_at else "",
            "duration_ms": r.duration_ms,
            "summary": r.summary,
            "error": r.error,
            "ok": r.error is None,
        }
        for r in rows
    ]

    qs_parts = []
    if job: qs_parts.append(f"job={job}")
    if status_filter: qs_parts.append(f"status_filter={status_filter}")
    qs = ("&".join(qs_parts) + "&") if qs_parts else ""

    # Distinct job names for the filter dropdown
    job_names = db.scalars(
        _sel(SchedulerRun.job).distinct().order_by(SchedulerRun.job.asc())
    ).all()

    ctx = base_context(
        request, username,
        runs=runs,
        total=total,
        offset=offset,
        limit=limit,
        job=job,
        status_filter=status_filter,
        qs=qs,
        job_names=list(job_names),
    )
    return templates.TemplateResponse(request, "scheduler_runs.html", ctx)
```

Place the handler in `app/admin_ui.py` near `admin_ops`. Admin-router-level 2FA gate applies automatically.

### Template — `app/templates/scheduler_runs.html`

```html
{% extends "base.html" %}
{% block title %}Scheduler runs — NKS WDC{% endblock %}
{% block content %}
<section class="section">
  <header class="section-head">
    <h1>Scheduler runs ({{ total }})</h1>
    <a class="btn" href="/admin/ops">← Ops</a>
  </header>

  <form method="get" class="inline-form">
    <select name="job">
      <option value="">All jobs</option>
      {% for j in job_names %}
        <option value="{{ j }}" {% if j == job %}selected{% endif %}>{{ j }}</option>
      {% endfor %}
    </select>
    <select name="status_filter">
      <option value="" {% if not status_filter %}selected{% endif %}>Any status</option>
      <option value="ok" {% if status_filter == 'ok' %}selected{% endif %}>ok</option>
      <option value="failed" {% if status_filter == 'failed' %}selected{% endif %}>failed</option>
    </select>
    <button class="btn">Filter</button>
    {% if job or status_filter %}
      <a class="btn btn-ghost" href="/admin/ops/scheduler">clear</a>
    {% endif %}
  </form>

  <table class="data compact">
    <thead>
      <tr><th>Job</th><th>Started</th><th>Status</th><th>Duration</th><th>Summary</th><th>Error</th></tr>
    </thead>
    <tbody>
      {% for r in runs %}
      <tr>
        <td><code>{{ r.job }}</code></td>
        <td class="nowrap">{{ r.started_at[:19] }}</td>
        <td>
          {% if r.ok %}<span class="pill pill-ok">ok</span>
          {% else %}<span class="pill pill-suspended">failed</span>{% endif %}
        </td>
        <td class="nowrap">{% if r.duration_ms is not none %}{{ r.duration_ms }} ms{% else %}<span class="muted">—</span>{% endif %}</td>
        <td>
          {% if r.summary %}<details><summary>view</summary><pre class="detail json-tint">{{ r.summary | json_highlight }}</pre></details>
          {% else %}<span class="muted">—</span>{% endif %}
        </td>
        <td>
          {% if r.error %}<details><summary class="muted">view</summary><pre class="detail">{{ r.error }}</pre></details>
          {% else %}<span class="muted">—</span>{% endif %}
        </td>
      </tr>
      {% else %}
      <tr>
        <td colspan="6">
          <div class="empty-state">
            <div class="empty-icon">⏲</div>
            <h3>{% if job or status_filter %}No runs match the filter{% else %}No scheduler runs recorded yet{% endif %}</h3>
            <p>Retention runs nightly at 03:00 UTC — rows land here on the next pass.</p>
          </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="pager">
    {% if offset > 0 %}
      <a class="btn" href="?{{ qs }}offset={{ [offset - limit, 0]|max }}&limit={{ limit }}">← prev</a>
    {% endif %}
    <span class="muted">showing {{ offset + 1 }}–{{ offset + runs|length }} of {{ total }}</span>
    {% if offset + limit < total %}
      <a class="btn" href="?{{ qs }}offset={{ offset + limit }}&limit={{ limit }}">next →</a>
    {% endif %}
  </div>
</section>
{% endblock %}
```

### `/admin/ops` wire-up

In `app/templates/ops.html`, inside the "Retention scheduler" card, add below the existing `.stat-sub`:

```html
<div class="stat-sub">
  <a class="btn btn-ghost btn-sm" href="/admin/retention">Policy →</a>
  <a class="btn btn-ghost btn-sm" href="/admin/ops/scheduler?job=retention">History →</a>
</div>
```

Replace the existing single-link `.stat-sub` with the two-link version. Watch for pre-existing markup differences and keep the wrapping div intact.

### Tests — `tests/test_scheduler_runs_history.py`

Borrow the `admin_client` fixture from `tests/test_retention_last_run.py` (resets 2FA + TOTP + logs in).

1. `test_history_page_renders_with_rows`:
   - Seed 3 SchedulerRun rows with varying status (2 ok, 1 with error).
   - GET `/admin/ops/scheduler` → 200.
   - Body contains "Scheduler runs (3)", two `pill pill-ok`, one `pill pill-suspended`.

2. `test_history_empty_state`:
   - Reset table to empty.
   - GET `/admin/ops/scheduler` → 200.
   - Body contains "No scheduler runs recorded yet".

3. `test_history_job_filter`:
   - Seed rows with jobs `retention` and `blob-cleanup` (just make up a name).
   - GET `?job=retention` → body contains retention rows but not the other.

4. `test_history_status_filter_failed`:
   - Seed 1 ok + 1 failed row.
   - GET `?status_filter=failed` → body contains only the failed row (assert via pill-suspended count).

5. `test_ops_page_links_to_scheduler_history`:
   - GET `/admin/ops`.
   - Body contains `href="/admin/ops/scheduler?job=retention"`.

Reset `SchedulerRun` at fixture teardown (DELETE) so suites don't cross-contaminate.

### Run

- `pytest tests/test_scheduler_runs_history.py -x -v` — 5 green.
- `pytest -x -q` — 384 total (379 + 5).

### Commit #1

```
git add -A
git commit -m "feat(ops): scheduler runs history page at /admin/ops/scheduler"
git push origin main
```

### Release — Commit #2

- Bump `app/__init__.py` + `pyproject.toml` to `0.19.0`.
- Prepend CHANGELOG.
- Final `pytest -x -q`.
- Commit + tag + push + deploy. Verify healthz `0.19.0`.

---

## Constraints

- **No schema changes** — `scheduler_runs` shipped in v0.18.0.
- **Pagination via offset/limit** — matches the audit page pattern; don't switch to cursor-based.
- **Filter dropdown sourced from distinct `job` names** — if the catalog grows new job types (blob cleanup, etc.) they show up automatically.
- **Error rendering NOT syntax-tinted** — plain `<pre class="detail">`; errors are stack traces, not JSON.
- **No retention-of-retention-rows** — still too early; revisit when rows cross 10k.
- No JS, no new CSS beyond what already exists.
