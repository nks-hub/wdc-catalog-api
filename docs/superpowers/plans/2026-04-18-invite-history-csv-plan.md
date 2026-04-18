# Invite-history filter + CSV export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** add email-substring + date-range filters and a CSV download to `/admin/invites/history`. Ship as v0.12.0.

**Architecture:** extend the existing `admin_invites_history` handler with query params, add a matching CSV endpoint at `/admin/invites/history.csv` with the same filters, UI form above the table (same style as `/admin/audit`'s filter form).

**Tech stack:** SQLAlchemy WHERE clauses, `csv.writer` to a `StringIO`, `Response(media_type="text/csv")`. No deps.

---

## Task 1 — filter + CSV + tests (single atomic commit)

**Files:**
- Modify: `app/admin_ui.py` (extend `admin_invites_history` + new `admin_invites_history_csv`)
- Modify: `app/templates/invites_history.html` (filter form + CSV button)
- New: `tests/test_invites_history_csv.py` (4 tests)

### Handler changes

Extend `admin_invites_history`:
```python
def admin_invites_history(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    email: str = "",
    since: str = "",     # ISO date, inclusive
    until: str = "",     # ISO date, inclusive (end-of-day)
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from datetime import datetime, time, timezone
    from sqlalchemy import select as _sel
    from .db import ConsumedInvite, count_query

    stmt = _sel(ConsumedInvite)
    if email:
        stmt = stmt.where(ConsumedInvite.email.ilike(f"%{email.strip()}%"))
    since_dt = _parse_iso_date(since)
    if since_dt:
        stmt = stmt.where(ConsumedInvite.consumed_at >= since_dt)
    until_dt = _parse_iso_date(until)
    if until_dt:
        # Inclusive end-of-day.
        until_dt = datetime.combine(until_dt.date(), time.max).replace(tzinfo=timezone.utc)
        stmt = stmt.where(ConsumedInvite.consumed_at <= until_dt)

    total = count_query(db, stmt)
    rows = db.scalars(stmt.order_by(ConsumedInvite.consumed_at.desc()).limit(500)).all()
    consumed = [ ... same shape as today ... ]

    qs_parts = []
    if email: qs_parts.append(f"email={email}")
    if since: qs_parts.append(f"since={since}")
    if until: qs_parts.append(f"until={until}")
    qs = "&".join(qs_parts)

    ctx = base_context(
        request, username,
        consumed=consumed, total=total,
        email=email, since=since, until=until, qs=qs,
        flash=_pop_flash(flash),
    )
    ...
```

Add helper near the top of the file (after existing helpers):
```python
def _parse_iso_date(raw: str):
    """Parse YYYY-MM-DD → aware UTC datetime at 00:00. Returns None on empty/invalid."""
    from datetime import datetime, timezone
    if not raw or not raw.strip():
        return None
    try:
        return datetime.strptime(raw.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
```

Add CSV endpoint just after the HTML one:
```python
@router.get("/admin/invites/history.csv")
def admin_invites_history_csv(
    username: Annotated[str, Depends(current_user)],
    email: str = "",
    since: str = "",
    until: str = "",
    db: Session = Depends(get_session),
) -> Response:
    import csv, io
    from datetime import datetime, time, timezone
    from sqlalchemy import select as _sel
    from .db import ConsumedInvite

    stmt = _sel(ConsumedInvite)
    # Same filters as the HTML handler; refactor the filter logic into a
    # shared `_invites_history_stmt(stmt, email, since, until)` helper to
    # avoid duplication.
    ... build stmt ...

    rows = db.scalars(stmt.order_by(ConsumedInvite.consumed_at.desc()).limit(10000)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["email", "consumed_at", "account_id", "nonce"])
    for r in rows:
        w.writerow([
            r.email or "",
            r.consumed_at.isoformat() if r.consumed_at else "",
            r.account_id if r.account_id is not None else "",
            r.nonce or "",
        ])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="invite-history.csv"',
            "Cache-Control": "no-store",
        },
    )
```

### Template changes

Above the `<table>`, insert:
```html
<form method="get" class="inline-form">
  <input type="text" name="email" placeholder="email contains…" value="{{ email or '' }}">
  <input type="date" name="since" placeholder="since" value="{{ since or '' }}">
  <input type="date" name="until" placeholder="until" value="{{ until or '' }}">
  <button class="btn">Filter</button>
  {% if email or since or until %}
    <a class="btn btn-ghost" href="/admin/invites/history">clear</a>
  {% endif %}
  <a class="btn btn-ghost" href="/admin/invites/history.csv{% if qs %}?{{ qs }}{% endif %}" download>Export CSV</a>
</form>
```

Leave the existing empty-state row, but improve the copy to reflect the active filter when one is present.

### Tests — `tests/test_invites_history_csv.py`

1. `test_csv_endpoint_returns_all_rows`: seed 3 ConsumedInvite rows, GET `/admin/invites/history.csv`, assert `Content-Type` starts with `text/csv`, body has a header row + 3 data rows.
2. `test_csv_filters_by_email_substring`: seed rows `alice@ex.com`, `bob@ex.com`, GET `/admin/invites/history.csv?email=alice`, assert only the alice row comes back.
3. `test_html_page_filters_by_date_range`: seed rows dated 2026-04-10 and 2026-04-15, GET `/admin/invites/history?since=2026-04-12`, body must contain the later email but not the earlier.
4. `test_csv_rejects_unauthenticated`: TestClient without a session cookie GET → 302/303 redirect to `/login`.

Reuse the `admin_client` fixture pattern from `tests/test_saved_audit_queries.py` (handles TOTP-reset + login).

## Run

- `python -m pytest tests/test_invites_history_csv.py -x -v` — 4 green.
- `python -m pytest -x -q` — 351 total (347 + 4).

## Commit

```
git add -A
git commit -m "feat(invites): history CSV export + email/date filters"
git push origin main
```

## Task 2 — release v0.12.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.12.0`.
- Prepend CHANGELOG entry summarizing the new filters + CSV download + 4 tests.
- Final `pytest -x -q` green.
- `git commit -m "chore: v0.12.0 — invite history CSV export + filters"`
- `git tag -a v0.12.0 -m "v0.12.0 — invite history CSV export + filters"`
- `git push origin main --tags`
- `./scripts/deploy.sh`, verify `/healthz.version == "0.12.0"`.

## Constraints

- Both HTML and CSV handlers apply filters identically — factor the WHERE-building into a `_invites_history_stmt` helper so they can't drift.
- CSV limit: 10 000 rows. If someone actually has that many redeemed invites, they want streaming, not a CSV — ship streaming later.
- Escape CSV cells via `csv.writer` (handles quotes/commas). Don't hand-format.
- No new deps. No new CSS.
