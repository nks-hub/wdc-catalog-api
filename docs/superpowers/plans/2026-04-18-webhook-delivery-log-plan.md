# Webhook delivery log — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** record every webhook POST attempt into a `webhook_deliveries` table so operators can confirm webhooks fire, debug receiver-side issues, and see rate-of-failure spikes. Browse at `/admin/ops/webhooks`.

**Architecture:** one new table, one instrumentation change in `app/webhooks.py::_post` that records the attempt outcome, one new handler at `/admin/ops/webhooks` with pagination + status filter (ok / failed), link from `/admin/ops`. Retention of rows deferred — pattern lifts directly from v0.21.0's scheduler_runs retention when we get there.

**Tech stack:** SQLAlchemy model + `session_factory()` in the thread-pool worker.

---

## Task 1 — schema + instrumentation + history page + tests + release (single subagent sweep)

**Files:**
- Modify: `app/db.py` — add `WebhookDelivery` model
- Modify: `app/webhooks.py` — record the attempt in `_post` (success + failure paths)
- Modify: `app/admin_ui.py` — new `GET /admin/ops/webhooks` handler
- New: `app/templates/webhook_deliveries.html`
- Modify: `app/templates/ops.html` — "History →" link under the Webhooks card
- New: `tests/test_webhook_delivery_log.py` (5 tests)
- Release bump to v0.22.0

### Schema

In `app/db.py` near `SchedulerRun`:
```python
class WebhookDelivery(Base):
    """One row per outbound webhook POST attempt.

    Covers both the audit-event-triggered dispatches (via
    ``audit.emit`` → ``webhooks.fire``) and the explicit "Send test
    webhook" button on /admin/settings. Captures the attempt outcome
    so operators can confirm deliveries + spot receiver-side errors.
    """

    __tablename__ = "webhook_deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    event_action: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, index=True)
```

`status_code` NULL means the HTTP round-trip never completed (connection refused, timeout, etc.) — `error` carries the reason. Auto-ALTER handles legacy DBs.

### Instrument `_post`

Current `app/webhooks.py::_post(url, payload)` swallows everything. Expand to record:

```python
def _post(url: str, payload: dict) -> None:
    import time as _time
    from datetime import datetime, timezone

    # Extract event.action from payload for the log row — the payload
    # shape ships as {source, ts, event:{action, ...}}; the test-webhook
    # path uses {source, test:True, event:{action:"webhook.test"}}.
    event_action: str | None = None
    try:
        event_action = (payload.get("event") or {}).get("action")
    except Exception:
        pass

    body = json.dumps(payload, default=str).encode("utf-8")
    req = _urlreq.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "nks-wdc-catalog-api/webhook",
        },
    )
    t0 = _time.monotonic()
    status_code: int | None = None
    err: str | None = None
    try:
        with _urlreq.urlopen(req, timeout=_POST_TIMEOUT) as resp:
            status_code = resp.status
            if resp.status >= 300:
                err = f"HTTP {resp.status}"
                log.warning("webhooks: POST %s returned %s", url, resp.status)
    except URLError as exc:
        err = f"URLError: {exc}"
        log.warning("webhooks: POST %s failed: %s", url, exc)
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        log.warning("webhooks: POST %s unexpected error: %s", url, exc)
    finally:
        duration_ms = int((_time.monotonic() - t0) * 1000)
        _record_delivery(
            url=url, event_action=event_action,
            status_code=status_code, duration_ms=duration_ms, error=err,
        )


def _record_delivery(*, url, event_action, status_code, duration_ms, error):
    """Best-effort: never raises. Called from the thread pool."""
    try:
        from .db import WebhookDelivery, session_factory
        with session_factory() as db:
            db.add(WebhookDelivery(
                url=url,
                event_action=event_action,
                status_code=status_code,
                duration_ms=duration_ms,
                error=(error[:512] if error else None),  # cap pathological traces
            ))
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("webhooks: failed to record delivery: %s", exc)
```

### History page handler

In `app/admin_ui.py`, add after `admin_scheduler_runs`:

```python
@router.get("/admin/ops/webhooks", response_class=HTMLResponse)
def admin_webhook_deliveries(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    status_filter: str = "",  # "" | "ok" | "failed"
    offset: int = 0,
    limit: int = 50,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel
    from .db import WebhookDelivery, count_query

    stmt = _sel(WebhookDelivery)
    if status_filter == "ok":
        stmt = stmt.where(WebhookDelivery.error.is_(None))
    elif status_filter == "failed":
        stmt = stmt.where(WebhookDelivery.error.is_not(None))

    total = count_query(db, stmt)
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    rows = db.scalars(
        stmt.order_by(WebhookDelivery.created_at.desc(), WebhookDelivery.id.desc())
        .offset(offset).limit(limit)
    ).all()

    deliveries = [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else "",
            "url": r.url,
            "event_action": r.event_action,
            "status_code": r.status_code,
            "duration_ms": r.duration_ms,
            "error": r.error,
            "ok": r.error is None,
        }
        for r in rows
    ]

    qs = (f"status_filter={status_filter}&") if status_filter else ""

    ctx = base_context(
        request, username,
        deliveries=deliveries, total=total, offset=offset, limit=limit,
        status_filter=status_filter, qs=qs,
    )
    return templates.TemplateResponse(request, "webhook_deliveries.html", ctx)
```

### Template — `webhook_deliveries.html`

Mirrors `scheduler_runs.html` shape. Columns: When / Action / URL / Status / Duration / Error. Same pagination + empty-state + clear-link pattern.

```html
{% extends "base.html" %}
{% block title %}Webhook deliveries — NKS WDC{% endblock %}
{% block content %}
<section class="section">
  <header class="section-head">
    <h1>Webhook deliveries ({{ total }})</h1>
    <a class="btn" href="/admin/ops">← Ops</a>
  </header>

  <form method="get" class="inline-form">
    <select name="status_filter">
      <option value="" {% if not status_filter %}selected{% endif %}>Any status</option>
      <option value="ok" {% if status_filter == 'ok' %}selected{% endif %}>ok</option>
      <option value="failed" {% if status_filter == 'failed' %}selected{% endif %}>failed</option>
    </select>
    <button class="btn">Filter</button>
    {% if status_filter %}
      <a class="btn btn-ghost" href="/admin/ops/webhooks">clear</a>
    {% endif %}
  </form>

  <table class="data compact">
    <thead>
      <tr><th>When</th><th>Action</th><th>URL</th><th>Status</th><th>Duration</th><th>Error</th></tr>
    </thead>
    <tbody>
      {% for d in deliveries %}
      <tr>
        <td class="nowrap">{{ d.created_at[:19] }}</td>
        <td>{% if d.event_action %}<code>{{ d.event_action }}</code>{% else %}<span class="muted">—</span>{% endif %}</td>
        <td class="muted" style="max-width: 28ch; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="{{ d.url }}">{{ d.url }}</td>
        <td>
          {% if d.ok %}<span class="pill pill-ok">ok{% if d.status_code %} · {{ d.status_code }}{% endif %}</span>
          {% else %}<span class="pill pill-suspended">failed{% if d.status_code %} · {{ d.status_code }}{% endif %}</span>{% endif %}
        </td>
        <td class="nowrap">{% if d.duration_ms is not none %}{{ d.duration_ms }} ms{% else %}<span class="muted">—</span>{% endif %}</td>
        <td>
          {% if d.error %}<details><summary class="muted">view</summary><pre class="detail">{{ d.error }}</pre></details>
          {% else %}<span class="muted">—</span>{% endif %}
        </td>
      </tr>
      {% else %}
      <tr>
        <td colspan="6">
          <div class="empty-state">
            <div class="empty-icon">🪝</div>
            <h3>{% if status_filter %}No deliveries match the filter{% else %}No webhook deliveries recorded yet{% endif %}</h3>
            <p>Configure a webhook URL in Settings; rows land here after the next matching event.</p>
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
    <span class="muted">showing {{ offset + 1 }}–{{ offset + deliveries|length }} of {{ total }}</span>
    {% if offset + limit < total %}
      <a class="btn" href="?{{ qs }}offset={{ offset + limit }}&limit={{ limit }}">next →</a>
    {% endif %}
  </div>
</section>
{% endblock %}
```

### `/admin/ops` Webhooks card — link to history

In `ops.html`, inside the existing "Webhooks" card's `.stat-sub`, add a second link alongside the "Configure →" one:

```html
<div class="stat-sub">
  <a class="btn btn-ghost btn-sm" href="/admin/settings">Configure →</a>
  <a class="btn btn-ghost btn-sm" href="/admin/ops/webhooks">History →</a>
</div>
```

### Tests — `tests/test_webhook_delivery_log.py`

Reuse the mock-server pattern from `tests/test_webhooks.py` (borrow `_Capture` + `mock_webhook` + `_free_port` — copy directly since they're already in the file, or adapt). `admin_client` fixture should disable 2FA enforcement + reset TOTP.

1. `test_delivery_recorded_on_success`:
   - Start mock_webhook server. Config `GlobalPolicy.webhook_url = mock_webhook`.
   - Call `audit.emit(db, ..., action="permission.denied")`; commit.
   - `webhooks.drain(timeout=3)` + `_reset_pool_for_tests()`.
   - Query `WebhookDelivery` — exactly 1 row, `event_action="permission.denied"`, `status_code=204`, `error IS NULL`.

2. `test_delivery_recorded_on_connection_failure`:
   - Point `webhook_url` at an unreachable port (free port with nothing bound).
   - Emit a matching event. Drain.
   - Query `WebhookDelivery` — 1 row, `status_code IS NULL`, `error` starts with `URLError` or similar.

3. `test_delivery_recorded_on_5xx_response`:
   - Spawn a mock server whose `do_POST` returns 503.
   - Emit event. Drain.
   - Query — 1 row, `status_code=503`, `error="HTTP 503"`.

4. `test_history_page_renders_rows(admin_client)`:
   - Seed 3 WebhookDelivery rows directly (2 ok, 1 with error).
   - GET `/admin/ops/webhooks` → 200.
   - Body contains "Webhook deliveries (3)" and two `pill-ok` + one `pill-suspended`.

5. `test_history_page_filter_failed(admin_client)`:
   - Seed 1 ok + 1 failed. GET `?status_filter=failed` — body shows only the failed row.

6. `test_ops_page_links_to_webhook_history(admin_client)`:
   - GET `/admin/ops` — body contains `href="/admin/ops/webhooks"`.

Reset `WebhookDelivery` rows at fixture teardown.

## Run

- `pytest tests/test_webhook_delivery_log.py -x -v` — 6 green.
- `pytest -x -q` — 399 total (393 + 6).

## Commit #1

```
git add -A
git commit -m "feat(webhooks): delivery log + history page at /admin/ops/webhooks"
git push origin main
```

## Task 2 — release v0.22.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.22.0`.
- Prepend CHANGELOG.
- Final `pytest -x -q` green.
- Commit + tag + push + deploy. Verify `/healthz.version == "0.22.0"`.

---

## Constraints

- **Record per-attempt, not per-submit** — `fire()` could theoretically submit without `_post` running (if pool is shut down during test teardown), and that's fine. We record what actually dispatched.
- **Error cap 512 chars** — prevent a pathological connection-error traceback from blowing up the table.
- **No retention yet** — rows accumulate. A follow-up patch will extend `GlobalPolicy.webhook_delivery_retention_days` mirroring the v0.21.0 scheduler-runs pattern. Call this out in the CHANGELOG.
- **No JSON API export** — this is operational data; the full-state backup ZIP (v0.20.0) does not include `webhook_deliveries` today; that's acceptable.
- No new deps, no new CSS.
