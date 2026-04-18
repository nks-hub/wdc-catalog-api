# Dashboard "Webhook health" card — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** add a compact "Webhook health" tile to the `/admin` dashboard stat-grid showing last-24h sent / failed counts + failure rate + a quick link into `/admin/ops/webhooks?status_filter=failed` when there's anything to triage. Operators see delivery health without navigating to `/admin/ops`.

**Architecture:** extend `admin_dashboard` handler to aggregate the same `WebhookDelivery` 24h window used by `admin_ops` (v0.24.0). Add a fifth stat-card beside the existing Catalog / Users / Devices / Audit trio.

---

## Task 1 — handler + template + tests + release (single subagent sweep)

**Files:**
- Modify: `app/admin_ui.py::admin_dashboard` — aggregate webhook 24h counts
- Modify: `app/templates/dashboard.html` — new stat-card in the grid
- New: `tests/test_dashboard_webhook_card.py` (3 tests)
- Release bump to v0.25.0

### Handler

Inside `admin_dashboard`, after the existing audit sparkline build, add:

```python
# --- webhook delivery health (last 24h) ---
from .db import WebhookDelivery
wh_rows = db.scalars(
    _sel(WebhookDelivery).where(
        WebhookDelivery.created_at >= day_ago.replace(tzinfo=None)
    )
).all()
wh_ok = sum(1 for r in wh_rows if r.error is None)
wh_failed = sum(1 for r in wh_rows if r.error is not None)
wh_total = wh_ok + wh_failed
wh_failure_pct = (wh_failed / wh_total * 100.0) if wh_total else 0.0
webhook_health = {
    "ok": wh_ok,
    "failed": wh_failed,
    "total": wh_total,
    "failure_pct": wh_failure_pct,
    # Classify for the pill: >5% failure over the last day is a real
    # receiver-side problem worth paging; 0-5% is noise; 0 = healthy.
    "status": (
        "ok" if wh_total == 0 or wh_failed == 0 else
        "warn" if wh_failure_pct < 5 else
        "bad"
    ),
}
```

Pass as `webhook_health=webhook_health` into `base_context(...)`.

### Template

In `app/templates/dashboard.html`, find the existing `.stat-grid` block (contains Catalog / Users / Devices / Audit cards). Add a fifth card at the end:

```html
<div class="stat-card">
  <h3>Webhooks · 24h</h3>
  {% if webhook_health.total %}
    <div class="stat-row"><span>Sent</span><b>{{ webhook_health.ok }}</b></div>
    <div class="stat-row"><span>Failed</span>
      <b>
        {% if webhook_health.status == "bad" %}<span class="pill pill-suspended">{{ webhook_health.failed }}</span>
        {% elif webhook_health.status == "warn" %}<span class="pill pill-warn">{{ webhook_health.failed }}</span>
        {% else %}{{ webhook_health.failed }}{% endif %}
      </b>
    </div>
    <div class="stat-row"><span>Failure rate</span>
      <b>{{ "%.1f"|format(webhook_health.failure_pct) }}%</b>
    </div>
    {% if webhook_health.failed %}
    <div class="stat-sub">
      <a class="btn btn-ghost btn-sm" href="/admin/ops/webhooks?status_filter=failed">Triage failed →</a>
    </div>
    {% endif %}
  {% else %}
    <div class="stat-row muted"><span>No deliveries in last 24h</span></div>
    <div class="stat-sub">
      <a class="btn btn-ghost btn-sm" href="/admin/settings">Configure →</a>
    </div>
  {% endif %}
</div>
```

The existing `.stat-grid` auto-flows (shipped in v0.7.2 with `auto-fill, minmax(230px, 1fr)`); adding a fifth card shows as 4-wide on desktop and wraps on narrower screens without any CSS change.

### Tests — `tests/test_dashboard_webhook_card.py`

Reuse the `admin_client` fixture from `tests/test_scheduler_runs_retention.py` (disables 2FA gate, resets TOTP, logs in). Reset `WebhookDelivery` table at fixture teardown.

1. `test_dashboard_no_deliveries_shows_empty_state`:
   - Clean `WebhookDelivery` table.
   - GET `/admin` — 200.
   - Body contains "Webhooks · 24h" and "No deliveries in last 24h".
   - Body does NOT contain "Triage failed".

2. `test_dashboard_shows_sent_and_failed_counts`:
   - Seed 7 ok + 2 failed deliveries (all within last hour).
   - GET `/admin`.
   - Body contains `7` adjacent to "Sent" and `2` adjacent to "Failed" (match via literal fragments, e.g. `>Sent</span><b>7</b>` or `>7</b>`).
   - Failure-rate row renders `22.2%`.

3. `test_dashboard_triage_link_only_when_failures`:
   - Seed only 3 ok deliveries. GET `/admin`. Body does NOT contain `status_filter=failed`.
   - Add 1 failed row. GET again. Body DOES contain `/admin/ops/webhooks?status_filter=failed`.

Direct-insert helper:
```python
from app.db import WebhookDelivery, session_factory
from datetime import datetime, timezone
with session_factory() as db:
    for _ in range(7):
        db.add(WebhookDelivery(url="http://h/hook", event_action="test",
                               status_code=204, duration_ms=5, error=None))
    for _ in range(2):
        db.add(WebhookDelivery(url="http://h/hook", event_action="test",
                               status_code=500, duration_ms=20, error="HTTP 500"))
    db.commit()
```

### Run

- `pytest tests/test_dashboard_webhook_card.py -x -v` — 3 green.
- `pytest -x -q` — 408 total (405 + 3).

### Commit #1

```
git add -A
git commit -m "feat(dashboard): 24h webhook health card"
git push origin main
```

## Task 2 — release v0.25.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.25.0`.
- Prepend CHANGELOG.
- Final `pytest -x -q` green.
- Commit + tag + push + deploy. Verify `/healthz.version == "0.25.0"`.

---

## Constraints

- **No new CSS** — existing `.stat-card` + `.stat-row` + `.pill-suspended` / `.pill-warn` classes already style this.
- **Failure-rate thresholds**: 0% = ok (plain), 0–5% = warn (amber pill), >5% = bad (red pill). Matches what most SRE runbooks treat as "anomalous" for webhook egress.
- **Triage link only when failures exist** — blank card should promote configuration, not a dead filter link.
- **Reuses v0.24.0 logic** — the exact same aggregation shape already ships in `admin_ops`. Duplicating 8 lines of SQL is cleaner than hoisting to a shared helper at this stage.
- No new deps.
