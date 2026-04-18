# Webhook stats on `/admin/ops` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** enrich the existing Webhooks card on `/admin/ops` with last-24h delivery counts (ok / failed) + a 64 px SVG sparkline of hourly delivery rate. Reuses the audit-sparkline technique already shipped in v0.7.2's dashboard.

**Architecture:** extend the `admin_ops` handler to aggregate `WebhookDelivery` rows into 24 hourly buckets + ok/failed totals. Template adds rows + sparkline inside the existing Webhooks `.stat-card`. No new CSS (existing `.sparkline` + pill classes already style it).

---

## Task 1 — handler extension + template + tests + release (single sweep)

**Files:**
- Modify: `app/admin_ui.py` — extend `admin_ops` handler with `webhook_stats` + `webhook_sparkline` context keys
- Modify: `app/templates/ops.html` — extend Webhooks card
- New: `tests/test_webhook_ops_stats.py` (3 tests)
- Release bump to v0.24.0

### Handler extension

Inside `admin_ops`, after the existing webhook `policy`/`webhook_enabled` lookup, aggregate:

```python
# --- webhook delivery stats (last 24h) ---
from .db import WebhookDelivery
now_hr = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
day_ago_hr = now_hr - timedelta(hours=23)

webhook_rows = db.scalars(
    _sel(WebhookDelivery).where(
        WebhookDelivery.created_at >= day_ago_hr.replace(tzinfo=None)
    )
).all()

webhook_ok_24h = sum(1 for r in webhook_rows if r.error is None)
webhook_failed_24h = sum(1 for r in webhook_rows if r.error is not None)
webhook_total_24h = webhook_ok_24h + webhook_failed_24h

# 24-hour sparkline: total deliveries per hour (ok + failed combined)
wh_buckets = {day_ago_hr + timedelta(hours=i): 0 for i in range(24)}
for r in webhook_rows:
    if r.created_at is None:
        continue
    dt = r.created_at
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    key = dt.replace(minute=0, second=0, microsecond=0)
    if key in wh_buckets:
        wh_buckets[key] += 1
webhook_sparkline = [
    {"hour": k.strftime("%H:00"), "count": v}
    for k, v in sorted(wh_buckets.items())
]
webhook_sparkline_max = max((b["count"] for b in webhook_sparkline), default=0) or 1
```

Pass into context:
```python
webhook_stats={
    "ok_24h": webhook_ok_24h,
    "failed_24h": webhook_failed_24h,
    "total_24h": webhook_total_24h,
},
webhook_sparkline=webhook_sparkline,
webhook_sparkline_max=webhook_sparkline_max,
```

`_sel` + `AuditEvent` pattern is already present in the handler — mirror it for `WebhookDelivery`.

### Template — extend Webhooks card

Current Webhooks card in `ops.html`:
```html
<div class="stat-card">
  <h3>Webhooks</h3>
  <div class="stat-row"><span>Configured</span>
    <b>{% if webhook_enabled %}...{% endif %}</b>
  </div>
  <div class="stat-sub">
    <a class="btn btn-ghost btn-sm" href="/admin/settings">Configure →</a>
    <a class="btn btn-ghost btn-sm" href="/admin/ops/webhooks">History →</a>
  </div>
</div>
```

Replace with:
```html
<div class="stat-card">
  <h3>Webhooks</h3>
  <div class="stat-row"><span>Configured</span>
    <b>{% if webhook_enabled %}<span class="pill pill-ok">yes</span>{% else %}<span class="pill pill-warn">no</span>{% endif %}</b>
  </div>
  <div class="stat-row"><span>Sent · 24h</span><b>{{ webhook_stats.ok_24h }}</b></div>
  <div class="stat-row"><span>Failed · 24h</span>
    <b>{% if webhook_stats.failed_24h %}<span class="pill pill-suspended">{{ webhook_stats.failed_24h }}</span>{% else %}0{% endif %}</b>
  </div>

  {% if webhook_stats.total_24h %}
  {# Mini sparkline — mirrors the dashboard audit sparkline shape #}
  {% set _sp_points = [] %}
  {% for b in webhook_sparkline %}
    {% set x = loop.index0 * 10 + 5 %}
    {% set y = 62 - ((b.count / webhook_sparkline_max * 58) if webhook_sparkline_max else 0) %}
    {% set _ = _sp_points.append(x ~ "," ~ y) %}
  {% endfor %}
  <svg class="sparkline" viewBox="0 0 245 68" preserveAspectRatio="none"
       xmlns="http://www.w3.org/2000/svg"
       aria-label="Webhook deliveries per hour, last 24h">
    <line x1="0" y1="62" x2="245" y2="62"
          stroke="currentColor" stroke-width="1" stroke-dasharray="2 3" opacity="0.12"/>
    <polygon points="5,62 {{ _sp_points | join(' ') }} {{ 5 + (webhook_sparkline|length - 1) * 10 }},62"
             fill="currentColor" opacity="0.12"/>
    <polyline points="{{ _sp_points | join(' ') }}"
              fill="none" stroke="currentColor" stroke-width="1.5"
              stroke-linejoin="round" stroke-linecap="round"/>
    {% for b in webhook_sparkline %}
      {% set cx = loop.index0 * 10 + 5 %}
      {% set cy = 62 - ((b.count / webhook_sparkline_max * 58) if webhook_sparkline_max else 0) %}
      <circle cx="{{ cx }}" cy="{{ cy }}" r="4" fill="transparent">
        <title>{{ b.hour }}: {{ b.count }} delivery{{ '' if b.count == 1 else 'ies' }}</title>
      </circle>
    {% endfor %}
  </svg>
  <div class="spark-axis">
    <span>{{ webhook_sparkline[0].hour }}</span>
    <span class="muted">deliveries/hour</span>
    <span>{{ webhook_sparkline[-1].hour }}</span>
  </div>
  {% endif %}

  <div class="stat-sub">
    <a class="btn btn-ghost btn-sm" href="/admin/settings">Configure →</a>
    <a class="btn btn-ghost btn-sm" href="/admin/ops/webhooks">History →</a>
    {% if webhook_stats.failed_24h %}
      <a class="btn btn-ghost btn-sm" href="/admin/ops/webhooks?status_filter=failed">Failed →</a>
    {% endif %}
  </div>
</div>
```

### Tests — `tests/test_webhook_ops_stats.py`

Borrow `admin_client` fixture from `tests/test_scheduler_runs_retention.py` (disables 2FA gate + resets TOTP).

1. `test_ops_page_no_webhook_deliveries_hides_sparkline`:
   - Start clean (empty `webhook_deliveries` table).
   - GET `/admin/ops` — 200. Body contains `Sent · 24h` and `0` but NOT a `<svg class="sparkline"` element in the Webhooks card context. (Match via the absence of the label text: no `deliveries/hour` in body.)

2. `test_ops_page_shows_24h_counts`:
   - Seed 3 ok deliveries (created_at within last hour) + 2 failed.
   - GET `/admin/ops` — body contains `3` next to `Sent · 24h`; `pill pill-suspended">2` next to Failed.

3. `test_ops_page_renders_sparkline_when_non_zero`:
   - Seed one delivery now. GET `/admin/ops` — body contains `deliveries/hour` (proves the sparkline block rendered).

Direct-insert helper:
```python
from app.db import WebhookDelivery, session_factory
from datetime import datetime, timezone
with session_factory() as db:
    for _ in range(3):
        db.add(WebhookDelivery(url="http://h/hook", event_action="test",
                               status_code=204, duration_ms=5, error=None))
    db.commit()
```

Reset the table at fixture teardown.

### Run

- `pytest tests/test_webhook_ops_stats.py -x -v` — 3 green.
- `pytest -x -q` — 405 total (402 + 3).

### Commit #1

```
git add -A
git commit -m "feat(ops): 24h webhook delivery stats + sparkline on /admin/ops"
git push origin main
```

## Task 2 — release v0.24.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.24.0`.
- Prepend CHANGELOG.
- Final `pytest -x -q`.
- Commit + tag + push + deploy. Verify `/healthz.version == "0.24.0"`.

---

## Constraints

- **No new CSS** — `.sparkline` + `.spark-axis` + pill classes already style the existing audit sparkline on the dashboard.
- **No Chart.js or external lib** — pure SVG mirrors the existing pattern.
- **Sparkline hidden when no data** — the empty 24-hour grid would render as a flat baseline, which is visually dishonest. Only show when there's at least one row.
- **Failed-count pill only when > 0** — zero failures should render as a plain `0`, not an alarmist red.
- No new deps.
