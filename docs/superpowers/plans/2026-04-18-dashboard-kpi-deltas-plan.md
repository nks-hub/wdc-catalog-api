# Dashboard KPI deltas — Implementation Plan

> **For agentic workers:** inline implementation — trivial scope, no subagent needed.

**Goal:** show "+N vs previous 24h" deltas on the dashboard hero KPI and the Webhooks card. Operators see "today busier than yesterday" at a glance without navigating.

**Architecture:** extend the handler to query `AuditEvent` / `WebhookDelivery` counts for the 24h window AND the prior 24h window. Compute delta + direction. Template renders a compact `▲ +12 · ▼ -3` indicator next to the primary number.

---

## Files

- `app/admin_ui.py::admin_dashboard` — two extra COUNT queries (audit prev-24h + webhook prev-24h), pass as `audit_delta` + `webhook_delta` into context
- `app/templates/dashboard.html` — small `<span class="kpi-delta">` next to hero KPI + Webhooks `Sent` row
- `tests/test_dashboard_kpi_deltas.py` (new) — 3 tests

## Handler extension

Compute deltas after the existing sparkline build:
```python
# Previous 24h window: from 48h-ago to 24h-ago
two_days_ago = now - timedelta(hours=47)
prev_audit_count = db.scalar(
    _sel(func.count()).select_from(AuditEvent).where(
        AuditEvent.created_at >= two_days_ago.replace(tzinfo=None),
        AuditEvent.created_at < day_ago.replace(tzinfo=None),
    )
) or 0
audit_delta = stats.audit.events_last_24h - prev_audit_count

prev_webhook_count = db.scalar(
    _sel(func.count()).select_from(WebhookDelivery).where(
        WebhookDelivery.created_at >= two_days_ago.replace(tzinfo=None),
        WebhookDelivery.created_at < day_ago.replace(tzinfo=None),
    )
) or 0
webhook_delta = wh_total - prev_webhook_count
```

## Template additions

Hero KPI card:
```html
<b class="stat-hero-kpi">{{ stats.audit.events_last_24h }}</b>
{% if audit_delta is not none and (webhook_delta is defined or audit_delta != 0) %}
  {% if audit_delta > 0 %}
    <span class="kpi-delta kpi-delta-up">▲ +{{ audit_delta }}</span>
  {% elif audit_delta < 0 %}
    <span class="kpi-delta kpi-delta-down">▼ {{ audit_delta }}</span>
  {% else %}
    <span class="kpi-delta kpi-delta-flat">—</span>
  {% endif %}
  <span class="muted" style="font-size: 0.7em;">vs prior 24h</span>
{% endif %}
```

Webhooks Sent row similar pattern using `webhook_delta`.

CSS (appended to admin.css):
```css
.kpi-delta {
  display: inline-block;
  padding: 2px 6px;
  margin-left: var(--space-2);
  border-radius: var(--radius);
  font-size: 0.7em;
  font-weight: 600;
  vertical-align: middle;
}
.kpi-delta-up { background: color-mix(in srgb, var(--success) 18%, transparent); color: var(--success); }
.kpi-delta-down { background: color-mix(in srgb, var(--danger) 18%, transparent); color: var(--danger); }
.kpi-delta-flat { background: var(--surface-2); color: var(--text-3); }
```

## Tests

1. `test_dashboard_shows_positive_delta` — seed 5 audit events in last hour + 2 in the 24-48h window; assert `▲ +3` in body.
2. `test_dashboard_shows_negative_delta` — seed 2 now + 10 24-48h ago; assert `▼ -8`.
3. `test_dashboard_shows_flat_delta` — seed 3 now + 3 24-48h ago; assert `—` and `vs prior 24h`.

For seeding at a specific past time, construct `AuditEvent(..., created_at=<backdated>)`.
