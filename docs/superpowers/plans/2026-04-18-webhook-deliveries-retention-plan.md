# `webhook_deliveries` retention — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** close the v0.22.0 debt — rows in `webhook_deliveries` accumulate without bound today. Add a configurable retention window that mirrors `scheduler_run_retention_days` exactly (v0.21.0 pattern).

**Architecture:** one new column on `GlobalPolicy`, one extra `_batched_delete` call in `_do_retention`, one summary-key extension, one settings-form field in the existing "Retention windows" fieldset.

---

## Task 1 — schema + runner + settings + tests + release (single sweep)

**Files:**
- Modify: `app/db.py` — add column
- Modify: `app/retention.py` — extend `_do_retention` sweep + return key + skipped-branch key
- Modify: `app/admin_ui.py` — `admin_save_settings` Form param + before/after dicts + GET handler policy dict + flash text
- Modify: `app/templates/settings.html` — third input inside "Retention windows" fieldset
- New: `tests/test_webhook_deliveries_retention.py` (3 tests)
- Release v0.23.0

### Schema

On `GlobalPolicy` after `scheduler_run_retention_days`:
```python
webhook_delivery_retention_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
```

Default 30d — webhook deliveries are high-churn operational telemetry, don't need a full quarter like scheduler runs. Auto-ALTER handles legacy DBs.

### Runner — `_do_retention` in `app/retention.py`

After the existing `scheduler_runs` sweep, add:

```python
webhook_retain_days = policy_row.webhook_delivery_retention_days if policy_row else 30
if webhook_retain_days is None:
    webhook_retain_days = 30
webhook_purged = 0
if webhook_retain_days > 0:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        days=webhook_retain_days
    )
    from .db import WebhookDelivery
    webhook_purged = _batched_delete(
        session,
        WebhookDelivery,
        WebhookDelivery.created_at < cutoff,
    )
```

Extend the return dict with `"webhook_deliveries_purged": webhook_purged`.

Also patch the `skipped: True` empty-summary return in `run_retention()` to include `"webhook_deliveries_purged": 0`.

Extend the `admin_retention_run_now` flash text in `admin_ui.py` with `, webhook_deliveries_purged={summary.get('webhook_deliveries_purged', 0)}`.

### Settings handler + template

1. **Handler**: add `webhook_delivery_retention_days: Annotated[int, Form()] = 30` to `admin_save_settings`. Append to `before` and `after` dicts. Set `row.webhook_delivery_retention_days = max(0, min(int(webhook_delivery_retention_days), 3650))`. Include in the GET handler's `policy` dict.

2. **Template** (`app/templates/settings.html`): inside the "Retention windows" fieldset, add below the existing two fields:
   ```html
   <label>Keep webhook deliveries for (days)
     <input type="number" name="webhook_delivery_retention_days" value="{{ policy.webhook_delivery_retention_days }}" min="0" max="3650">
     <span class="hint">Nightly sweep drops rows from <code>/admin/ops/webhooks</code> older than this. 0 = keep forever.</span>
   </label>
   ```

### Tests — `tests/test_webhook_deliveries_retention.py`

Autouse `_bootstrap_db` fixture (pattern from `tests/test_scheduler_runs_retention.py`).

1. `test_sweep_purges_old_webhook_deliveries`:
   - Seed three `WebhookDelivery` rows: created_at 90d ago, 10d ago, now.
   - Set `GlobalPolicy.webhook_delivery_retention_days = 30`.
   - Call `run_retention(db)` directly (session injected).
   - Assert `summary["webhook_deliveries_purged"] == 1`.
   - Assert two rows remain.

2. `test_zero_means_never_purge`:
   - Seed one row `created_at = now - 2000d`. Set `webhook_delivery_retention_days = 0`.
   - Run retention. Assert `summary["webhook_deliveries_purged"] == 0` + row still exists.

3. `test_settings_save_persists_window(admin_client)`:
   - POST `/admin/settings` with `webhook_delivery_retention_days=14`. Verify `GlobalPolicy.webhook_delivery_retention_days == 14`. Verify `settings.updated` audit detail carries `{"from": 30, "to": 14}`.

Direct-insert pattern:
```python
from app.db import WebhookDelivery, session_factory
from datetime import datetime, timezone, timedelta

with session_factory() as db:
    db.add(WebhookDelivery(
        url="http://example.com/hook",
        event_action="test.retention",
        status_code=204,
        duration_ms=5,
        error=None,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=90),
    ))
    db.commit()
```

## Run

- `pytest tests/test_webhook_deliveries_retention.py -x -v` — 3 green.
- `pytest -x -q` — 402 total (399 + 3).

## Commit #1

```
git add -A
git commit -m "feat(retention): webhook_deliveries retention sweep + settings knob"
git push origin main
```

## Task 2 — release v0.23.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.23.0`.
- Prepend CHANGELOG entry summarizing: closes v0.22.0 debt, default 30d, mirrors v0.21.0 pattern, 3 new tests.
- Final `pytest -x -q` green.
- Commit + tag + push + deploy. Verify `/healthz.version == "0.23.0"`.

---

## Constraints

- **No new audit event** — the existing `settings.updated` diff picks up the new field automatically.
- **Default 30 days** — webhook deliveries are fast-churn operational data, no compliance value after a month.
- **0 = never purge** escape hatch.
- No new deps, no UI changes beyond the single settings field.
