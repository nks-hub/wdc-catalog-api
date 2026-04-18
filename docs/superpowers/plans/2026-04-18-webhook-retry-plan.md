# v0.47.0 — Webhook delivery manual retry

**Goal:** Add a per-row "retry" button on `/admin/ops/webhooks` so operators can re-send a failed webhook without waiting for the next real event.

**Scope:** One new POST handler, one template tweak, one audit action, tests. No schema changes. Reuses `webhooks._post()` + `_record_delivery()` primitives.

---

## Task 1 — Retry handler

**File:** `app/admin_ui.py`

Add `POST /admin/ops/webhooks/{delivery_id}/retry` handler:
- admin-only via existing `current_user` auth
- CSRF via `require_csrf`
- Load the `WebhookDelivery` row by id. 404 if missing.
- Reconstruct a minimal payload: `{"action": row.event_action, "resource_type": "retry", "resource_id": str(row.id), "detail": {"retried_from": row.id}}`. The original full event payload isn't stored on the row; document this limitation in the docstring. Real-world use is "did the URL come back online" not "replay exact bytes".
- Dispatch via the existing `webhooks.fire(event, db=db)` (it will `_record_delivery()` a fresh row).
- Emit `webhook.retried` audit with `detail={"from_delivery_id": row.id, "url": row.url, "event_action": row.event_action}`.
- Redirect back to `/admin/ops/webhooks` with success flash.

## Task 2 — Allowlist

**File:** `app/observability.py`

Add `"webhook.retried"` to `SECURITY_ACTION_ALLOWLIST`.

## Task 3 — Template button

**File:** `app/templates/webhook_deliveries.html`

For each row, add a small CSRF-guarded form rendering a "Retry" submit button. Only show it when `delivery.ok is False` (failed deliveries) — successes don't need retry.

## Task 4 — Tests

**File:** `tests/test_webhook_retry.py` (new)

- 404 for unknown id
- Unauth → 303/401
- Success path: seed a failed WebhookDelivery, POST retry, assert 303 + new `WebhookDelivery` row created + `webhook.retried` audit row landed
- CSRF missing → 403
- Regression: `webhook.retried` in `SECURITY_ACTION_ALLOWLIST`

## Task 5 — Release

- Bump `app/__init__.py` + `pyproject.toml` to `0.47.0`
- Prepend CHANGELOG entry
- `pytest -x -q`
- Commit: `feat(admin): webhook delivery manual retry button`
- Tag `v0.47.0`, push, deploy.
