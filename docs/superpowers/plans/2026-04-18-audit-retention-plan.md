# Audit-log retention — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** expose an `audit_retention_days` policy on `GlobalPolicy`, teach the nightly retention runner to prune `audit_events` older than that, and surface the knob in the settings UI. Ship as v0.13.0.

**Architecture:** one new column, one extra `_batched_delete` call in `_do_retention`, one new summary field (`audit_events_purged`), one settings-form field. Reuses all existing infrastructure (scheduler, advisory lock, audit-on-manual-run).

**Tech stack:** SQLAlchemy column add, reuse existing `_batched_delete` helper.

---

## Task 1 — schema + runner + tests (atomic commit)

**Files:**
- Modify: `app/db.py` — add `audit_retention_days` column on `GlobalPolicy`
- Modify: `app/retention.py` — extend `_do_retention` with audit sweep
- New: `tests/test_audit_retention.py` (3 tests)

### Schema

On `GlobalPolicy` (class at line ~336 of `app/db.py`):
```python
audit_retention_days: Mapped[int] = mapped_column(Integer, default=365, nullable=False)
```
Auto-ALTER on startup handles legacy DBs. Default 365 d = "keep one year" — conservative for compliance.

### Runner

In `app/retention.py::_do_retention`, after the `revoked_purged` block:
```python
from .db import AuditEvent, GlobalPolicy  # add to imports

policy_row = session.get(GlobalPolicy, 1)
audit_retain_days = (policy_row.audit_retention_days if policy_row else 365) or 365
audit_purged = 0
if audit_retain_days > 0:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        days=audit_retain_days
    )
    audit_purged = _batched_delete(
        session,
        AuditEvent,
        AuditEvent.created_at < cutoff,
    )
```

Extend the return dict:
```python
return {
    "accounts": len(account_ids),
    "deleted": deleted_total,
    "idempotency_purged": idempotency_purged,
    "revoked_tokens_purged": revoked_purged,
    "audit_events_purged": audit_purged,
}
```

Extend the admin-UI manual-run message in `admin_ui.py::admin_retention_run_now` to include the new field in the `msg` flash text (append `, audit_events_purged={summary.get('audit_events_purged', 0)}`). The audit detail already uses `summary` as-is so the new field lands automatically.

Also extend the empty-summary branch in `run_retention` (the `skipped: True` return) to include `"audit_events_purged": 0`.

### Tests — `tests/test_audit_retention.py`

Reuse the `admin_client` fixture pattern from `tests/test_settings_retention_audit.py` but you won't need the HTTP client for most of these — retention runs synchronously via `run_retention(db)`.

```python
def test_audit_retention_purges_old_rows():
    # Seed 3 events: one from ~400 days ago, one from ~10 days ago, one "now".
    # Set audit_retention_days=30 on GlobalPolicy.
    # Call run_retention(db); assert summary["audit_events_purged"] == 1
    # and only two rows remain.

def test_audit_retention_default_365_days_keeps_recent():
    # Seed 2 events: 100 days ago + now. Default policy (365d, no UPDATE).
    # Run; assert 0 purged, 2 rows remain.

def test_audit_retention_zero_means_never_purge():
    # Seed an event dated 2000 days ago. Set audit_retention_days=0.
    # Run; assert 0 purged (the "0 means never" branch).
```

For seeding an event at an arbitrary date, INSERT directly — bypass `audit.emit` so you can control `created_at`:
```python
e = AuditEvent(
    action="test.backdated",
    resource_type="account",
    resource_id="1",
    created_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=400),
)
db.add(e); db.commit()
```

## Run

- `pytest tests/test_audit_retention.py -x -v` — 3 green.
- `pytest -x -q` — 354 total (351 + 3).

## Commit

```
git add -A
git commit -m "feat(retention): audit_events_purged sweep + audit_retention_days policy"
git push origin main
```

## Task 2 — settings UI (atomic commit)

**Files:** `app/admin_ui.py`, `app/templates/settings.html`

### Handler

`admin_save_settings` already threads `before`/`after` dicts through to the `settings.updated` audit diff. Add `audit_retention_days: Annotated[int, Form()] = 365` to the params, include it in both `before` and `after` snapshots, and set:
```python
row.audit_retention_days = max(0, min(int(audit_retention_days), 3650))
```
0 = never purge, capped at 10 years.

Also extend the `admin_settings` GET handler's `policy` dict passed into the template to include `audit_retention_days`.

### Template

Inside the "Snapshot defaults" fieldset (the one with `snapshot_keep_last_n` + `snapshot_retain_days`), add under those two fields — OR create a new fieldset "Audit retention" so the groups stay semantic. Pick the cleaner. If a new fieldset, shape:

```html
<fieldset class="form-fieldset">
  <legend>Audit retention</legend>
  <label>Keep audit events for (days)
    <input type="number" name="audit_retention_days" value="{{ policy.audit_retention_days }}" min="0" max="3650">
    <span class="hint">Nightly sweep drops rows older than this. 0 = keep forever.</span>
  </label>
</fieldset>
```

Place this fieldset between "Snapshot defaults" and "Quotas" so the settings surface reads: Access · Snapshot defaults · Audit retention · Quotas · Admin UI.

### Regression test

Append one test to `tests/test_audit_retention.py`:
```python
def test_save_settings_updates_audit_retention_days(admin_client):
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    admin_client.post("/admin/settings", data={
        "_csrf": csrf,
        "snapshot_keep_last_n": "30",
        "snapshot_retain_days": "90",
        "max_bytes_per_user": "",
        "registration_enabled": "1",
        "default_role": "user",
        "banner_message": "",
        "audit_retention_days": "42",
    })
    with session_factory() as db:
        assert db.get(GlobalPolicy, 1).audit_retention_days == 42
```

The `admin_client` fixture must reset `require_2fa_for_admins=False` + TOTP (borrow from `tests/test_invites_history_csv.py` fixture — it already does this).

## Run

- `pytest -x -q` — 355 total (354 + 1).

## Commit

```
git add -A
git commit -m "feat(retention): audit_retention_days settings toggle"
git push origin main
```

## Task 3 — release v0.13.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.13.0`.
- Prepend CHANGELOG entry.
- `pytest -x -q` final green.
- `git commit -m "chore: v0.13.0 — audit retention policy + settings toggle"`
- `git tag -a v0.13.0 -m "v0.13.0 — audit retention policy + settings toggle"`
- `git push origin main --tags`
- `./scripts/deploy.sh`, verify `/healthz.version == "0.13.0"`.

## Constraints

- **Default 365 days** — don't break legacy instances by accidentally purging years of audit on first startup. Behaviour: legacy rows (auto-ALTER sets the column to the default) keep everything younger than a year, silently drop older. That's the intended compliance behaviour.
- **0 = never purge** — explicit escape hatch for users with external SIEM.
- **No new audit event** — the existing `settings.updated` diff picks up the change; `retention.manual_run` already includes the summary dict.
- No new deps, no new CSS.
