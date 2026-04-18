# `scheduler_runs` retention — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** add a configurable retention window for `scheduler_runs` rows (shipped in v0.18.0 but unbounded today). Extend `_do_retention` with a sweep, expose a knob in settings, surface `scheduler_runs_purged` in the run summary.

**Architecture:** one new `GlobalPolicy.scheduler_run_retention_days` column (default 90). One extra `_batched_delete` call in `_do_retention`. One settings-form field inside the existing "Audit retention" fieldset (rename to "Retention windows" OR add a second field in the same fieldset; pick the cleaner).

**Tech stack:** reuses every pattern already in place from v0.13.0 (audit retention).

---

## Task 1 — schema + runner + tests + settings + release (single sweep)

**Files:**
- Modify: `app/db.py` — add column
- Modify: `app/retention.py` — extend `_do_retention` with sweep + return key
- Modify: `app/admin_ui.py` — add the Form() param to `admin_save_settings`, extend before/after dicts, include in the `policy` dict for the GET handler
- Modify: `app/templates/settings.html` — new input inside the existing "Audit retention" fieldset (rename to "Retention windows" so both fields read semantically)
- Modify: `app/templates/retention.html` — flash/last-run display picks up `scheduler_runs_purged` automatically via the existing summary dict
- New: `tests/test_scheduler_runs_retention.py` (3 tests)

### Schema

On `GlobalPolicy` after the existing `audit_retention_days`:
```python
scheduler_run_retention_days: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
```

Auto-ALTER on startup handles legacy rows; default 90d keeps 3 months of scheduler history.

### Runner — `_do_retention` in `app/retention.py`

After the existing audit-events sweep, add:

```python
scheduler_retain_days = policy_row.scheduler_run_retention_days if policy_row else 90
if scheduler_retain_days is None:
    scheduler_retain_days = 90
scheduler_purged = 0
if scheduler_retain_days > 0:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        days=scheduler_retain_days
    )
    from .db import SchedulerRun
    scheduler_purged = _batched_delete(
        session,
        SchedulerRun,
        SchedulerRun.started_at < cutoff,
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
    "scheduler_runs_purged": scheduler_purged,
}
```

Also extend the `{"skipped": True}` empty-summary return in `run_retention()` with `"scheduler_runs_purged": 0` so the shape stays consistent across all paths.

Extend the `admin_retention_run_now` flash text in `admin_ui.py` with `, scheduler_runs_purged={summary.get('scheduler_runs_purged', 0)}`.

### Settings UI

1. **Handler** (`admin_save_settings`): add `scheduler_run_retention_days: Annotated[int, Form()] = 90`. Append to both `before` and `after` dicts. Set `row.scheduler_run_retention_days = max(0, min(int(scheduler_run_retention_days), 3650))`. Include in the `policy` dict the GET handler passes into the template.

2. **Template** (`app/templates/settings.html`): inside the existing "Audit retention" fieldset, rename the `<legend>` to "Retention windows" and add a second field beside the existing `audit_retention_days`:
   ```html
   <label>Keep scheduler runs for (days)
     <input type="number" name="scheduler_run_retention_days" value="{{ policy.scheduler_run_retention_days }}" min="0" max="3650">
     <span class="hint">Nightly sweep drops rows from <code>/admin/ops/scheduler</code> older than this. 0 = keep forever.</span>
   </label>
   ```

### Tests — `tests/test_scheduler_runs_retention.py`

Bootstrap via autouse fixture that spins up `TestClient(app)` once to fire `create_all`. Pattern from `tests/test_audit_retention.py`.

1. `test_sweep_purges_old_scheduler_runs`:
   - Seed three `SchedulerRun` rows: started_at 180d ago, 10d ago, now.
   - Set `GlobalPolicy.scheduler_run_retention_days = 30`.
   - Call `run_retention(db)` directly (session injected).
   - Assert `summary["scheduler_runs_purged"] == 1`.
   - Assert two rows remain.

2. `test_zero_means_never_purge`:
   - Seed one row started 2000d ago. Set `scheduler_run_retention_days = 0`.
   - Run retention. Assert `summary["scheduler_runs_purged"] == 0` and row still exists.

3. `test_settings_save_persists_window(admin_client)`:
   - POST `/admin/settings` with `scheduler_run_retention_days=42`. Verify `GlobalPolicy.scheduler_run_retention_days == 42`. Verify the `settings.updated` audit detail carries the `{"from": 90, "to": 42}` diff.

## Run

- `pytest tests/test_scheduler_runs_retention.py -x -v` — 3 green.
- `pytest -x -q` — 393 total (390 + 3).

## Commit

```
git add -A
git commit -m "feat(retention): scheduler_runs retention sweep + settings knob"
git push origin main
```

## Task 2 — release v0.21.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.21.0`.
- Prepend CHANGELOG.
- Final `pytest -x -q` green.
- `git commit -m "chore: v0.21.0 — scheduler_runs retention"`
- `git tag -a v0.21.0 -m "v0.21.0 — scheduler_runs retention"`
- `git push origin main --tags`
- `./scripts/deploy.sh`, verify `/healthz.version == "0.21.0"`.

---

## Constraints

- **No new audit event** — the existing `settings.updated` diff picks up the new field automatically.
- **No new dep**, no new CSS.
- **Default 90 days** — balances visibility with table growth. A daily-retention-run deployment generates one row per day; 90 rows per job × N jobs stays small indefinitely.
- **0 = never purge** — matches the `audit_retention_days=0` escape hatch shipped in v0.13.0.
