# Scheduled backup + on-disk retention — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** nightly cron writes the v0.20/v0.26 ZIP to the configured `backup_directory`, prunes to a retention count, records `SchedulerRun(job="backup")`. Completes the backup trilogy.

**Architecture:** new `app/backup.py::run_scheduled_backup(db=None)` modelled on `retention.run_retention` — same SchedulerRun instrumentation. APScheduler job wired from `start_scheduler`. Retention: delete oldest files matching `nks-wdc-backup-*.zip` in the directory beyond the count.

---

## Task 1 — scheduled runner + retention + settings + tests + release (single sweep)

**Files:**
- Modify: `app/db.py` — add `backup_enabled`, `backup_retention_count` on `GlobalPolicy`
- Modify: `app/backup.py` — add `run_scheduled_backup(db=None) -> dict` + `_prune_disk_backups(directory, keep_count) -> int`
- Modify: `app/retention.py` (or a new wiring point) — `start_scheduler` adds the backup cron job next to the retention one
- Modify: `app/admin_ui.py::admin_save_settings` — add the two form params; GET handler passes both into `policy` dict; `admin_ops` computes `last_backup_run` (most-recent `SchedulerRun(job="backup")` row) + passes into context
- Modify: `app/templates/settings.html` — add two fields to the "Backup" fieldset: enable checkbox + retention count
- Modify: `app/templates/ops.html` — Backup card gains a "Last scheduled run" row when there's a SchedulerRun record
- New: `tests/test_scheduled_backup.py` (5 tests)
- Release bump to v0.27.0

### Schema

On `GlobalPolicy` after `backup_directory`:
```python
backup_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
backup_retention_count: Mapped[int] = mapped_column(Integer, default=7, nullable=False)
```

Default 7 keeps a week of daily backups. Auto-ALTER on startup.

### `app/backup.py` additions

```python
import os
import glob
import logging
import time as _time
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def _prune_disk_backups(directory: str, keep_count: int) -> int:
    """Delete oldest files matching nks-wdc-backup-*.zip beyond the cap.
    Returns the number of files removed. ``keep_count <= 0`` is a
    never-prune escape hatch."""
    if keep_count <= 0:
        return 0
    try:
        pattern = os.path.join(directory, "nks-wdc-backup-*.zip")
        files = sorted(
            (f for f in glob.glob(pattern) if os.path.isfile(f)),
            key=os.path.getmtime,
        )
    except OSError:
        return 0
    if len(files) <= keep_count:
        return 0
    to_delete = files[: len(files) - keep_count]
    removed = 0
    for path in to_delete:
        try:
            os.remove(path)
            removed += 1
        except OSError as exc:
            log.warning("backup prune: failed to remove %s: %s", path, exc)
    return removed


def run_scheduled_backup(db=None) -> dict:
    """Write a backup ZIP to the configured directory + prune retention.

    Mirrors ``retention.run_retention`` — when *db* is provided the caller
    owns the commit; otherwise we open our own session. Always records a
    ``SchedulerRun(job="backup")`` row (success + failure paths) so the
    scheduler-runs history page surfaces it.
    """
    from .db import GlobalPolicy, SchedulerRun, session_factory

    started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    t0 = _time.monotonic()

    def _record(session, summary, error):
        try:
            row = SchedulerRun(
                job="backup",
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
                duration_ms=int((_time.monotonic() - t0) * 1000),
                summary=summary,
                error=error,
            )
            session.add(row)
            session.flush()
        except Exception as exc:
            log.warning("scheduled backup: failed to record SchedulerRun: %s", exc)

    def _run(session) -> dict:
        policy = session.get(GlobalPolicy, 1)
        if policy is None or not policy.backup_enabled:
            return {"skipped": True, "reason": "backup_disabled"}
        directory = (policy.backup_directory or "").strip()
        if not directory:
            return {"skipped": True, "reason": "no_directory"}

        os.makedirs(directory, exist_ok=True)
        zip_bytes, filename, manifest = generate_backup_bytes(
            session, actor_email="scheduler@nks-wdc"
        )
        out_path = os.path.join(directory, filename)
        with open(out_path, "wb") as fh:
            fh.write(zip_bytes)

        pruned = _prune_disk_backups(directory, policy.backup_retention_count or 0)
        return {
            "path": out_path,
            "bytes": len(zip_bytes),
            "counts": manifest["counts"],
            "pruned": pruned,
        }

    if db is not None:
        try:
            summary = _run(db)
            _record(db, summary, None)
            db.flush()
            return summary
        except Exception as exc:
            _record(db, None, str(exc))
            raise
    else:
        session = session_factory()
        try:
            try:
                summary = _run(session)
                _record(session, summary, None)
                session.commit()
                return summary
            except Exception as exc:
                session.rollback()
                try:
                    err_s = session_factory()
                    err_started_at = started_at  # captured via closure
                    err_row = SchedulerRun(
                        job="backup",
                        started_at=err_started_at,
                        finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
                        duration_ms=int((_time.monotonic() - t0) * 1000),
                        summary=None,
                        error=str(exc),
                    )
                    err_s.add(err_row); err_s.commit(); err_s.close()
                except Exception:
                    pass
                raise
        finally:
            session.close()
```

### Scheduler wiring

In `app/retention.py::start_scheduler`, after the existing retention job registration, add:

```python
# Backup — 30 min before retention so the ZIP reflects pre-sweep state.
backup_cron = os.environ.get("NKS_WDC_BACKUP_CRON", "30 2 * * *")
try:
    backup_trigger = CronTrigger.from_crontab(backup_cron, timezone="UTC")
except Exception as exc:
    log.warning(
        "Invalid NKS_WDC_BACKUP_CRON=%s: %s — defaulting daily 02:30", backup_cron, exc
    )
    backup_trigger = CronTrigger.from_crontab("30 2 * * *", timezone="UTC")
sched.add_job(
    _scheduled_backup, backup_trigger, id="backup-daily", replace_existing=True
)
log.info("backup scheduler started (cron=%s)", backup_cron)
```

Add the `_scheduled_backup` wrapper near `_scheduled_retention` in `app/retention.py`:
```python
def _scheduled_backup() -> dict:
    """APScheduler entry-point for the nightly backup."""
    from uuid import uuid4
    from .observability import REQUEST_ID  # reuse the ContextVar

    token = REQUEST_ID.set(f"job-{uuid4().hex[:8]}")
    try:
        from . import backup as _bk
        return _bk.run_scheduled_backup()
    except Exception:
        log.exception("scheduled backup failed")
        raise
    finally:
        REQUEST_ID.reset(token)
```

Check `app/retention.py` for the existing `_scheduled_retention` wrapper shape; mirror it exactly. If `REQUEST_ID` lives elsewhere or the retention wrapper doesn't use it, skip that detail and match whatever pattern `_scheduled_retention` uses.

### Settings handler + template

1. Handler: add `backup_enabled: Annotated[str, Form()] = ""` + `backup_retention_count: Annotated[int, Form()] = 7` to `admin_save_settings`. Extend before/after dicts + GET policy dict.
   - `row.backup_enabled = bool(backup_enabled)`
   - `row.backup_retention_count = max(0, min(int(backup_retention_count), 365))`

2. Template — inside the existing "Backup" fieldset, alongside `backup_directory`:
   ```html
   <label class="checkbox span-all">
     <input type="checkbox" name="backup_enabled" value="1" {% if policy.backup_enabled %}checked{% endif %}>
     Enable nightly scheduled backup
     <span class="hint">Cron 02:30 UTC by default (override via <code>NKS_WDC_BACKUP_CRON</code>). Requires backup directory set above.</span>
   </label>
   <label>Keep last N backups
     <input type="number" name="backup_retention_count" value="{{ policy.backup_retention_count }}" min="0" max="365">
     <span class="hint">Nightly prune removes the oldest beyond this count. 0 = never prune.</span>
   </label>
   ```

### `/admin/ops` wire-up

`admin_ops` handler fetches the most-recent `SchedulerRun(job="backup")` row and passes `backup_last_run` dict into context:
```python
backup_last_run_row = db.scalar(
    _sel(SchedulerRun)
    .where(SchedulerRun.job == "backup")
    .order_by(SchedulerRun.started_at.desc())
    .limit(1)
)
backup_last_run = None
if backup_last_run_row is not None:
    age_s = (datetime.now(timezone.utc).replace(tzinfo=None) - backup_last_run_row.started_at).total_seconds()
    backup_last_run = {
        "age": _format_uptime(age_s) + " ago",
        "ok": backup_last_run_row.error is None,
        "summary": backup_last_run_row.summary,
    }
```

Pass into context. Template addition in the Backup card:
```html
{% if backup_last_run %}
<div class="stat-row"><span>Last scheduled run</span>
  <b>{% if backup_last_run.ok %}<span class="pill pill-ok">ok</span>{% else %}<span class="pill pill-suspended">failed</span>{% endif %} {{ backup_last_run.age }}</b>
</div>
{% if backup_last_run.summary and backup_last_run.summary.bytes %}
<div class="stat-row"><span>Last size</span><b>{{ (backup_last_run.summary.bytes / 1024 / 1024)|round(1) }} MB</b></div>
{% endif %}
{% if backup_last_run.summary and backup_last_run.summary.pruned %}
<div class="stat-row"><span>Pruned</span><b>{{ backup_last_run.summary.pruned }} old backup(s)</b></div>
{% endif %}
{% endif %}
```

### Tests — `tests/test_scheduled_backup.py`

Reuse `admin_client` fixture from `tests/test_backup_to_disk.py`. Use `tmp_path`.

1. `test_run_scheduled_backup_writes_file_when_enabled(tmp_path)`:
   - Set `GlobalPolicy.backup_enabled=True`, `backup_directory=str(tmp_path)`.
   - Call `backup.run_scheduled_backup()` (no db arg).
   - Assert returned dict has `path`, `bytes`, `counts`; tmp_path contains 1 file.
   - Assert `SchedulerRun(job="backup")` row exists with `error IS NULL`.

2. `test_run_scheduled_backup_skips_when_disabled(tmp_path)`:
   - `backup_enabled=False`, `backup_directory=str(tmp_path)`.
   - Call `run_scheduled_backup()`. Assert returned dict has `skipped: True, reason: "backup_disabled"`.
   - Assert no files in tmp_path. Assert `SchedulerRun` row was still recorded with `summary.skipped=True`.

3. `test_run_scheduled_backup_skips_when_no_directory()`:
   - `backup_enabled=True`, `backup_directory=None`.
   - Call → `skipped: True, reason: "no_directory"`. No ZIP anywhere.

4. `test_prune_keeps_last_n(tmp_path)`:
   - Pre-create 10 files named `nks-wdc-backup-20260101T*.zip` with varying mtimes via `os.utime`.
   - Call `backup._prune_disk_backups(str(tmp_path), 3)`.
   - Assert returns 7, 3 files remain (the most recent by mtime).

5. `test_settings_save_persists_backup_fields(admin_client)`:
   - POST `/admin/settings` with `backup_enabled=1`, `backup_retention_count=14`.
   - Assert `GlobalPolicy.backup_enabled=True` + `backup_retention_count=14`.
   - Assert `settings.updated` audit detail carries the diff for both fields.

### Run

- `pytest tests/test_scheduled_backup.py -x -v` — 5 green.
- `pytest -x -q` — 417 total (412 + 5).

### Commit #1

```
git add -A
git commit -m "feat(backup): nightly scheduled runner + on-disk retention pruning"
git push origin main
```

## Task 2 — release v0.27.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.27.0`.
- Prepend CHANGELOG.
- Final `pytest -x -q` green.
- Commit + tag + push + deploy. Verify `/healthz.version == "0.27.0"`.

---

## Constraints

- **Never raise into the APScheduler worker** — `_scheduled_backup` logs + raises for visibility, same pattern as `_scheduled_retention`. APScheduler's `BackgroundScheduler` default missed-job behaviour is logging only.
- **Advisory-lock** — the existing `retention.run_retention` uses `_try_acquire_leader_lock` to prevent multi-worker double-runs on Postgres. For the backup runner, that's overkill today (single-container deploy) — SKIP the lock, document in the CHANGELOG.
- **Cron default 02:30 UTC** — fires 30 min before the retention sweep so the ZIP captures pre-sweep state.
- **Retention = file count, not days** — `len(files) > keep_count` beats age-based pruning here because "keep last 7 nightly backups" is the mental model operators have.
- **No new deps.**
