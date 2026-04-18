# Persistent retention last-run tracking — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** record every retention run (manual + scheduled) to a new `SchedulerRun` table, then display the most-recent run on `/admin/retention` and `/admin/ops`. Closes the `last_run=None` hardcode shipped in admin_ui.py and adds a "Last run N ago" line to the ops page.

**Architecture:** one new table keyed by id; `run_retention` wraps its body with a try/except, recording start + finish + summary + error + duration_ms. The admin retention page + ops page both query `SELECT * FROM scheduler_runs WHERE job='retention' ORDER BY started_at DESC LIMIT 1`.

**Tech stack:** one SQLAlchemy model with `JSON` column, time measurement via `time.monotonic`, existing advisory-lock + scheduler wiring untouched.

---

## Task 1 — schema + runner instrumentation + UI wiring + tests (atomic commit)

**Files:**
- Modify: `app/db.py` — add `SchedulerRun` model
- Modify: `app/retention.py` — record each run
- Modify: `app/admin_ui.py` — retention GET handler reads real `last_run`; ops page surfaces it
- Modify: `app/templates/retention.html` — already renders `last_run`; no change needed if the dict shape matches
- Modify: `app/templates/ops.html` — add "Last run" row to the "Retention scheduler" card
- New: `tests/test_retention_last_run.py` (4 tests)

### Schema

Place `SchedulerRun` in `app/db.py` near `AuditEvent`:
```python
class SchedulerRun(Base):
    """One row per scheduled-job execution (manual or cron).

    We only persist retention today, but the ``job`` column keeps it
    open for future jobs (catalog refresh, blob cleanup) without
    schema churn.
    """

    __tablename__ = "scheduler_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
```

Auto-ALTER handles legacy DBs; `Text` and `JSON` are already imported.

### Runner instrumentation — `app/retention.py`

Refactor `run_retention` so the happy + error paths each persist a row. Pseudo-code:

```python
import time as _time

def run_retention(db: Optional[Session] = None) -> dict:
    from .db import SchedulerRun  # local to avoid import cycles

    started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    t0 = _time.monotonic()

    # ... existing body: if db is not None, use it; else open a fresh one.
    # Capture the session we'll write the SchedulerRun to as `record_db`
    # so the manual-run path commits with the caller and the scheduler
    # path commits its own session.

    if db is not None:
        # Manual (admin-UI) run — caller holds the commit.
        try:
            summary = _do_retention(db)
            db.flush()
            _write_scheduler_run(
                db, job="retention", started_at=started_at,
                duration_ms=int((_time.monotonic() - t0) * 1000),
                summary=summary, error=None,
            )
        except Exception as exc:
            _write_scheduler_run(
                db, job="retention", started_at=started_at,
                duration_ms=int((_time.monotonic() - t0) * 1000),
                summary=None, error=str(exc),
            )
            raise
    else:
        # Scheduler run — own session.
        session = session_factory()
        try:
            if not _try_acquire_leader_lock(session):
                # … existing skipped-return path; do NOT write a SchedulerRun
                # row when we didn't actually do anything.
                ...
            try:
                summary = _do_retention(session)
                _write_scheduler_run(
                    session, job="retention", started_at=started_at,
                    duration_ms=int((_time.monotonic() - t0) * 1000),
                    summary=summary, error=None,
                )
                session.commit()
            except Exception as exc:
                session.rollback()
                # Fresh session for the error row so the rolled-back state
                # doesn't leak; best-effort — never re-raise from the record.
                try:
                    err_s = session_factory()
                    _write_scheduler_run(
                        err_s, job="retention", started_at=started_at,
                        duration_ms=int((_time.monotonic() - t0) * 1000),
                        summary=None, error=str(exc),
                    )
                    err_s.commit()
                    err_s.close()
                except Exception:
                    pass
                raise
        finally:
            session.close()

    # metric emission unchanged …
    return summary


def _write_scheduler_run(db, *, job, started_at, duration_ms, summary, error):
    from datetime import datetime, timezone
    from .db import SchedulerRun
    row = SchedulerRun(
        job=job,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
        duration_ms=duration_ms,
        summary=summary,
        error=error,
    )
    db.add(row)
    db.flush()
```

Important: do NOT write a SchedulerRun for the `skipped: True` advisory-lock loser path.

### `/admin/retention` GET handler

Currently:
```python
last_run=None,
```
Replace with:
```python
from .db import SchedulerRun
last_run_row = db.scalar(
    _sel(SchedulerRun)
    .where(SchedulerRun.job == "retention")
    .order_by(SchedulerRun.started_at.desc())
    .limit(1)
)
last_run = None
if last_run_row is not None:
    last_run = {
        "started_at": last_run_row.started_at.isoformat() if last_run_row.started_at else None,
        "finished_at": last_run_row.finished_at.isoformat() if last_run_row.finished_at else None,
        "duration_ms": last_run_row.duration_ms,
        "summary": last_run_row.summary,
        "error": last_run_row.error,
    }
```
Pass into context unchanged (key name `last_run`).

The existing `retention.html` template already renders `{{ last_run | tojson(indent=2) }}` inside a `<details>` — works as-is. If it renders prettier with named rows, optionally polish, but don't expand scope here.

### `/admin/ops` page

In `admin_ops` handler, query the same row and pass as `retention_last_run_row`:
```python
from .db import SchedulerRun
rr = db.scalar(
    _sel(SchedulerRun)
    .where(SchedulerRun.job == "retention")
    .order_by(SchedulerRun.started_at.desc())
    .limit(1)
)
retention_last_run = None
if rr is not None:
    age_s = None
    if rr.started_at is not None:
        age_s = (datetime.now(timezone.utc).replace(tzinfo=None) - rr.started_at).total_seconds()
    retention_last_run = {
        "age": _format_uptime(age_s) + " ago" if age_s is not None else "—",
        "ok": rr.error is None,
        "deleted": (rr.summary or {}).get("deleted", 0),
        "audit_purged": (rr.summary or {}).get("audit_events_purged", 0),
    }
```

### `ops.html` — Retention scheduler card

Add rows below the existing Enabled + Cron rows:
```html
{% if retention_last_run %}
<div class="stat-row"><span>Last run</span>
  <b>{% if retention_last_run.ok %}<span class="pill pill-ok">ok</span>{% else %}<span class="pill pill-suspended">failed</span>{% endif %} {{ retention_last_run.age }}</b>
</div>
<div class="stat-row"><span>Purged</span><b>{{ retention_last_run.deleted }} snapshots, {{ retention_last_run.audit_purged }} audit rows</b></div>
{% else %}
<div class="stat-row"><span>Last run</span><b><span class="muted">never</span></b></div>
{% endif %}
```

### Tests — `tests/test_retention_last_run.py`

Bootstrap DB via the `_bootstrap_db` autouse fixture pattern from `tests/test_audit_retention.py` — needs tables created before direct-session access.

1. `test_manual_run_writes_scheduler_run_row`:
   - Call `run_retention(db)` directly in a `session_factory()` context. Commit.
   - Query `SchedulerRun` — exactly 1 row, `job="retention"`, `finished_at IS NOT NULL`, `error IS NULL`, `summary` dict includes the expected keys.

2. `test_retention_page_shows_last_run(admin_client)`:
   - Seed a SchedulerRun row directly.
   - GET `/admin/retention` — page includes `started_at` timestamp or `"deleted"` value from the summary.

3. `test_ops_page_shows_last_run(admin_client)`:
   - Seed a SchedulerRun row.
   - GET `/admin/ops` — body contains "Last run" label AND the "ok" pill class.

4. `test_run_records_duration_ms`:
   - Call `run_retention(db)` directly. Assert the resulting row has `duration_ms` set to a small positive integer.

Fixture: reset `SchedulerRun` table at test start (delete all rows) so tests don't contaminate each other.

## Run

- `pytest tests/test_retention_last_run.py -x -v` — 4 green.
- `pytest -x -q` — 379 total (375 + 4).

## Commit

```
git add -A
git commit -m "feat(retention): persistent scheduler_runs table + last-run on ops/retention"
git push origin main
```

## Task 2 — release v0.18.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.18.0`.
- Prepend CHANGELOG entry.
- Final `pytest -x -q` green.
- `git commit -m "chore: v0.18.0 — persistent retention last-run tracking"`
- `git tag -a v0.18.0 -m "v0.18.0 — retention scheduler_runs persistence"`
- `git push origin main --tags`
- `./scripts/deploy.sh`, verify `/healthz.version == "0.18.0"`.

---

## Constraints

- **Do NOT write a row on the advisory-lock `skipped: True` path** — that run didn't actually touch data.
- **Error path writes its own row** — so operators can see "last run: failed 6 h ago: <exc message>" on the ops page.
- **No cleanup of old scheduler_runs** — they're tiny (<1 KB each), 365 rows/yr; keep them forever until someone complains. Retention-of-retention-rows is a later concern.
- **No new audit event** — SchedulerRun is operational state, not a trust-boundary mutation.
- No new deps.
