"""Retention runner — scheduled purge of auto snapshots.

Runs inside the FastAPI process via APScheduler ``BackgroundScheduler``
started at ``lifespan`` startup. Retention policy resolution per account:

    1. SnapshotRetentionPolicy where account_id=X and device_id=None.
    2. GlobalPolicy singleton defaults.
    3. Hardcoded fallback (30 auto snapshots, keep labeled forever).

The runner is idempotent and may also be invoked manually via the
``/api/v1/admin/retention/run-now`` endpoint.
"""

from __future__ import annotations

import logging
import os
import time as _time
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from .db import (
    Account,
    AuditEvent,
    GlobalPolicy,
    IdempotencyRecord,
    RevokedToken,
    SchedulerRun,
    SnapshotRetentionPolicy,
    WebhookDelivery,
    session_factory,
)
from .snapshots import purge_auto_older_than

log = logging.getLogger(__name__)


@dataclass
class ResolvedPolicy:
    keep_last_n_auto: int
    auto_expire_days: Optional[int]
    keep_labeled_forever: bool


DEFAULT_POLICY = ResolvedPolicy(
    keep_last_n_auto=30,
    auto_expire_days=None,
    keep_labeled_forever=True,
)


def _resolve_policy(db: Session, account_id: int) -> ResolvedPolicy:
    row = db.scalar(
        select(SnapshotRetentionPolicy).where(
            SnapshotRetentionPolicy.account_id == account_id,
            SnapshotRetentionPolicy.device_id.is_(None),
        )
    )
    if row is not None:
        return ResolvedPolicy(
            keep_last_n_auto=row.keep_last_n_auto,
            auto_expire_days=row.auto_expire_days,
            keep_labeled_forever=row.keep_labeled_forever,
        )
    global_row = db.get(GlobalPolicy, 1)
    if global_row is not None:
        return ResolvedPolicy(
            keep_last_n_auto=global_row.snapshot_keep_last_n,
            auto_expire_days=global_row.snapshot_retain_days,
            keep_labeled_forever=True,
        )
    return DEFAULT_POLICY


_SQLITE_BATCH_SIZE = int(os.environ.get("NKS_WDC_RETENTION_BATCH", "1000"))


def _batched_delete(session: Session, model, filter_expr) -> int:
    """Delete matching rows in ``_SQLITE_BATCH_SIZE`` chunks.

    SQLite holds an exclusive lock for the duration of a DELETE; at
    100k+ expired rows that's seconds of downtime for writers. Batching
    lets readers + writers make progress between chunks. Postgres
    handles the unbatched path fine, but the code costs nothing to keep
    uniform across both engines.
    """
    total = 0
    while True:
        # Pick a page of primary keys matching the predicate, then delete
        # only those (portable across both sqlite + pg without relying on
        # LIMIT inside DELETE).
        pk_col = list(model.__table__.primary_key.columns)[0]
        ids = [
            row[0]
            for row in session.execute(
                select(pk_col).where(filter_expr).limit(_SQLITE_BATCH_SIZE)
            ).all()
        ]
        if not ids:
            break
        res = session.execute(delete(model).where(pk_col.in_(ids)))
        total += res.rowcount or 0
        if len(ids) < _SQLITE_BATCH_SIZE:
            break
    return total


def _do_retention(session: Session) -> dict:
    """Snapshot purge + idempotency + revoked-token sweeps, all against
    a single session. Caller decides whether to commit (manual admin
    run uses the request session; the scheduler opens its own)."""
    deleted_total = 0
    account_ids = [a.id for a in session.scalars(select(Account)).all()]
    for acc_id in account_ids:
        policy = _resolve_policy(session, acc_id)
        deleted_total += purge_auto_older_than(
            session,
            account_id=acc_id,
            keep_last_n=policy.keep_last_n_auto,
            auto_expire_days=policy.auto_expire_days,
            keep_labeled=policy.keep_labeled_forever,
        )

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    idempotency_purged = _batched_delete(
        session,
        IdempotencyRecord,
        IdempotencyRecord.expires_at <= now,
    )
    revoked_purged = _batched_delete(
        session,
        RevokedToken,
        (RevokedToken.expires_at.is_not(None)) & (RevokedToken.expires_at <= now),
    )

    policy_row = session.get(GlobalPolicy, 1)
    _raw = policy_row.audit_retention_days if policy_row is not None else None
    audit_retain_days = _raw if _raw is not None else 365
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

    scheduler_retain_days = policy_row.scheduler_run_retention_days if policy_row else 90
    if scheduler_retain_days is None:
        scheduler_retain_days = 90
    scheduler_purged = 0
    if scheduler_retain_days > 0:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
            days=scheduler_retain_days
        )
        scheduler_purged = _batched_delete(
            session,
            SchedulerRun,
            SchedulerRun.started_at < cutoff,
        )

    webhook_retain_days = policy_row.webhook_delivery_retention_days if policy_row else 30
    if webhook_retain_days is None:
        webhook_retain_days = 30
    webhook_purged = 0
    if webhook_retain_days > 0:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
            days=webhook_retain_days
        )
        webhook_purged = _batched_delete(
            session,
            WebhookDelivery,
            WebhookDelivery.created_at < cutoff,
        )

    return {
        "accounts": len(account_ids),
        "deleted": deleted_total,
        "idempotency_purged": idempotency_purged,
        "revoked_tokens_purged": revoked_purged,
        "audit_events_purged": audit_purged,
        "scheduler_runs_purged": scheduler_purged,
        "webhook_deliveries_purged": webhook_purged,
    }


# Postgres advisory-lock key for the scheduled retention pass. Any
# non-zero int64 works; pick a stable constant so two processes always
# contend for the same slot. SQLite callers ignore this — there's no
# multi-writer on a single file anyway.
_RETENTION_LOCK_KEY = 42001


def _try_acquire_leader_lock(session: Session) -> bool:
    """``True`` when this worker got the advisory lock, ``False`` when
    someone else already holds it. SQLite always returns ``True``.

    Postgres ``pg_try_advisory_lock`` is session-scoped — unlock happens
    automatically on ``session.close()``.
    """
    from sqlalchemy import text

    try:
        bind = session.get_bind()
    except Exception:
        return True
    dialect = bind.dialect.name if bind is not None else ""
    if dialect != "postgresql":
        return True
    result = session.execute(
        text("SELECT pg_try_advisory_lock(:k)"), {"k": _RETENTION_LOCK_KEY}
    ).scalar()
    return bool(result)


def _write_scheduler_run(
    db: Session,
    *,
    job: str,
    started_at: datetime,
    duration_ms: int | None,
    summary: dict | None,
    error: str | None,
) -> None:
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


def run_retention(db: Optional[Session] = None) -> dict:
    """Iterate every account and apply their resolved retention policy.

    When *db* is supplied (manual admin run) the caller owns the commit
    lifecycle — we only flush. When *db* is None (scheduler) a fresh
    session is opened, committed, and closed exactly once.

    On Postgres the scheduler path acquires ``pg_try_advisory_lock`` so
    multi-worker deployments don't run retention N times in parallel.
    Losers return early with ``{"skipped": True}`` and don't touch DB.
    """
    started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    t0 = _time.monotonic()

    if db is not None:
        try:
            summary = _do_retention(db)
            db.flush()
            _write_scheduler_run(
                db,
                job="retention",
                started_at=started_at,
                duration_ms=int((_time.monotonic() - t0) * 1000),
                summary=summary,
                error=None,
            )
        except Exception as exc:
            _write_scheduler_run(
                db,
                job="retention",
                started_at=started_at,
                duration_ms=int((_time.monotonic() - t0) * 1000),
                summary=None,
                error=str(exc),
            )
            raise
    else:
        session = session_factory()
        try:
            if not _try_acquire_leader_lock(session):
                log.info("retention skipped: advisory lock held by another worker")
                return {
                    "accounts": 0,
                    "deleted": 0,
                    "idempotency_purged": 0,
                    "revoked_tokens_purged": 0,
                    "audit_events_purged": 0,
                    "scheduler_runs_purged": 0,
                    "webhook_deliveries_purged": 0,
                    "skipped": True,
                }
            try:
                summary = _do_retention(session)
                _write_scheduler_run(
                    session,
                    job="retention",
                    started_at=started_at,
                    duration_ms=int((_time.monotonic() - t0) * 1000),
                    summary=summary,
                    error=None,
                )
                session.commit()
            except Exception as exc:
                session.rollback()
                try:
                    err_s = session_factory()
                    _write_scheduler_run(
                        err_s,
                        job="retention",
                        started_at=started_at,
                        duration_ms=int((_time.monotonic() - t0) * 1000),
                        summary=None,
                        error=str(exc),
                    )
                    err_s.commit()
                    err_s.close()
                except Exception:
                    pass
                raise
        finally:
            session.close()  # releases advisory lock on Postgres

    try:
        from .observability import RETENTION_DELETED

        RETENTION_DELETED.inc(summary.get("deleted", 0))
    except Exception:
        pass
    return summary


# ── APScheduler integration ────────────────────────────────────────────

_scheduler = None


def start_scheduler() -> None:
    """Called from FastAPI lifespan. Idempotent."""
    global _scheduler
    if os.environ.get("NKS_WDC_DISABLE_SCHEDULER") == "1":
        log.info("retention scheduler disabled by env flag")
        return
    if _scheduler is not None:
        return
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    sched = BackgroundScheduler(daemon=True)
    cron = os.environ.get("NKS_WDC_RETENTION_CRON", "0 3 * * *")  # 03:00 UTC daily
    try:
        trigger = CronTrigger.from_crontab(cron, timezone="UTC")
    except Exception as exc:
        log.warning(
            "Invalid NKS_WDC_RETENTION_CRON=%s: %s — defaulting daily 03:00", cron, exc
        )
        trigger = CronTrigger.from_crontab("0 3 * * *", timezone="UTC")
    sched.add_job(
        _scheduled_retention, trigger, id="retention-daily", replace_existing=True
    )

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

    sched.start()
    _scheduler = sched
    log.info("retention scheduler started (cron=%s)", cron)
    log.info("backup scheduler started (cron=%s)", backup_cron)


def _scheduled_retention() -> dict:
    """APScheduler entry-point wrapper.

    Sets a ``job-<uuid>`` into the ``request_id`` ContextVar so every
    log record emitted during the retention run carries a correlation
    ID. Without this the scheduler thread inherits the default ``"-"``
    and its logs can't be traced alongside request handlers.
    """
    import uuid

    try:
        from .observability import request_id_var
    except Exception:
        return run_retention()
    token = request_id_var.set(f"job-{uuid.uuid4().hex[:8]}")
    try:
        return run_retention()
    finally:
        request_id_var.reset(token)


def _scheduled_backup() -> dict:
    """APScheduler entry-point for the nightly backup."""
    import uuid

    try:
        from .observability import request_id_var
    except Exception:
        from . import backup as _bk
        return _bk.run_scheduled_backup()
    token = request_id_var.set(f"job-{uuid.uuid4().hex[:8]}")
    try:
        from . import backup as _bk
        return _bk.run_scheduled_backup()
    except Exception:
        log.exception("scheduled backup failed")
        raise
    finally:
        request_id_var.reset(token)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:
            pass
        _scheduler = None


__all__ = [
    "DEFAULT_POLICY",
    "ResolvedPolicy",
    "run_retention",
    "start_scheduler",
    "stop_scheduler",
]
