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
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from sqlalchemy import delete

from .db import (
    Account,
    GlobalPolicy,
    IdempotencyRecord,
    RevokedToken,
    SnapshotRetentionPolicy,
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
        ids = [row[0] for row in session.execute(
            select(pk_col).where(filter_expr).limit(_SQLITE_BATCH_SIZE)
        ).all()]
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
        session, IdempotencyRecord,
        IdempotencyRecord.expires_at <= now,
    )
    revoked_purged = _batched_delete(
        session, RevokedToken,
        (RevokedToken.expires_at.is_not(None)) & (RevokedToken.expires_at <= now),
    )
    return {
        "accounts": len(account_ids),
        "deleted": deleted_total,
        "idempotency_purged": idempotency_purged,
        "revoked_tokens_purged": revoked_purged,
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
    dialect = session.bind.dialect.name if session.bind else ""
    if dialect != "postgresql":
        return True
    result = session.execute(
        text("SELECT pg_try_advisory_lock(:k)"), {"k": _RETENTION_LOCK_KEY}
    ).scalar()
    return bool(result)


def run_retention(db: Optional[Session] = None) -> dict:
    """Iterate every account and apply their resolved retention policy.

    When *db* is supplied (manual admin run) the caller owns the commit
    lifecycle — we only flush. When *db* is None (scheduler) a fresh
    session is opened, committed, and closed exactly once.

    On Postgres the scheduler path acquires ``pg_try_advisory_lock`` so
    multi-worker deployments don't run retention N times in parallel.
    Losers return early with ``{"skipped": True}`` and don't touch DB.
    """
    if db is not None:
        summary = _do_retention(db)
        db.flush()
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
                    "skipped": True,
                }
            summary = _do_retention(session)
            session.commit()
        except Exception:
            session.rollback()
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
        log.warning("Invalid NKS_WDC_RETENTION_CRON=%s: %s — defaulting daily 03:00", cron, exc)
        trigger = CronTrigger.from_crontab("0 3 * * *", timezone="UTC")
    sched.add_job(_scheduled_retention, trigger, id="retention-daily", replace_existing=True)
    sched.start()
    _scheduler = sched
    log.info("retention scheduler started (cron=%s)", cron)


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
