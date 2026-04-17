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
    idem_res = session.execute(
        delete(IdempotencyRecord).where(IdempotencyRecord.expires_at <= now)
    )
    rev_res = session.execute(
        delete(RevokedToken).where(
            RevokedToken.expires_at.is_not(None),
            RevokedToken.expires_at <= now,
        )
    )
    return {
        "accounts": len(account_ids),
        "deleted": deleted_total,
        "idempotency_purged": idem_res.rowcount or 0,
        "revoked_tokens_purged": rev_res.rowcount or 0,
    }


def run_retention(db: Optional[Session] = None) -> dict:
    """Iterate every account and apply their resolved retention policy.

    When *db* is supplied (manual admin run) the caller owns the commit
    lifecycle — we only flush. When *db* is None (scheduler) a fresh
    session is opened, committed, and closed exactly once.
    """
    if db is not None:
        summary = _do_retention(db)
        db.flush()
    else:
        session = session_factory()
        try:
            summary = _do_retention(session)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    try:
        from .observability import RETENTION_DELETED
        RETENTION_DELETED.inc(summary["deleted"])
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
    sched.add_job(run_retention, trigger, id="retention-daily", replace_existing=True)
    sched.start()
    _scheduler = sched
    log.info("retention scheduler started (cron=%s)", cron)


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
