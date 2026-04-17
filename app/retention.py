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

from .db import (
    Account,
    GlobalPolicy,
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


def run_retention(db: Optional[Session] = None) -> dict:
    """Iterate every account and apply their resolved policy.

    Returns a summary dict: ``{"accounts": N, "deleted": total_rows}``.
    Safe to call concurrently (relies on DB-level row deletion; no
    shared in-memory state).
    """
    close_after = db is None
    session = db or session_factory()
    deleted_total = 0
    account_ids = [a.id for a in session.scalars(select(Account)).all()]
    try:
        for acc_id in account_ids:
            policy = _resolve_policy(session, acc_id)
            deleted_total += purge_auto_older_than(
                session,
                account_id=acc_id,
                keep_last_n=policy.keep_last_n_auto,
                auto_expire_days=policy.auto_expire_days,
                keep_labeled=policy.keep_labeled_forever,
            )
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        if close_after:
            session.close()

    summary = {"accounts": len(account_ids), "deleted": deleted_total}
    log.info("retention pass: %s", summary)
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
