"""Tests for scheduler_runs retention sweep + settings toggle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import GlobalPolicy, SchedulerRun, session_factory
from app.main import app
from app.retention import run_retention


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist before any test in this module runs."""
    with TestClient(app):
        pass


def _seed_scheduler_run(days_ago: float) -> int:
    """Insert a SchedulerRun with started_at = now - days_ago. Returns its id."""
    with session_factory() as db:
        ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_ago)
        row = SchedulerRun(
            job="retention",
            started_at=ts,
            finished_at=ts + timedelta(seconds=1),
            duration_ms=1000,
            summary={"deleted": 0},
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id


def _set_scheduler_retention(days: int) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.scheduler_run_retention_days = days
        db.commit()


def test_sweep_purges_old_scheduler_runs() -> None:
    old_id = _seed_scheduler_run(180)
    recent_id = _seed_scheduler_run(10)
    now_id = _seed_scheduler_run(0)

    _set_scheduler_retention(30)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["scheduler_runs_purged"] >= 1

    with session_factory() as db:
        assert db.get(SchedulerRun, old_id) is None
        assert db.get(SchedulerRun, recent_id) is not None
        assert db.get(SchedulerRun, now_id) is not None


def test_zero_means_never_purge() -> None:
    old_id = _seed_scheduler_run(2000)

    _set_scheduler_retention(0)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["scheduler_runs_purged"] == 0

    with session_factory() as db:
        assert db.get(SchedulerRun, old_id) is not None


# ── Settings UI ────────────────────────────────────────────────────────


def _set_2fa_required(value: bool) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _reset_totp() -> None:
    from sqlalchemy import select as _sel

    from app.db import Account

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


@pytest.fixture()
def admin_client() -> TestClient:
    """Authenticated admin client with TOTP + 2FA gate reset."""
    with TestClient(app) as c:
        _reset_totp()
        _set_2fa_required(False)

        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        c.get("/admin/account")

        yield c

        _set_2fa_required(False)
        _reset_totp()


def test_settings_save_persists_window(admin_client: TestClient) -> None:
    _set_scheduler_retention(90)

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/settings",
        data={
            "_csrf": csrf,
            "snapshot_keep_last_n": "30",
            "snapshot_retain_days": "90",
            "max_bytes_per_user": "",
            "registration_enabled": "1",
            "default_role": "user",
            "banner_message": "",
            "audit_retention_days": "365",
            "scheduler_run_retention_days": "42",
        },
        follow_redirects=False,
    )
    assert r.status_code in (200, 303)

    with session_factory() as db:
        assert db.get(GlobalPolicy, 1).scheduler_run_retention_days == 42

    # Verify the settings.updated audit diff carries the from/to pair
    from sqlalchemy import select as _sel

    from app.db import AuditEvent

    with session_factory() as db:
        ev = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "settings.updated")
            .order_by(AuditEvent.id.desc())
        )
    assert ev is not None
    diff = ev.detail.get("changed", {})
    assert "scheduler_run_retention_days" in diff
    assert diff["scheduler_run_retention_days"]["from"] == 90
    assert diff["scheduler_run_retention_days"]["to"] == 42
