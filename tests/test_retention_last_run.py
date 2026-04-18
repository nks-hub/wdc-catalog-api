"""Tests for persistent scheduler_runs tracking + admin UI wiring."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select as _sel

from app.db import SchedulerRun, session_factory
from app.main import app
from app.retention import run_retention


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist before any test in this module runs."""
    with TestClient(app):
        pass


def _clear_scheduler_runs() -> None:
    with session_factory() as db:
        db.query(SchedulerRun).delete()
        db.commit()


def _set_2fa_required(value: bool) -> None:
    from app.db import GlobalPolicy

    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _reset_totp() -> None:
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


def test_manual_run_writes_scheduler_run_row() -> None:
    _clear_scheduler_runs()

    with session_factory() as db:
        run_retention(db)
        db.commit()

    with session_factory() as db:
        rows = db.scalars(_sel(SchedulerRun).where(SchedulerRun.job == "retention")).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.job == "retention"
        assert row.finished_at is not None
        assert row.error is None
        assert isinstance(row.summary, dict)
        assert "deleted" in row.summary
        assert "accounts" in row.summary


def test_retention_page_shows_last_run(admin_client: TestClient) -> None:
    _clear_scheduler_runs()

    with session_factory() as db:
        row = SchedulerRun(
            job="retention",
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
            finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
            duration_ms=42,
            summary={"deleted": 7, "accounts": 2, "idempotency_purged": 0,
                     "revoked_tokens_purged": 0, "audit_events_purged": 3},
            error=None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        started_iso = row.started_at.isoformat()

    r = admin_client.get("/admin/retention")
    assert r.status_code == 200
    assert started_iso in r.text or '"deleted": 7' in r.text or "deleted" in r.text


def test_ops_page_shows_last_run(admin_client: TestClient) -> None:
    _clear_scheduler_runs()

    with session_factory() as db:
        row = SchedulerRun(
            job="retention",
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
            finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
            duration_ms=55,
            summary={"deleted": 5, "accounts": 1, "idempotency_purged": 0,
                     "revoked_tokens_purged": 0, "audit_events_purged": 0},
            error=None,
        )
        db.add(row)
        db.commit()

    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    assert "Last run" in r.text
    assert "pill-ok" in r.text


def test_run_records_duration_ms() -> None:
    _clear_scheduler_runs()

    with session_factory() as db:
        run_retention(db)
        db.commit()

    with session_factory() as db:
        row = db.scalar(
            _sel(SchedulerRun)
            .where(SchedulerRun.job == "retention")
            .order_by(SchedulerRun.started_at.desc())
            .limit(1)
        )
        assert row is not None
        assert row.duration_ms is not None and row.duration_ms >= 0
