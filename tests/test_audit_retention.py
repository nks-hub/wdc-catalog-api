"""Tests for audit-event retention sweep + settings toggle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import AuditEvent, GlobalPolicy, session_factory
from app.main import app
from app.retention import run_retention


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist before any test in this module runs."""
    with TestClient(app):
        pass


def _seed_audit_event(days_ago: float) -> int:
    """Insert an AuditEvent with created_at = now - days_ago. Returns its id."""
    with session_factory() as db:
        e = AuditEvent(
            action="test.backdated",
            resource_type="account",
            resource_id="1",
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
            - timedelta(days=days_ago),
        )
        db.add(e)
        db.commit()
        db.refresh(e)
        return e.id


def _set_audit_retention(days: int) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.audit_retention_days = days
        db.commit()


def test_audit_retention_purges_old_rows() -> None:
    old_id = _seed_audit_event(400)
    recent_id = _seed_audit_event(10)
    now_id = _seed_audit_event(0)

    _set_audit_retention(30)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["audit_events_purged"] >= 1

    with session_factory() as db:
        assert db.get(AuditEvent, old_id) is None
        assert db.get(AuditEvent, recent_id) is not None
        assert db.get(AuditEvent, now_id) is not None


def test_audit_retention_default_365_days_keeps_recent() -> None:
    id_100 = _seed_audit_event(100)
    id_now = _seed_audit_event(0)

    _set_audit_retention(365)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["audit_events_purged"] == 0

    with session_factory() as db:
        assert db.get(AuditEvent, id_100) is not None
        assert db.get(AuditEvent, id_now) is not None


def test_audit_retention_zero_means_never_purge() -> None:
    old_id = _seed_audit_event(2000)

    _set_audit_retention(0)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["audit_events_purged"] == 0

    with session_factory() as db:
        assert db.get(AuditEvent, old_id) is not None


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


def test_save_settings_updates_audit_retention_days(admin_client: TestClient) -> None:
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
            "audit_retention_days": "42",
        },
        follow_redirects=False,
    )
    assert r.status_code in (200, 303)

    with session_factory() as db:
        assert db.get(GlobalPolicy, 1).audit_retention_days == 42
