"""Tests for admin_sessions idle-revoke sweep + settings knob."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select as _sel

from app.db import AdminSession, GlobalPolicy, User, session_factory
from app.main import app
from app.retention import run_retention


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist before any test in this module runs."""
    with TestClient(app):
        pass


def _admin_user_id() -> int:
    with session_factory() as db:
        return db.scalar(_sel(User).where(User.username == "admin")).id


def _seed_session(
    fingerprint: str, days_ago: float, revoked_at: datetime | None = None
) -> int:
    """Insert an AdminSession with last_seen_at = now - days_ago. Returns its id."""
    with session_factory() as db:
        ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_ago)
        row = AdminSession(
            user_id=_admin_user_id(),
            fingerprint=fingerprint,
            ip="127.0.0.1",
            user_agent="test",
            last_seen_at=ts,
            revoked_at=revoked_at,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id


def _set_idle_days(days: int) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.admin_session_idle_days = days
        db.commit()


def _reset_sessions() -> None:
    """Delete all AdminSession rows for the admin user."""
    with session_factory() as db:
        rows = db.scalars(
            _sel(AdminSession).where(AdminSession.user_id == _admin_user_id())
        ).all()
        for r in rows:
            db.delete(r)
        db.commit()


def test_sweep_revokes_stale_sessions() -> None:
    _reset_sessions()
    stale_id = _seed_session("a" * 64, days_ago=40)
    recent_id = _seed_session("b" * 64, days_ago=5)
    fresh_id = _seed_session("c" * 64, days_ago=0)

    _set_idle_days(30)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["admin_sessions_auto_revoked"] == 1

    with session_factory() as db:
        assert db.get(AdminSession, stale_id).revoked_at is not None
        assert db.get(AdminSession, recent_id).revoked_at is None
        assert db.get(AdminSession, fresh_id).revoked_at is None

    _set_idle_days(0)


def test_zero_means_disabled() -> None:
    _reset_sessions()
    old_id = _seed_session("d" * 64, days_ago=2000)

    _set_idle_days(0)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["admin_sessions_auto_revoked"] == 0

    with session_factory() as db:
        assert db.get(AdminSession, old_id).revoked_at is None


def test_already_revoked_sessions_not_touched() -> None:
    _reset_sessions()
    pre_revoked_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=5)
    already_id = _seed_session("e" * 64, days_ago=40, revoked_at=pre_revoked_at)
    unrevoked_id = _seed_session("f" * 64, days_ago=40)

    _set_idle_days(30)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["admin_sessions_auto_revoked"] == 1

    with session_factory() as db:
        already_row = db.get(AdminSession, already_id)
        assert already_row.revoked_at == pre_revoked_at
        assert db.get(AdminSession, unrevoked_id).revoked_at is not None

    _set_idle_days(0)


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
        _set_idle_days(0)


def test_settings_save_persists_idle_days(admin_client: TestClient) -> None:
    _set_idle_days(0)

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
            "scheduler_run_retention_days": "90",
            "webhook_delivery_retention_days": "30",
            "admin_session_idle_days": "14",
        },
        follow_redirects=False,
    )
    assert r.status_code in (200, 303)

    with session_factory() as db:
        assert db.get(GlobalPolicy, 1).admin_session_idle_days == 14

    from app.db import AuditEvent

    with session_factory() as db:
        ev = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "settings.updated")
            .order_by(AuditEvent.id.desc())
        )
    assert ev is not None
    diff = ev.detail.get("changed", {})
    assert "admin_session_idle_days" in diff
    assert diff["admin_session_idle_days"]["from"] == 0
    assert diff["admin_session_idle_days"]["to"] == 14
