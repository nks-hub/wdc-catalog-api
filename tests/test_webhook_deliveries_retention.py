"""Tests for webhook_deliveries retention sweep + settings toggle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import GlobalPolicy, WebhookDelivery, session_factory
from app.main import app
from app.retention import run_retention


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist before any test in this module runs."""
    with TestClient(app):
        pass


def _seed_delivery(days_ago: float) -> int:
    """Insert a WebhookDelivery with created_at = now - days_ago. Returns its id."""
    with session_factory() as db:
        ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_ago)
        row = WebhookDelivery(
            url="http://example.com/hook",
            event_action="test.retention",
            status_code=204,
            duration_ms=5,
            error=None,
            created_at=ts,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id


def _set_webhook_retention(days: int) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.webhook_delivery_retention_days = days
        db.commit()


def test_sweep_purges_old_webhook_deliveries() -> None:
    old_id = _seed_delivery(90)
    recent_id = _seed_delivery(10)
    now_id = _seed_delivery(0)

    _set_webhook_retention(30)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["webhook_deliveries_purged"] >= 1

    with session_factory() as db:
        assert db.get(WebhookDelivery, old_id) is None
        assert db.get(WebhookDelivery, recent_id) is not None
        assert db.get(WebhookDelivery, now_id) is not None


def test_zero_means_never_purge() -> None:
    old_id = _seed_delivery(2000)

    _set_webhook_retention(0)

    with session_factory() as db:
        summary = run_retention(db)
        db.commit()

    assert summary["webhook_deliveries_purged"] == 0

    with session_factory() as db:
        assert db.get(WebhookDelivery, old_id) is not None


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
    _set_webhook_retention(30)

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
            "webhook_delivery_retention_days": "14",
        },
        follow_redirects=False,
    )
    assert r.status_code in (200, 303)

    with session_factory() as db:
        assert db.get(GlobalPolicy, 1).webhook_delivery_retention_days == 14

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
    assert "webhook_delivery_retention_days" in diff
    assert diff["webhook_delivery_retention_days"]["from"] == 30
    assert diff["webhook_delivery_retention_days"]["to"] == 14
