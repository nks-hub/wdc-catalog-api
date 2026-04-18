"""KPI delta chips on /admin dashboard.

Operators see `▲ +12` / `▼ -3` / `—` next to the hero KPI + Webhooks
Sent row so "today busier than yesterday" is visible without navigating.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def admin_client() -> TestClient:
    with TestClient(app) as c:
        from app.db import Account, GlobalPolicy, session_factory
        from sqlalchemy import select as _sel

        with session_factory() as db:
            acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
            if acct is not None:
                acct.totp_enabled = False
                acct.totp_secret = None
                acct.totp_recovery_hashes = None
                acct.totp_enabled_at = None
            policy = db.get(GlobalPolicy, 1)
            if policy is not None:
                policy.require_2fa_for_admins = False
                policy.admin_ip_allowlist = None
            db.commit()

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


def _seed_audit_at(offset_hours: int, count: int = 1) -> None:
    """Insert N audit events dated offset_hours ago (backdated ORM write)."""
    from app.db import AuditEvent, session_factory

    when = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        hours=offset_hours
    )
    with session_factory() as db:
        for i in range(count):
            db.add(
                AuditEvent(
                    action=f"test.kpi-delta.{offset_hours}h",
                    resource_type="test",
                    resource_id=str(i),
                    created_at=when,
                )
            )
        db.commit()


def _wipe_recent_audit() -> None:
    """Delete every audit event inside the last 60 hours — clean slate for
    both the current-24h and prior-24h windows so ambient login-flow
    events don't skew the deltas."""
    from app.db import AuditEvent, session_factory
    from sqlalchemy import delete as _delete

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=60)
    with session_factory() as db:
        db.execute(_delete(AuditEvent).where(AuditEvent.created_at >= cutoff))
        db.commit()


def test_positive_delta_renders_up_arrow(admin_client: TestClient) -> None:
    """Current 24h > prior 24h → ▲ +N."""
    _wipe_recent_audit()
    # Current window (last 24h): 5 events at 1h ago
    _seed_audit_at(1, 5)
    # Prior window (24-48h ago): 2 events at 30h ago
    _seed_audit_at(30, 2)

    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "kpi-delta-up" in r.text
    assert "▲" in r.text
    # Check the current dashboard contains "vs prior 24h" copy.
    assert "vs prior 24h" in r.text


def test_negative_delta_renders_down_arrow(admin_client: TestClient) -> None:
    _wipe_recent_audit()
    _seed_audit_at(1, 2)  # current: 2
    _seed_audit_at(30, 10)  # prior: 10

    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "kpi-delta-down" in r.text
    assert "▼" in r.text


def test_flat_delta_renders_em_dash(admin_client: TestClient) -> None:
    _wipe_recent_audit()
    _seed_audit_at(1, 3)  # current: 3
    _seed_audit_at(30, 3)  # prior: 3 → delta 0

    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "kpi-delta-flat" in r.text
