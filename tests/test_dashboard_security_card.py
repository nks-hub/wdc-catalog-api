"""Dashboard security signals card — mirror of the /admin/ops card but
only surfaces on the landing page when at least one signal is at warn
or bad severity. Quiet days keep the dashboard calm.
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


def _wipe_recent_audit() -> None:
    from app.db import AuditEvent, session_factory
    from sqlalchemy import delete as _delete

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=60)
    with session_factory() as db:
        db.execute(_delete(AuditEvent).where(AuditEvent.created_at >= cutoff))
        db.commit()


def _seed(action: str, count: int) -> None:
    from app.db import AuditEvent, session_factory

    with session_factory() as db:
        for i in range(count):
            db.add(AuditEvent(
                action=action,
                resource_type="account",
                resource_id=str(i),
            ))
        db.commit()


def test_calm_dashboard_omits_security_card(admin_client: TestClient) -> None:
    """When every signal is at ok severity, the card does NOT render."""
    _wipe_recent_audit()
    r = admin_client.get("/admin")
    assert r.status_code == 200
    # The "Security signals" heading only appears inside this card — its
    # absence confirms the block short-circuited on the all-ok path.
    assert "Security signals · last 24h" not in r.text


def test_warn_threshold_surfaces_card(admin_client: TestClient) -> None:
    _wipe_recent_audit()
    _seed("login.failed", 6)  # 6 >= warn(5)
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "Security signals · last 24h" in r.text
    import re
    assert re.search(r'pill pill-warn">6<', r.text) is not None


def test_bad_threshold_surfaces_card(admin_client: TestClient) -> None:
    _wipe_recent_audit()
    _seed("permission.denied", 15)  # 15 >= bad(10)
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "Security signals · last 24h" in r.text
    import re
    assert re.search(r'pill pill-suspended">15<', r.text) is not None


def test_card_links_to_full_breakdown(admin_client: TestClient) -> None:
    _wipe_recent_audit()
    _seed("totp.login_failed", 7)  # warn on aggregated login failures
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert 'href="/admin/ops"' in r.text
    assert 'href="/admin/audit?q=login.failed"' in r.text
