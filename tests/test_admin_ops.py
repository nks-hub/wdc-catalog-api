"""Tests for /admin/ops diagnostics page."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select as _sel

from app.main import app


def _set_2fa_required(value: bool) -> None:
    from app.db import GlobalPolicy, session_factory

    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _reset_totp() -> None:
    from app.db import Account, session_factory

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


def test_ops_page_renders(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    assert "Ops diagnostics" in r.text
    for marker in [
        "Version",
        "Uptime",
        "Active sessions",
        "Total events",
        "Enabled",
        "Cron",
    ]:
        assert marker in r.text


def test_ops_page_shows_current_version(admin_client: TestClient) -> None:
    from app import __version__

    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    assert __version__ in r.text


def test_ops_page_reflects_active_sessions_count(admin_client: TestClient) -> None:
    """Fixture login creates at least one active session; verify a non-zero value renders."""
    import re

    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    # The page renders "Active sessions" followed by the count in a <b> tag.
    # The fixture login itself creates at least one session row.
    match = re.search(r"Active sessions\s*</span>\s*<b>(\d+)</b>", r.text)
    assert match is not None, "Active sessions count not found in page"
    assert int(match.group(1)) >= 1


def test_ops_page_requires_auth() -> None:
    with TestClient(app, follow_redirects=False) as c:
        r = c.get("/admin/ops")
    assert r.status_code in (302, 303)
    assert "/login" in r.headers.get("location", "")


def test_ops_nav_link_visible(admin_client: TestClient) -> None:
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert 'href="/admin/ops"' in r.text
