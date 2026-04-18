"""Tests for /admin/search global search endpoint."""

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


def test_search_empty_query_renders_hint(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/search")
    assert r.status_code == 200
    assert "Enter a query" in r.text


def test_search_finds_apps_by_id_substring(admin_client: TestClient) -> None:
    from app.db import App, session_factory
    from app.service import create_app as _svc_create_app

    app_id = "search-target-app"
    with session_factory() as db:
        existing = db.get(App, app_id)
        if existing is None:
            _svc_create_app(db, app_id=app_id, display_name="Search Target", category="other")

    r = admin_client.get("/admin/search?q=search-target")
    assert r.status_code == 200
    assert "search-target-app" in r.text


def test_search_finds_users_by_email(admin_client: TestClient) -> None:
    from app.auth import hash_password
    from app.db import Account, session_factory

    email = "search-hit@example.com"
    with session_factory() as db:
        if not db.scalar(_sel(Account).where(Account.email == email)):
            db.add(Account(email=email, password_hash=hash_password("x"), role="user"))
            db.commit()

    r = admin_client.get("/admin/search?q=search-hit")
    assert r.status_code == 200
    assert email in r.text


def test_search_finds_audit_by_action(admin_client: TestClient) -> None:
    from app.db import AuditEvent, session_factory

    with session_factory() as db:
        db.add(AuditEvent(action="search.test.event", resource_type="account", resource_id="1"))
        db.commit()

    r = admin_client.get("/admin/search?q=search.test")
    assert r.status_code == 200
    assert "search.test.event" in r.text


def test_no_match_renders_empty_state(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/search?q=zzz-no-match-xyz-never")
    assert r.status_code == 200
    assert "No matches" in r.text
    assert "zzz-no-match-xyz-never" in r.text
