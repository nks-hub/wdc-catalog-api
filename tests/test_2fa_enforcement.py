"""Tests for the GlobalPolicy.require_2fa_for_admins enforcement gate."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

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
    """Clear TOTP state on the admin account so tests start clean."""
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


def _enable_totp() -> None:
    """Directly enable TOTP on the admin account (bypassing the confirm step)."""
    from app.db import Account, session_factory
    from app import totp as _totp
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_secret = _totp.new_secret()
            acct.totp_enabled = True
            db.commit()


@pytest.fixture()
def admin_client():
    """Authenticated admin client with clean TOTP state.

    The TestClient context manager triggers the app lifespan (create_all),
    so DB helpers must be called inside the ``with`` block.
    """
    with TestClient(app) as c:
        # DB is now initialised — safe to manipulate state.
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
        yield c

        # Teardown: always reset the policy flag so later suites are not affected.
        _set_2fa_required(False)
        _reset_totp()


def test_gate_off_allows_admin_paths(admin_client: TestClient) -> None:
    """When require_2fa_for_admins is False and TOTP not set, /admin returns 200."""
    _set_2fa_required(False)
    r = admin_client.get("/admin", follow_redirects=False)
    assert r.status_code == 200


def test_gate_on_no_totp_redirects(admin_client: TestClient) -> None:
    """When gate is on and admin has no TOTP, /admin redirects to /admin/account."""
    _set_2fa_required(True)
    _reset_totp()
    r = admin_client.get("/admin", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers.get("location", "")
    assert "/admin/account" in location


def test_gate_on_with_totp_allows(admin_client: TestClient) -> None:
    """When gate is on but admin has TOTP enabled, /admin returns 200."""
    _set_2fa_required(True)
    _enable_totp()
    r = admin_client.get("/admin", follow_redirects=False)
    assert r.status_code == 200


def test_gate_on_allows_totp_setup_routes(admin_client: TestClient) -> None:
    """With gate on and no TOTP, the setup POST is not gated — returns 200."""
    _set_2fa_required(True)
    _reset_totp()
    # Fetch CSRF token first via the allowed /admin/account page.
    admin_client.get("/admin/account")
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/account/totp/setup",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 200


def test_gate_on_shows_banner_on_account_page(admin_client: TestClient) -> None:
    """With gate on and no TOTP, /admin/account renders the enforcement banner."""
    _set_2fa_required(True)
    _reset_totp()
    r = admin_client.get("/admin/account", follow_redirects=False)
    assert r.status_code == 200
    assert "Two-factor authentication is required by instance policy" in r.text


def test_logout_always_works_under_gate(admin_client: TestClient) -> None:
    """POST /logout always succeeds even when the enforcement gate is active."""
    _set_2fa_required(True)
    _reset_totp()
    admin_client.get("/login")
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/logout",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    # Logout redirects to /login — any 3xx is success.
    assert r.status_code in (302, 303)
    assert "/login" in r.headers.get("location", "")


def test_save_settings_toggles_2fa_requirement(admin_client: TestClient) -> None:
    """Settings form flips require_2fa_for_admins + audits the diff."""
    from app.db import GlobalPolicy, session_factory

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    # Flip on
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
            "require_2fa_for_admins": "1",
        },
    )
    assert r.status_code in (200, 303)
    with session_factory() as db:
        assert db.get(GlobalPolicy, 1).require_2fa_for_admins is True

    # The checkbox renders as checked on reload.
    # Enable TOTP first so the gate doesn't block the settings page.
    _enable_totp()
    page = admin_client.get("/admin/settings")
    assert 'name="require_2fa_for_admins" value="1" checked' in page.text
    _reset_totp()

    # Audit row carries the diff.
    from app.db import AuditEvent
    from sqlalchemy import select as _sel

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "settings.updated")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    changed = (evt.detail or {}).get("changed", {})
    assert "require_2fa_for_admins" in changed
    assert changed["require_2fa_for_admins"]["to"] is True

    # Flip off (omit the field). Enable TOTP so the POST itself isn't gated.
    _enable_totp()
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
        },
    )
    assert r.status_code in (200, 303)
    with session_factory() as db:
        assert db.get(GlobalPolicy, 1).require_2fa_for_admins is False
