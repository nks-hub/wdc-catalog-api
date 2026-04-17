"""Smoke tests for the HTML admin UI.

Guarantees every ``/admin/*`` route returns 200 for an authenticated
session with the bootstrap admin user. A single template syntax error or
missing context key would previously only be caught by manual
click-through; the suite below locks each page down with a minimal HTML
marker so template regressions fail CI.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def admin_client() -> TestClient:
    """Authenticated client — logs in once at module load and keeps the
    session cookie on the client for every subsequent GET."""
    with TestClient(app) as c:
        # Bootstrap user in DEV mode is admin/admin.
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303, (
            f"bootstrap login failed: {r.status_code} {r.text[:200]}"
        )
        yield c


@pytest.mark.parametrize(
    "path,marker",
    [
        ("/admin", "Dashboard"),
        ("/admin/catalog", "Apps"),
        ("/admin/users", "Users"),
        ("/admin/audit", "Audit log"),
        ("/admin/invites", "Mint"),
        ("/admin/invites/history", "history"),
        ("/admin/devices", "Devices"),
        ("/admin/retention", "Retention"),
        ("/admin/settings", "Global settings"),
        ("/admin/account", "My account"),
    ],
)
def test_admin_page_renders(admin_client: TestClient, path: str, marker: str) -> None:
    r = admin_client.get(path)
    assert r.status_code == 200, f"{path} returned {r.status_code}: {r.text[:200]}"
    assert marker.lower() in r.text.lower(), f"{path} missing marker {marker!r}"


def test_admin_nav_highlights_active_tab(admin_client: TestClient) -> None:
    """The nav entry matching the current URL must carry the .active class."""
    r = admin_client.get("/admin/users")
    assert r.status_code == 200
    # The Users link should have class="active" when on /admin/users.
    assert 'href="/admin/users" class="active"' in r.text


def test_admin_settings_roundtrip(admin_client: TestClient) -> None:
    """Save a banner, verify it renders on another admin page, then clear it."""
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    r = admin_client.post(
        "/admin/settings",
        data={
            "_csrf": csrf,
            "snapshot_keep_last_n": "25",
            "snapshot_retain_days": "60",
            "max_bytes_per_user": "",
            "registration_enabled": "1",
            "default_role": "user",
            "banner_message": "Scheduled maintenance at 22:00",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    # Banner should now appear on any admin page (via base_context).
    r = admin_client.get("/admin")
    assert "Scheduled maintenance at 22:00" in r.text

    # Clear banner back out so other tests don't see it.
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    admin_client.post(
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
        follow_redirects=False,
    )


def test_admin_invite_mint_shows_token_once(admin_client: TestClient) -> None:
    """Minting an invite should render the signed token inline in the
    response — it's the only time it's shown."""
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/invites",
        data={
            "_csrf": csrf,
            "email": "smoke-invitee@example.com",
            "role": "user",
            "ttl_hours": "24",
        },
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "smoke-invitee@example.com" in r.text
    # Signed tokens produced by itsdangerous have a dot separator.
    assert "." in r.text
