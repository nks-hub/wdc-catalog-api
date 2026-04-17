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
        ("/admin/revoked-tokens", "Revoked tokens"),
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


def test_admin_audit_csv_export(admin_client: TestClient) -> None:
    """CSV export must stream with correct content-type + header row."""
    r = admin_client.get("/admin/audit.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers.get("content-disposition", "")
    # First line is the CSV header.
    first = r.text.splitlines()[0] if r.text else ""
    for col in ("id", "created_at", "actor_email", "action"):
        assert col in first


def test_admin_error_page_renders_html_not_problem_json(
    admin_client: TestClient,
) -> None:
    """404 in the admin HTML area must surface as the templated error
    page, not Problem+JSON. Accept header drives this."""
    r = admin_client.get(
        "/admin/devices/no-such-device-123",
        headers={"Accept": "text/html"},
    )
    assert r.status_code == 404
    assert "text/html" in r.headers["content-type"].lower()
    assert "Not Found".lower() in r.text.lower()


def test_admin_unregistered_path_also_renders_html(
    admin_client: TestClient,
) -> None:
    """404s from unregistered routes (router-level miss) must also flow
    through the HTML content-negotiation path. Previously Starlette's
    default JSON handler was leaking through here."""
    r = admin_client.get(
        "/admin/nonexistent-page-xyz",
        headers={"Accept": "text/html"},
    )
    assert r.status_code == 404
    assert "text/html" in r.headers["content-type"].lower()


def test_api_404_stays_problem_json(admin_client: TestClient) -> None:
    """The /api/v1/* namespace must always return Problem+JSON on 404,
    even when Accept mentions HTML — machine clients depend on it."""
    r = admin_client.get(
        "/api/v1/catalog/nonexistent-app-42",
        headers={"Accept": "text/html,application/xhtml+xml"},
    )
    assert r.status_code == 404
    assert "application/problem+json" in r.headers["content-type"].lower()


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
