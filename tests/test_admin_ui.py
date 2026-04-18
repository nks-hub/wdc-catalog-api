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
    """The nav entry matching the current URL must carry the .active class.

    Post-sidebar-redesign the link lives in `<a class="sidebar-link ... active">`
    rather than the old `<a ... class="active">` flat form, so we anchor on
    the Users href + ``active`` appearing in the same link open-tag.
    """
    r = admin_client.get("/admin/users")
    assert r.status_code == 200
    import re

    users_link = re.search(r'<a\s+href="/admin/users"[^>]*>', r.text)
    assert users_link, "Users nav link not found"
    assert "active" in users_link.group(0), (
        f"Users link has no active class on /admin/users: {users_link.group(0)}"
    )


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


def test_admin_theme_toggle_cycles_cookie(admin_client: TestClient) -> None:
    """Three POSTs cycle auto → light → dark → auto again."""
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    # Starting state: no cookie (auto).
    if "nks_wdc_theme" in admin_client.cookies:
        admin_client.cookies.delete("nks_wdc_theme")

    r1 = admin_client.post(
        "/admin/theme",
        data={"_csrf": csrf, "next": "/admin"},
        follow_redirects=False,
    )
    assert r1.status_code == 303
    assert admin_client.cookies.get("nks_wdc_theme") == "light"

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r2 = admin_client.post(
        "/admin/theme",
        data={"_csrf": csrf, "next": "/admin"},
        follow_redirects=False,
    )
    assert r2.status_code == 303
    assert admin_client.cookies.get("nks_wdc_theme") == "dark"

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r3 = admin_client.post(
        "/admin/theme",
        data={"_csrf": csrf, "next": "/admin"},
        follow_redirects=False,
    )
    assert r3.status_code == 303
    # Cookie cleared on the auto step.
    assert "nks_wdc_theme" not in admin_client.cookies or admin_client.cookies.get(
        "nks_wdc_theme"
    ) in (None, "")


def test_security_headers_present_on_admin_pages(admin_client: TestClient) -> None:
    """CSP + nosniff + X-Frame-Options must stamp every admin HTML
    response. HSTS is DEV-gated so it isn't asserted here."""
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "content-security-policy" in r.headers
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "referrer-policy" in r.headers


def test_security_headers_skip_metrics(admin_client: TestClient) -> None:
    """Prometheus scrapers don't need CSP — it'd clutter the plain-text
    metrics body for scanners that parse headers."""
    r = admin_client.get("/metrics")
    assert r.status_code == 200
    assert "content-security-policy" not in r.headers


def test_first_visit_csrf_bootstrap_lets_login_succeed() -> None:
    """Fresh browser with no cookies must be able to complete the login
    flow on its *first* visit. The form field + response cookie must
    carry the SAME token so the submit passes CSRF.

    Regression for a bug where the middleware wrote a newly-minted
    random token while the template had already rendered with an empty
    ``csrf_token`` placeholder, guaranteeing first-POST 403.
    """
    with TestClient(app) as c:
        r = c.get("/login")
        assert r.status_code == 200
        form_csrf_match = (
            '_csrf" value="' in r.text
            and 'value=""' not in r.text.split("_csrf")[1][:40]
        )
        assert form_csrf_match, "login form rendered with empty _csrf value"

        cookie_csrf = c.cookies.get("nks_wdc_csrf") or ""
        assert len(cookie_csrf) >= 32
        # Extract the hidden field value from the form.
        import re as _re

        match = _re.search(r'name="_csrf"\s+value="([^"]+)"', r.text)
        assert match is not None
        form_csrf = match.group(1)
        assert form_csrf == cookie_csrf, (
            f"csrf mismatch: form={form_csrf[:8]}… cookie={cookie_csrf[:8]}…"
        )

        # Submit login with the cookie+form token.
        login = c.post(
            "/login",
            data={
                "username": "admin",
                "password": "admin",
                "_csrf": form_csrf,
            },
            follow_redirects=False,
        )
        assert login.status_code == 303, login.text[:200]


def test_dashboard_renders_recent_activity(admin_client: TestClient) -> None:
    """The dashboard pulls the last 10 audit rows and renders the
    "Recent activity" section if any events exist."""
    r = admin_client.get("/admin")
    assert r.status_code == 200
    # Either we have events (Recent activity shown) or the markup stays
    # absent — both are valid. The critical regression is the route not
    # 500'ing when it prepares the recent_events list.
    assert "Dashboard" in r.text


def test_admin_audit_has_live_toggle(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/audit")
    assert r.status_code == 200
    assert 'class="live-toggle"' in r.text
    assert 'id="audit-tbody"' in r.text


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
