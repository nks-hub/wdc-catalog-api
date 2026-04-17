"""CSRF double-submit protection for the admin UI."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _login(client: TestClient) -> tuple[str, str]:
    """Submit the login form and return (session_cookie, csrf_token)."""
    # GET /login first so the middleware drops a CSRF cookie
    r = client.get("/login")
    csrf = r.cookies.get("nks_wdc_csrf")
    assert csrf
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    return r.cookies.get("nks_wdc_catalog_session"), csrf


def test_admin_post_without_csrf_rejected(client: TestClient):
    _login(client)
    # Session cookie is on the client, CSRF cookie too — but we omit the
    # form field to simulate a cross-site form submission.
    r = client.post(
        "/admin/new",
        data={"id": "csrf-test-app"},
        follow_redirects=False,
    )
    assert r.status_code == 403


def test_admin_post_with_wrong_csrf_rejected(client: TestClient):
    _login(client)
    r = client.post(
        "/admin/new",
        data={
            "id": "csrf-test-app",
            "_csrf": "some-other-value",
        },
        follow_redirects=False,
    )
    assert r.status_code == 403


def test_admin_post_with_matching_csrf_succeeds(client: TestClient):
    _session, csrf = _login(client)
    r = client.post(
        "/admin/new",
        data={
            "id": "csrf-test-allowed",
            "display_name": "CSRF Test",
            "_csrf": csrf,
        },
        follow_redirects=False,
    )
    # Redirect after success → 303 back to /admin/apps/csrf-test-allowed
    assert r.status_code in (303, 303)


def test_login_requires_csrf(client: TestClient):
    # Fresh client to drop all cookies so we can test the initial flow
    with TestClient(app) as fresh:
        r = fresh.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        # Without a CSRF cookie/form pair the login POST must be rejected.
        assert r.status_code == 403


def test_metrics_endpoint_unaffected_by_csrf(client: TestClient):
    # Sanity: non-admin routes don't get blocked by the CSRF middleware.
    r = client.get("/metrics")
    assert r.status_code == 200
