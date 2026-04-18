"""OIDC SSO via Authentik — feature-flag gating, authorize URL shape,
callback flow, group→role mapping.

Mock httpx + jwt where necessary — we don't hit sso.nks-hub.cz in
tests. Real wire shape is verified manually after deploy + env upload.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(autouse=True, scope="module")
def _bootstrap_db():
    with TestClient(app, client=("127.0.0.1", 50000)):
        yield


# ── sso.sso_enabled() feature flag ────────────────────────────────────


def test_sso_enabled_returns_false_when_unset(monkeypatch):
    from app import sso

    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_ID", "")
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_SECRET", "")
    assert sso.sso_enabled() is False


def test_sso_enabled_requires_both_id_and_secret(monkeypatch):
    from app import sso

    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_ID", "x")
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_SECRET", "")
    assert sso.sso_enabled() is False, "id alone is not enough"
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_SECRET", "y")
    assert sso.sso_enabled() is True


def test_sso_login_route_404_when_disabled(monkeypatch):
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_ID", "")
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.get("/auth/sso/login", follow_redirects=False)
    assert r.status_code == 404


# ── authorize URL shape ───────────────────────────────────────────────


def test_auth_sso_login_redirects_to_authority(monkeypatch):
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("NKS_WDC_SSO_AUTHORITY", "https://sso.example.com")
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.get("/auth/sso/login", follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("https://sso.example.com/application/o/authorize/")
    assert "client_id=test-client-id" in loc
    assert "response_type=code" in loc
    assert "code_challenge_method=S256" in loc
    assert "scope=openid+email+profile+groups" in loc
    assert "state=" in loc
    # state cookie landed
    assert "nks_wdc_sso_state" in r.cookies


# ── state-cookie mismatch path ────────────────────────────────────────


def test_sso_callback_state_mismatch_redirects_to_login_error(monkeypatch):
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_ID", "x")
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_SECRET", "y")
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        # Pass state parameter without matching signed cookie → exchange_code
        # raises SSOError, handler redirects to /login?error=sso_failed.
        r = c.get(
            "/auth/sso/callback?code=c&state=s", follow_redirects=False
        )
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=sso_failed"


def test_sso_callback_idp_error_redirects_to_login_error(monkeypatch):
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_ID", "x")
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_SECRET", "y")
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.get(
            "/auth/sso/callback?error=access_denied", follow_redirects=False
        )
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=sso_failed"


# ── group → role mapping ──────────────────────────────────────────────


def test_is_admin_group_matches_default_groups(monkeypatch):
    from app import sso

    monkeypatch.setenv("NKS_WDC_SSO_ADMIN_GROUPS", "admin,superadmin")
    assert sso.is_admin_group(["admin"]) is True
    assert sso.is_admin_group(["superadmin", "other"]) is True
    assert sso.is_admin_group(["Admin"]) is True, "case-insensitive"
    assert sso.is_admin_group(["user"]) is False
    assert sso.is_admin_group([]) is False


def test_is_admin_group_respects_env_override(monkeypatch):
    from app import sso

    monkeypatch.setenv("NKS_WDC_SSO_ADMIN_GROUPS", "wdc-admins,ops")
    assert sso.is_admin_group(["wdc-admins"]) is True
    assert sso.is_admin_group(["admin"]) is False, "default list no longer applies"


# ── login page renders SSO button based on flag ───────────────────────


def test_login_page_no_sso_button_when_disabled(monkeypatch):
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_ID", "")
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.get("/login")
    assert r.status_code == 200
    assert "Sign in with NKS SSO" not in r.text


def test_login_page_shows_sso_button_when_enabled(monkeypatch):
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_ID", "x")
    monkeypatch.setenv("NKS_WDC_SSO_CLIENT_SECRET", "y")
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.get("/login")
    assert r.status_code == 200
    assert "Sign in with NKS SSO" in r.text
    assert '/auth/sso/login' in r.text


# ── allowlist sanity ──────────────────────────────────────────────────


def test_login_sso_on_security_allowlist():
    from app.observability import SECURITY_ACTION_ALLOWLIST
    assert "login.sso" in SECURITY_ACTION_ALLOWLIST


# ── logo swap reflects the PNG, not the old inline SVG ────────────────


def test_login_page_uses_logo_png():
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.get("/login")
    assert r.status_code == 200
    assert '/static/logo-icon.png' in r.text
    # Old inline SVG markers should be gone
    assert 'viewBox="0 0 48 48"' not in r.text or 'login-logomark' not in r.text.split('viewBox="0 0 48 48"')[0].split('<svg')[-1]
