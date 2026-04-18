"""PAT ip_allowlist — CIDR enforcement, admin UI, and JSON API tests.

Tests 1-6 (Task 1): core CIDR enforcement via direct DB mint.
Tests 7-8 (Task 2): admin UI textarea parse + JSON API CIDR validation.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select as _sel

from app.main import app


# ── Helpers ─────────────────────────────────────────────────────────────


_LOOPBACK_CLIENT = ("127.0.0.1", 50000)


def _register_and_jwt(c: TestClient) -> tuple[str, int]:
    """Register a fresh account, return (jwt, account_id)."""
    email = f"al-{uuid.uuid4().hex[:8]}@example.com"
    r = c.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passphrase-5678!"},
    )
    assert r.status_code == 200, r.text
    jwt_token = r.json()["token"]
    r2 = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {jwt_token}"})
    assert r2.status_code == 200
    return jwt_token, r2.json()["id"]


def _mint_pat_direct(account_id: int, *, ip_allowlist: list[str] | None) -> str:
    """Mint a PAT directly via DB — no dependency on Task 2's API surface."""
    from app.db import session_factory
    from app import pats

    with session_factory() as db:
        _, plaintext = pats.issue(
            db,
            account_id=account_id,
            name="test-ip",
            ip_allowlist=ip_allowlist,
        )
        db.commit()
    return plaintext


# ── Task 1 tests (1-6) ──────────────────────────────────────────────────


def test_pat_without_allowlist_works_from_any_ip() -> None:
    """A PAT with ip_allowlist=None must succeed from any IP (no restriction)."""
    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        pat = _mint_pat_direct(account_id, ip_allowlist=None)

        r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pat}"})
        assert r.status_code == 200, r.text


def test_pat_with_matching_cidr_succeeds() -> None:
    """A PAT whose allowlist contains the client IP CIDR must return 200."""
    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        # TestClient configured with 127.0.0.1 as client address.
        pat = _mint_pat_direct(account_id, ip_allowlist=["127.0.0.0/8"])

        r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pat}"})
        assert r.status_code == 200, r.text


def test_pat_with_non_matching_cidr_returns_401() -> None:
    """A PAT whose allowlist does NOT include the client IP must return 401."""
    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        # Client is 127.0.0.1; 10.0.0.0/8 does not match.
        pat = _mint_pat_direct(account_id, ip_allowlist=["10.0.0.0/8"])

        r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pat}"})
        assert r.status_code == 401, r.text


def test_pat_with_multiple_cidrs_any_match_succeeds() -> None:
    """Any matching CIDR in the list is sufficient — OR semantics."""
    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        pat = _mint_pat_direct(
            account_id, ip_allowlist=["10.0.0.0/8", "127.0.0.0/8"]
        )

        r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pat}"})
        assert r.status_code == 200, r.text


def test_pat_with_malformed_cidr_is_skipped_gracefully() -> None:
    """A malformed CIDR entry is silently skipped; valid entry still matches."""
    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        pat = _mint_pat_direct(
            account_id, ip_allowlist=["not-a-cidr", "127.0.0.0/8"]
        )

        r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pat}"})
        assert r.status_code == 200, r.text


def test_pat_with_only_malformed_cidrs_returns_401() -> None:
    """When all stored CIDRs are malformed, no valid entry matches → 401."""
    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        pat = _mint_pat_direct(
            account_id, ip_allowlist=["not-a-cidr", "also-bad"]
        )

        r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pat}"})
        assert r.status_code == 401, r.text


# ── Task 2 tests (7-8) ──────────────────────────────────────────────────


@pytest.fixture()
def admin_client() -> TestClient:
    """Logged-in admin UI client (session cookie)."""
    with TestClient(app) as c:
        from app.db import Account, session_factory

        with session_factory() as db:
            acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
            if acct is not None:
                acct.totp_enabled = False
                acct.totp_secret = None
                acct.totp_recovery_hashes = None
                acct.totp_enabled_at = None
                db.commit()

        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        yield c


def test_admin_ui_mint_parses_allowlist_from_textarea(
    admin_client: TestClient,
) -> None:
    """POSTing newline-separated CIDRs stores a parsed list on the DB row."""
    from app.db import Account, PersonalAccessToken, session_factory

    admin_client.get("/admin/account")
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    r = admin_client.post(
        "/admin/account/tokens",
        data={
            "_csrf": csrf,
            "name": "ip-allowlist-test",
            "ip_allowlist_raw": "10.0.0.0/8\n192.168.0.0/16",
        },
    )
    assert r.status_code == 200, r.text

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        row = db.scalar(
            _sel(PersonalAccessToken)
            .where(PersonalAccessToken.account_id == acct.id)
            .where(PersonalAccessToken.name == "ip-allowlist-test")
            .order_by(PersonalAccessToken.id.desc())
        )
    assert row is not None
    assert row.ip_allowlist == ["10.0.0.0/8", "192.168.0.0/16"]


def test_json_api_rejects_malformed_cidr_at_request_time() -> None:
    """POST /api/v1/auth/tokens with a bad CIDR must return 422."""
    with TestClient(app) as c:
        _, account_id = _register_and_jwt(c)
        # Use a JWT for the write (PAT-free, avoids chicken-and-egg).
        email = f"al2-{uuid.uuid4().hex[:8]}@example.com"
        r = c.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "Passphrase-5678!"},
        )
        jwt_token = r.json()["token"]

        r2 = c.post(
            "/api/v1/auth/tokens",
            json={"name": "bad-cidr", "ip_allowlist": ["not-a-cidr"]},
            headers={"Authorization": f"Bearer {jwt_token}"},
        )
        assert r2.status_code == 422, r2.text
