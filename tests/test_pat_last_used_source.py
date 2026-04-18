"""PAT last-used source tracking — IP + UA stamped on auth success.

Test 1: successful auth stamps last_used_ip + last_used_ua.
Test 2: missing UA header leaves last_used_ua NULL.
Test 3: UA longer than 256 chars is truncated to 256.
Test 4: admin account page renders source details for a seeded PAT.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select as _sel

from app.main import app


_LOOPBACK_CLIENT = ("127.0.0.1", 50000)


# ── Helpers ──────────────────────────────────────────────────────────────


def _register_and_jwt(c: TestClient) -> tuple[str, int]:
    """Register a fresh account, return (jwt, account_id)."""
    email = f"lus-{uuid.uuid4().hex[:8]}@example.com"
    r = c.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passphrase-5678!"},
    )
    assert r.status_code == 200, r.text
    jwt_token = r.json()["token"]
    r2 = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {jwt_token}"})
    assert r2.status_code == 200
    return jwt_token, r2.json()["id"]


def _mint_pat_direct(account_id: int) -> str:
    """Mint a RW PAT directly via DB, return plaintext."""
    from app.db import session_factory
    from app import pats

    with session_factory() as db:
        _, plaintext = pats.issue(
            db, account_id=account_id, name="test-lus", read_only=False
        )
        db.commit()
    return plaintext


# ── Tests ────────────────────────────────────────────────────────────────


def test_pat_auth_stamps_last_used_ip_and_ua() -> None:
    """Successful PAT auth stamps last_used_ip and last_used_ua on the row."""
    from app.db import PersonalAccessToken, session_factory

    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        pat_plain = _mint_pat_direct(account_id)

        r = c.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {pat_plain}",
                "User-Agent": "test-agent/1.0",
            },
        )
        assert r.status_code == 200

    with session_factory() as db:
        prefix = pat_plain[:10]
        row = db.scalar(
            _sel(PersonalAccessToken).where(PersonalAccessToken.token_prefix == prefix)
        )
    assert row is not None
    assert row.last_used_ip == "127.0.0.1"
    assert row.last_used_ua == "test-agent/1.0"
    assert row.last_used_at is not None


def test_pat_auth_without_ua_header_leaves_ua_null() -> None:
    """When no User-Agent header is sent, last_used_ua stays NULL; IP still stamped."""
    from app.db import PersonalAccessToken, session_factory

    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        pat_plain = _mint_pat_direct(account_id)

        # Build headers dict without User-Agent so httpx sends none
        r = c.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {pat_plain}",
                "User-Agent": "",
            },
        )
        assert r.status_code == 200

    with session_factory() as db:
        prefix = pat_plain[:10]
        row = db.scalar(
            _sel(PersonalAccessToken).where(PersonalAccessToken.token_prefix == prefix)
        )
    assert row is not None
    assert row.last_used_ip == "127.0.0.1"
    # Empty UA header → (""[:256] or None) == None
    assert row.last_used_ua is None


def test_ua_truncated_to_256_chars() -> None:
    """A UA string longer than 256 chars is stored truncated to exactly 256."""
    from app.db import PersonalAccessToken, session_factory

    long_ua = "A" * 500

    with TestClient(app, client=_LOOPBACK_CLIENT) as c:
        _, account_id = _register_and_jwt(c)
        pat_plain = _mint_pat_direct(account_id)

        r = c.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {pat_plain}",
                "User-Agent": long_ua,
            },
        )
        assert r.status_code == 200

    with session_factory() as db:
        prefix = pat_plain[:10]
        row = db.scalar(
            _sel(PersonalAccessToken).where(PersonalAccessToken.token_prefix == prefix)
        )
    assert row is not None
    assert len(row.last_used_ua) == 256


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


def test_account_page_shows_source_details(admin_client: TestClient) -> None:
    """Account page renders IP + UA source details for a seeded PAT."""
    from datetime import datetime, timezone

    from app.db import Account, session_factory
    from app import pats

    # Trigger Account row creation by visiting an authenticated admin page
    admin_client.get("/admin/account")

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert acct is not None, "admin@admin.local account not created by page visit"
        row, _ = pats.issue(
            db, account_id=acct.id, name="source-detail-test", read_only=False
        )
        row.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)
        row.last_used_ip = "203.0.113.42"
        row.last_used_ua = "curl/7.88"
        db.commit()

    r = admin_client.get("/admin/account")
    assert r.status_code == 200
    assert "203.0.113.42" in r.text
    assert "curl/7.88" in r.text
    assert 'summary class="muted"' in r.text
