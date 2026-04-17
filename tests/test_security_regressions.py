"""Regression tests that lock in recent security fixes.

Each test mirrors one of the CRITICAL/HIGH findings from the three
audit rounds so a future refactor that re-opens the vector breaks CI
before reaching production.
"""

from __future__ import annotations

import uuid
from importlib import reload

import pytest
from fastapi.testclient import TestClient

from app import ratelimit as _ratelimit
from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


# ──────────────────────────────────────────────────────────────────────
# Metrics bearer auth (H4)
# ──────────────────────────────────────────────────────────────────────


def test_metrics_open_when_token_unset(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("NKS_WDC_METRICS_TOKEN", raising=False)
    r = client.get("/metrics")
    assert r.status_code == 200
    assert b"nks_wdc_http_requests_total" in r.content


def test_metrics_requires_bearer_when_token_set(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("NKS_WDC_METRICS_TOKEN", "s3cret-scrape-token")
    # No header — blocked.
    assert client.get("/metrics").status_code == 401
    # Wrong token — blocked.
    assert (
        client.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code
        == 401
    )
    # Right token — passes through.
    r = client.get("/metrics", headers={"Authorization": "Bearer s3cret-scrape-token"})
    assert r.status_code == 200


# ──────────────────────────────────────────────────────────────────────
# Invite nonce replay (sec C2)
# ──────────────────────────────────────────────────────────────────────


def _bootstrap_owner(client: TestClient) -> str:
    """Create an owner account + return its JWT for admin operations."""
    email = f"invite-owner-{uuid.uuid4().hex[:6]}@example.com"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passphrase-1234!"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    # Promote to owner via direct DB write — matches the bootstrap flow.
    from sqlalchemy import select as _sel

    from app.db import Account, session_factory

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == email))
        assert acct is not None
        acct.role = "owner"
        db.commit()
    return token


def test_invite_cannot_be_redeemed_twice(client: TestClient) -> None:
    owner_token = _bootstrap_owner(client)
    auth = {"Authorization": f"Bearer {owner_token}"}
    invitee_email = f"invitee-{uuid.uuid4().hex[:6]}@example.com"

    # Mint an invite.
    r = client.post(
        "/api/v1/admin/invites",
        json={"email": invitee_email, "role": "user", "ttl_hours": 1},
        headers=auth,
    )
    assert r.status_code == 200, r.text
    invite_token = r.json()["token"]

    # First redemption succeeds.
    r1 = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": invite_token, "password": "Passphrase-5678!"},
    )
    assert r1.status_code == 200, r1.text

    # Second redemption — even though the account now exists, the
    # consumed-nonce check must fire first and 409 out.
    r2 = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": invite_token, "password": "Passphrase-5678!"},
    )
    assert r2.status_code == 409, r2.text


# ──────────────────────────────────────────────────────────────────────
# X-Forwarded-For trusted-proxy handling (H1)
# ──────────────────────────────────────────────────────────────────────


def test_client_ip_ignores_xff_when_no_trust_configured(monkeypatch) -> None:
    monkeypatch.delenv("NKS_WDC_TRUSTED_PROXIES", raising=False)
    reload(_ratelimit)

    class _FakeReq:
        def __init__(self) -> None:
            self.headers = {"x-forwarded-for": "9.9.9.9, 10.0.0.1"}
            self.client = type("C", (), {"host": "127.0.0.1"})()

    # With no trust, XFF is ignored and socket peer wins.
    assert _ratelimit.client_ip(_FakeReq()) == "127.0.0.1"


def test_client_ip_trusts_xff_from_allowlisted_proxy(monkeypatch) -> None:
    monkeypatch.setenv("NKS_WDC_TRUSTED_PROXIES", "127.0.0.0/8")
    reload(_ratelimit)

    class _FakeReq:
        def __init__(self) -> None:
            self.headers = {"x-forwarded-for": "9.9.9.9, 10.0.0.1"}
            self.client = type("C", (), {"host": "127.0.0.1"})()

    # Proxy in the allowlist → first XFF hop is the real client.
    assert _ratelimit.client_ip(_FakeReq()) == "9.9.9.9"

    # Reset back to module default so other tests aren't affected.
    monkeypatch.delenv("NKS_WDC_TRUSTED_PROXIES", raising=False)
    reload(_ratelimit)
