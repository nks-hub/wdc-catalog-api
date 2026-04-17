"""Personal Access Token regression suite.

Covers the full lifecycle via JSON API:
- create returns plaintext exactly once
- list hides plaintext; shows prefix + metadata
- bearer-auth accepts the plaintext token
- revoke immediately invalidates further use
- expired tokens stop authenticating
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def authed_client() -> tuple[TestClient, str, int]:
    """Fresh client + JWT + account_id for each test.

    Function-scoped so every test works against a clean set of tokens.
    """
    with TestClient(app) as c:
        email = f"pat-{uuid.uuid4().hex[:8]}@example.com"
        pw = "Passphrase-1234!"
        r = c.post(
            "/api/v1/auth/register",
            json={"email": email, "password": pw},
        )
        assert r.status_code == 200, r.text
        token = r.json()["token"]

        # Get account_id via /auth/me.
        r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        account_id = r.json()["id"]

        yield c, token, account_id


def test_create_returns_plaintext_once(authed_client) -> None:
    c, jwt, _ = authed_client
    r = c.post(
        "/api/v1/auth/tokens",
        json={"name": "ci-pipeline", "ttl_days": 30},
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "ci-pipeline"
    assert body["token"].startswith("nks_pat_")
    assert len(body["token"]) > 20
    assert body["expires_at"] is not None


def test_pat_authenticates_api_requests(authed_client) -> None:
    c, jwt, _ = authed_client
    # Mint a token.
    r = c.post(
        "/api/v1/auth/tokens",
        json={"name": "smoke"},
        headers={"Authorization": f"Bearer {jwt}"},
    )
    plaintext = r.json()["token"]

    # Use PAT (not JWT) to call /auth/me — must succeed.
    r = c.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {plaintext}"},
    )
    assert r.status_code == 200, r.text


def test_revoke_invalidates_pat_immediately(authed_client) -> None:
    c, jwt, _ = authed_client
    r = c.post(
        "/api/v1/auth/tokens",
        json={"name": "revoke-me"},
        headers={"Authorization": f"Bearer {jwt}"},
    )
    plaintext = r.json()["token"]
    token_id = r.json()["id"]

    # Works before revoke.
    r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {plaintext}"})
    assert r.status_code == 200

    # Revoke.
    r = c.delete(
        f"/api/v1/auth/tokens/{token_id}",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert r.status_code == 204

    # Blocked after revoke.
    r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {plaintext}"})
    assert r.status_code == 401


def test_list_shows_prefix_not_plaintext(authed_client) -> None:
    c, jwt, _ = authed_client
    r = c.post(
        "/api/v1/auth/tokens",
        json={"name": "listed"},
        headers={"Authorization": f"Bearer {jwt}"},
    )
    plaintext = r.json()["token"]

    r = c.get(
        "/api/v1/auth/tokens",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(it["name"] == "listed" for it in items)
    # Prefix matches first 10 chars, plaintext tail not returned.
    for it in items:
        assert "token" not in it
        assert len(it["prefix"]) == 10
    assert plaintext[:10] in {it["prefix"] for it in items}


def test_expired_pat_rejected(authed_client) -> None:
    """Hand-expire a token by rewinding ``expires_at`` in DB."""
    from sqlalchemy import select

    from app.db import PersonalAccessToken, session_factory

    c, jwt, _ = authed_client
    r = c.post(
        "/api/v1/auth/tokens",
        json={"name": "soon-expired", "ttl_days": 30},
        headers={"Authorization": f"Bearer {jwt}"},
    )
    plaintext = r.json()["token"]
    tid = r.json()["id"]

    with session_factory() as db:
        row = db.scalar(
            select(PersonalAccessToken).where(PersonalAccessToken.id == tid)
        )
        assert row is not None
        row.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
            minutes=1
        )
        db.commit()

    r = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {plaintext}"})
    assert r.status_code == 401


def test_other_account_cannot_revoke_foreign_token(authed_client) -> None:
    c, jwt_a, _ = authed_client
    r = c.post(
        "/api/v1/auth/tokens",
        json={"name": "alice"},
        headers={"Authorization": f"Bearer {jwt_a}"},
    )
    token_id = r.json()["id"]

    # Register Bob; he must not be able to revoke Alice's token.
    with TestClient(app) as bob:
        email = f"bob-{uuid.uuid4().hex[:8]}@example.com"
        r = bob.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "Passphrase-1234!"},
        )
        bob_jwt = r.json()["token"]
        r = bob.delete(
            f"/api/v1/auth/tokens/{token_id}",
            headers={"Authorization": f"Bearer {bob_jwt}"},
        )
        assert r.status_code == 404
