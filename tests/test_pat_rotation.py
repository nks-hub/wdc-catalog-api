"""Regression tests — ``POST /api/v1/auth/tokens/{id}/rotate`` atomically
revokes a PAT and mints a replacement carrying over name, read-only flag,
IP allowlist and expiry, emitting a distinct ``pat.rotated`` audit event.

Separate action from ``pat.created`` / ``pat.revoked`` so forensics can
tell a rotation from an ad-hoc mint — which matters when triaging a
compromised-token incident.
"""

from __future__ import annotations


import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(autouse=True, scope="module")
def _bootstrap_db():
    with TestClient(app, client=("127.0.0.1", 50000)):
        yield


def _make_account_and_jwt(email: str) -> tuple[int, dict]:
    from app.db import Account, session_factory
    from app.auth import hash_password
    from app.devices import create_token as _create_jwt
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == email))
        if acct is None:
            acct = Account(
                email=email,
                password_hash=hash_password("correct-horse-battery-staple"),
                role="user",
            )
            db.add(acct)
            db.commit()
            db.refresh(acct)
        account_id = acct.id
        token_version = acct.token_version

    jwt_token = _create_jwt(account_id, email, token_version=token_version)
    return account_id, {"Authorization": f"Bearer {jwt_token}"}


def test_rotate_issues_new_token_and_revokes_old():
    _, auth = _make_account_and_jwt("pat-rotate@example.com")

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.post(
            "/api/v1/auth/tokens",
            json={
                "name": "rotating-ci",
                "ttl_days": 30,
                "read_only": True,
                "ip_allowlist": ["10.0.0.0/8"],
            },
            headers=auth,
        )
        assert r.status_code == 201, r.text
        old_id = r.json()["id"]
        old_plaintext = r.json()["token"]

        r2 = c.post(
            f"/api/v1/auth/tokens/{old_id}/rotate",
            headers=auth,
        )
        assert r2.status_code == 201, r2.text
        body = r2.json()
        new_id = body["id"]
        new_plaintext = body["token"]

    assert new_id != old_id
    assert new_plaintext != old_plaintext
    assert body["name"] == "rotating-ci"
    assert body["expires_at"] is not None

    # Old row revoked, new row carries over attributes.
    from app.db import PersonalAccessToken, session_factory

    with session_factory() as db:
        old = db.get(PersonalAccessToken, old_id)
        new = db.get(PersonalAccessToken, new_id)

    assert old is not None and old.revoked_at is not None
    assert new is not None and new.revoked_at is None
    assert new.read_only is True
    assert new.ip_allowlist == ["10.0.0.0/8"]
    # Expiry carried over — not silently extended.
    assert old.expires_at is not None and new.expires_at is not None
    delta = abs((new.expires_at - old.expires_at).total_seconds())
    assert delta < 2.0


def test_rotate_emits_pat_rotated_audit_event():
    _, auth = _make_account_and_jwt("pat-rotate-audit@example.com")

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.post(
            "/api/v1/auth/tokens",
            json={"name": "audit-rotate"},
            headers=auth,
        )
        assert r.status_code == 201
        old_id = r.json()["id"]

        r2 = c.post(f"/api/v1/auth/tokens/{old_id}/rotate", headers=auth)
        assert r2.status_code == 201
        new_id = r2.json()["id"]

    from app.db import AuditEvent, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "pat.rotated")
            .where(AuditEvent.resource_id == str(new_id))
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    assert evt.resource_type == "pat"
    detail = evt.detail or {}
    assert detail.get("old_token_id") == old_id
    assert detail.get("new_name") == "audit-rotate"
    assert str(detail.get("new_prefix", "")).startswith("nks_pat_")


def test_rotate_returns_404_for_foreign_token():
    """A user cannot rotate somebody else's PAT."""
    owner_id, owner_auth = _make_account_and_jwt("pat-rotate-owner@example.com")
    _, intruder_auth = _make_account_and_jwt("pat-rotate-intruder@example.com")

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.post(
            "/api/v1/auth/tokens",
            json={"name": "owned"},
            headers=owner_auth,
        )
        assert r.status_code == 201
        owned_id = r.json()["id"]

        r2 = c.post(
            f"/api/v1/auth/tokens/{owned_id}/rotate",
            headers=intruder_auth,
        )
        assert r2.status_code == 404


def test_rotate_returns_404_for_revoked_token():
    """Rotating an already-revoked PAT is a no-op — 404, don't mint a
    replacement from a dead row. Keeps the audit trail honest."""
    _, auth = _make_account_and_jwt("pat-rotate-revoked@example.com")

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.post(
            "/api/v1/auth/tokens",
            json={"name": "to-revoke"},
            headers=auth,
        )
        assert r.status_code == 201
        tok_id = r.json()["id"]

        rr = c.delete(f"/api/v1/auth/tokens/{tok_id}", headers=auth)
        assert rr.status_code == 204

        r2 = c.post(f"/api/v1/auth/tokens/{tok_id}/rotate", headers=auth)
        assert r2.status_code == 404


def test_pat_rotated_on_security_allowlist():
    """Sanity — rotations should light up the Prometheus security
    counter like other PAT lifecycle events."""
    from app.observability import SECURITY_ACTION_ALLOWLIST

    assert "pat.rotated" in SECURITY_ACTION_ALLOWLIST
