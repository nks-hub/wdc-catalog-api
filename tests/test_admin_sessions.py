"""Admin session viewer + idempotency/revoked-token sweep tests."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import Account, IdempotencyRecord, RevokedToken, get_session
from app.main import app
from app.roles import Role


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _register(client, *, role=Role.user) -> tuple[str, int]:
    email = f"sess-{role.value}-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    pwd = "pass12345678"
    client.post("/api/v1/auth/register", json={"email": email, "password": pwd})
    db = next(get_session())
    try:
        acc = db.query(Account).filter(Account.email == email).one()
        uid = acc.id
        if role != Role.user:
            acc.role = role.value
            db.commit()
    finally:
        db.close()
    tok = client.post(
        "/api/v1/auth/login", json={"email": email, "password": pwd}
    ).json()["token"]
    return tok, uid


class TestAdminSessionViewer:
    def test_support_can_view_sessions(self, client):
        user_tok, uid = _register(client)
        _, _ = _register(client, role=Role.support)
        support_tok, _ = _register(client, role=Role.support)
        r = client.get(
            f"/api/v1/admin/users/{uid}/sessions",
            headers={"Authorization": f"Bearer {support_tok}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["token_version"] >= 1
        assert "revoked_tokens" in body
        assert "revoked_tokens_active" in body

    def test_user_role_rejected(self, client):
        user_tok, uid = _register(client)
        r = client.get(
            f"/api/v1/admin/users/{uid}/sessions",
            headers={"Authorization": f"Bearer {user_tok}"},
        )
        assert r.status_code == 403

    def test_revoked_tokens_show_up_after_logout(self, client):
        user_tok, uid = _register(client)
        client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {user_tok}"},
        )
        _, _ = _register(client, role=Role.admin)
        admin_tok, _ = _register(client, role=Role.admin)
        r = client.get(
            f"/api/v1/admin/users/{uid}/sessions",
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert r.status_code == 200
        assert r.json()["revoked_tokens_active"] >= 1


class TestRetentionSweeps:
    def test_expired_idempotency_rows_purged(self, client):
        admin_tok, _ = _register(client, role=Role.admin)
        # Seed an expired row directly
        db = next(get_session())
        try:
            db.add(IdempotencyRecord(
                key_hash=uuid.uuid4().hex,
                account_id=None,
                method="POST",
                path="/api/v1/test",
                status_code=201,
                response_body=b"{}",
                content_type="application/json",
                expires_at=datetime.now(timezone.utc).replace(tzinfo=None)
                    - timedelta(hours=1),
            ))
            db.commit()
        finally:
            db.close()

        r = client.post(
            "/api/v1/admin/retention/run-now",
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["idempotency_purged"] >= 1

    def test_expired_revoked_tokens_purged(self, client):
        admin_tok, _ = _register(client, role=Role.admin)
        db = next(get_session())
        try:
            db.add(RevokedToken(
                jti=uuid.uuid4().hex,
                account_id=None,
                reason="test-expired",
                expires_at=datetime.now(timezone.utc).replace(tzinfo=None)
                    - timedelta(hours=1),
            ))
            db.commit()
        finally:
            db.close()

        r = client.post(
            "/api/v1/admin/retention/run-now",
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert r.status_code == 200
        assert r.json()["revoked_tokens_purged"] >= 1
