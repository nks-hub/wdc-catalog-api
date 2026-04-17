"""JWT revocation regression tests — logout + bulk revoke + password reset."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.db import Account, get_session
from app.main import app
from app.roles import Role


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _register(client, *, role=Role.user) -> tuple[str, int, str, str]:
    email = f"{role.value}-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    pwd = "pass12345678"
    client.post("/api/v1/auth/register", json={"email": email, "password": pwd})
    if role != Role.user:
        db = next(get_session())
        try:
            acc = db.query(Account).filter(Account.email == email).one()
            acc.role = role.value
            db.commit()
            uid = acc.id
        finally:
            db.close()
        tok = client.post(
            "/api/v1/auth/login", json={"email": email, "password": pwd}
        ).json()["token"]
        return email, uid, tok, pwd
    db = next(get_session())
    try:
        uid = db.query(Account.id).filter(Account.email == email).scalar()
    finally:
        db.close()
    tok = client.post(
        "/api/v1/auth/login", json={"email": email, "password": pwd}
    ).json()["token"]
    return email, uid, tok, pwd


def test_logout_invalidates_current_token(client):
    _, _, token, _ = _register(client)
    auth = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/v1/auth/me", headers=auth)
    assert r.status_code == 200
    out = client.post("/api/v1/auth/logout", headers=auth)
    assert out.status_code == 200
    assert out.json()["revoked"] is True
    r2 = client.get("/api/v1/auth/me", headers=auth)
    assert r2.status_code == 401


def test_admin_can_bulk_revoke_user_tokens(client):
    _, target_id, user_token, pwd = _register(client)
    _, _, admin_token, _ = _register(client, role=Role.admin)
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 200
    revoke = client.post(
        f"/api/v1/admin/users/{target_id}/revoke-tokens",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke.status_code == 200
    r2 = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert r2.status_code == 401


def test_password_reset_invalidates_prior_tokens(client):
    _, target_id, user_token, _ = _register(client)
    _, _, admin_token, _ = _register(client, role=Role.admin)
    client.post(
        f"/api/v1/admin/users/{target_id}/reset-password",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 401


def test_suspend_invalidates_prior_tokens(client):
    _, target_id, user_token, _ = _register(client)
    _, _, admin_token, _ = _register(client, role=Role.admin)
    client.post(
        f"/api/v1/admin/users/{target_id}/suspend",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 401
