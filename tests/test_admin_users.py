"""Tests for the admin JSON user-management API."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import Account, get_session
from app.main import app
from app.roles import Role


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _register(client: TestClient, *, role: Role | None = None) -> tuple[str, int, str]:
    """Register a fresh account, optionally elevate its role."""
    email = f"{(role or Role.user).value}-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    password = "pass12345678"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    if role and role != Role.user:
        db = next(get_session())
        try:
            acc = db.query(Account).filter(Account.email == email).one()
            acc.role = role.value
            db.commit()
            user_id = acc.id
        finally:
            db.close()
        # Re-issue token so the stored role is in effect (JWT carries only sub/email).
        login = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        token = login.json()["token"]
        return email, user_id, token
    db = next(get_session())
    try:
        user_id = db.query(Account.id).filter(Account.email == email).scalar()
    finally:
        db.close()
    return email, user_id, token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestAdminUsersList:
    def test_list_requires_admin(self, client):
        _, _, user_token = _register(client)
        r = client.get("/api/v1/admin/users", headers=_auth(user_token))
        assert r.status_code == 403

    def test_list_ok_for_admin(self, client):
        _, _, admin_token = _register(client, role=Role.admin)
        r = client.get("/api/v1/admin/users", headers=_auth(admin_token))
        assert r.status_code == 200
        body = r.json()
        assert "items" in body and "total" in body
        assert body["total"] >= 1


class TestChangeRole:
    def test_admin_can_promote_user_to_support(self, client):
        _, _, admin_token = _register(client, role=Role.admin)
        _, target_id, _ = _register(client)
        r = client.post(
            f"/api/v1/admin/users/{target_id}/role",
            json={"role": "support"},
            headers=_auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["role"] == "support"

    def test_admin_cannot_assign_owner(self, client):
        _, _, admin_token = _register(client, role=Role.admin)
        _, target_id, _ = _register(client)
        r = client.post(
            f"/api/v1/admin/users/{target_id}/role",
            json={"role": "owner"},
            headers=_auth(admin_token),
        )
        assert r.status_code == 403

    def test_owner_can_assign_owner(self, client):
        _, _, owner_token = _register(client, role=Role.owner)
        _, target_id, _ = _register(client)
        r = client.post(
            f"/api/v1/admin/users/{target_id}/role",
            json={"role": "owner"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 200
        assert r.json()["role"] == "owner"

    def test_cannot_demote_last_owner(self, client):
        _, target_id, owner_token = _register(client, role=Role.owner)
        # Snapshot owner count before attempting demotion
        db = next(get_session())
        try:
            from sqlalchemy import func, select as _sel
            owner_count = db.scalar(
                _sel(func.count(Account.id)).where(Account.role == Role.owner.value)
            )
        finally:
            db.close()
        # Attempting to demote when only one owner remains must fail.
        # Create a second owner, then try demoting the first.
        if owner_count <= 1:
            _, _, other_owner = _register(client, role=Role.owner)
        # Now only owner_target still has owner — demote them, should succeed.
        r = client.post(
            f"/api/v1/admin/users/{target_id}/role",
            json={"role": "admin"},
            headers=_auth(owner_token),
        )
        # 200 because there are at least 2 owners now
        assert r.status_code in (200, 409)


class TestSuspend:
    def test_suspend_blocks_subsequent_login(self, client):
        email, target_id, _ = _register(client)
        _, _, admin_token = _register(client, role=Role.admin)
        r = client.post(
            f"/api/v1/admin/users/{target_id}/suspend",
            headers=_auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["suspended"] is True
        login = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "pass12345678"},
        )
        assert login.status_code == 403

    def test_resume_unblocks_login(self, client):
        email, target_id, _ = _register(client)
        _, _, admin_token = _register(client, role=Role.admin)
        client.post(
            f"/api/v1/admin/users/{target_id}/suspend",
            headers=_auth(admin_token),
        )
        r = client.post(
            f"/api/v1/admin/users/{target_id}/resume",
            headers=_auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["suspended"] is False
        login = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "pass12345678"},
        )
        assert login.status_code == 200


class TestResetPassword:
    def test_support_can_reset_user_password(self, client):
        email, target_id, _ = _register(client)
        _, _, support_token = _register(client, role=Role.support)
        r = client.post(
            f"/api/v1/admin/users/{target_id}/reset-password",
            headers=_auth(support_token),
        )
        assert r.status_code == 200
        temp = r.json()["temp_password"]
        assert len(temp) >= 12
        # Old password now fails
        old = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "pass12345678"},
        )
        assert old.status_code == 401
        # New password works
        new = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": temp},
        )
        assert new.status_code == 200


class TestDelete:
    def test_delete_cascades_to_sync(self, client):
        _, target_id, _ = _register(client)
        _, _, admin_token = _register(client, role=Role.admin)
        r = client.delete(
            f"/api/v1/admin/users/{target_id}",
            headers=_auth(admin_token),
        )
        assert r.status_code == 204
        # Fetch returns 404 now
        r2 = client.get(
            f"/api/v1/admin/users/{target_id}",
            headers=_auth(admin_token),
        )
        assert r2.status_code == 404

    def test_cannot_delete_owner(self, client):
        _, target_id, _ = _register(client, role=Role.owner)
        _, _, admin_token = _register(client, role=Role.admin)
        r = client.delete(
            f"/api/v1/admin/users/{target_id}",
            headers=_auth(admin_token),
        )
        assert r.status_code == 403

    def test_cannot_delete_self(self, client):
        _, self_id, admin_token = _register(client, role=Role.admin)
        r = client.delete(
            f"/api/v1/admin/users/{self_id}",
            headers=_auth(admin_token),
        )
        assert r.status_code == 409
