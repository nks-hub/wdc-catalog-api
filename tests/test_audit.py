"""Tests for audit.emit + the admin audit viewer endpoint."""

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


def _register(client: TestClient, *, role: Role = Role.user) -> tuple[str, int, str]:
    email = f"{role.value}-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    password = "pass12345678"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    if role != Role.user:
        db = next(get_session())
        try:
            acc = db.query(Account).filter(Account.email == email).one()
            acc.role = role.value
            db.commit()
            uid = acc.id
        finally:
            db.close()
        token = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        ).json()["token"]
        return email, uid, token
    db = next(get_session())
    try:
        uid = db.query(Account.id).filter(Account.email == email).scalar()
    finally:
        db.close()
    return email, uid, token


def _auth(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


def test_admin_audit_endpoint_requires_support(client):
    _, _, user_token = _register(client)
    r = client.get("/api/v1/admin/audit", headers=_auth(user_token))
    assert r.status_code == 403


def test_role_change_emits_audit_event(client):
    _, target_id, _ = _register(client)
    admin_email, _, admin_token = _register(client, role=Role.admin)

    r = client.post(
        f"/api/v1/admin/users/{target_id}/role",
        json={"role": "support"},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200

    # Now query audit log with admin token (admin implies support for viewer)
    audit_r = client.get(
        "/api/v1/admin/audit",
        params={"action": "user.role_changed", "resource_id": str(target_id)},
        headers=_auth(admin_token),
    )
    assert audit_r.status_code == 200
    body = audit_r.json()
    assert body["total"] >= 1
    row = next(
        i
        for i in body["items"]
        if i["action"] == "user.role_changed" and i["resource_id"] == str(target_id)
    )
    assert row["actor_email"] == admin_email
    assert row["detail"]["to"] == "support"
    assert row["detail"]["from"] == "user"


def test_suspend_and_password_reset_emit_events(client):
    email, target_id, _ = _register(client)
    _, _, admin_token = _register(client, role=Role.admin)

    client.post(
        f"/api/v1/admin/users/{target_id}/suspend",
        headers=_auth(admin_token),
    )
    client.post(
        f"/api/v1/admin/users/{target_id}/resume",
        headers=_auth(admin_token),
    )
    client.post(
        f"/api/v1/admin/users/{target_id}/reset-password",
        headers=_auth(admin_token),
    )

    r = client.get(
        "/api/v1/admin/audit",
        params={"resource_id": str(target_id)},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200
    actions = {item["action"] for item in r.json()["items"]}
    assert "user.suspended" in actions
    assert "user.resumed" in actions
    assert "user.password_reset" in actions


def test_audit_filter_by_action(client):
    _, target_id, _ = _register(client)
    _, _, admin_token = _register(client, role=Role.admin)

    client.post(
        f"/api/v1/admin/users/{target_id}/suspend",
        headers=_auth(admin_token),
    )

    r = client.get(
        "/api/v1/admin/audit",
        params={"action": "user.suspended"},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["action"] == "user.suspended"
