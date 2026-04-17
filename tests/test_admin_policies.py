"""Tests for the global policy singleton endpoint."""

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


def _register(client, *, role=Role.user):
    email = f"{role.value}-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    pwd = "pass12345678"
    client.post("/api/v1/auth/register", json={"email": email, "password": pwd})
    if role != Role.user:
        db = next(get_session())
        try:
            acc = db.query(Account).filter(Account.email == email).one()
            acc.role = role.value
            db.commit()
        finally:
            db.close()
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": pwd}).json()["token"]
    return tok


def test_get_policy_returns_defaults(client):
    tok = _register(client, role=Role.admin)
    r = client.get("/api/v1/admin/policy", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert body["snapshot_keep_last_n"] == 30
    assert body["snapshot_retain_days"] == 90
    assert body["registration_enabled"] is True
    assert body["default_role"] == "user"


def test_put_policy_updates_values(client):
    tok = _register(client, role=Role.admin)
    r = client.put(
        "/api/v1/admin/policy",
        json={
            "snapshot_keep_last_n": 50,
            "snapshot_retain_days": 120,
            "banner_message": "Planned downtime 2026-04-30",
        },
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["snapshot_keep_last_n"] == 50
    assert body["snapshot_retain_days"] == 120
    assert body["banner_message"] == "Planned downtime 2026-04-30"
    assert body["updated_by_email"] is not None


def test_put_policy_requires_admin(client):
    tok = _register(client, role=Role.support)
    r = client.put(
        "/api/v1/admin/policy",
        json={"banner_message": "should fail"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 403


def test_get_policy_allowed_for_support(client):
    tok = _register(client, role=Role.support)
    r = client.get("/api/v1/admin/policy", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200


def test_policy_update_emits_audit_event(client):
    tok = _register(client, role=Role.admin)
    client.put(
        "/api/v1/admin/policy",
        json={"snapshot_keep_last_n": 77},
        headers={"Authorization": f"Bearer {tok}"},
    )
    r = client.get(
        "/api/v1/admin/audit",
        params={"action": "policy.updated"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_policy_validation_rejects_oversized_retention(client):
    tok = _register(client, role=Role.admin)
    r = client.put(
        "/api/v1/admin/policy",
        json={"snapshot_retain_days": 10000},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 422
