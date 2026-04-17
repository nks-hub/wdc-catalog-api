"""Tests for the retention runner + admin trigger endpoint."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.db import Account, SnapshotRetentionPolicy, get_session
from app.main import app
from app.roles import Role


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _register(client, *, role=Role.user) -> tuple[str, int]:
    email = f"ret-{role.value}-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    pwd = "pass12345678"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": pwd})
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
            "/api/v1/auth/login", json={"email": email, "password": pwd}
        ).json()["token"]
        return token, uid
    db = next(get_session())
    try:
        uid = db.query(Account.id).filter(Account.email == email).scalar()
    finally:
        db.close()
    return token, uid


def test_retention_endpoint_requires_admin(client):
    token, _ = _register(client)
    r = client.post(
        "/api/v1/admin/retention/run-now",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403


def test_retention_runs_and_returns_summary(client):
    token, _ = _register(client, role=Role.admin)
    r = client.post(
        "/api/v1/admin/retention/run-now",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "accounts" in body
    assert "deleted" in body


def test_retention_respects_custom_policy(client):
    token, uid = _register(client)
    auth = {"Authorization": f"Bearer {token}"}
    dev = f"ret-dev-{uuid.uuid4().hex[:6]}"
    # Create several auto snapshots
    for i in range(5):
        client.post(
            "/api/v1/sync/config",
            json={"device_id": dev, "payload": {"version": i}},
            headers=auth,
        )

    # Install a tight per-account policy (keep only 2)
    db = next(get_session())
    try:
        pol = SnapshotRetentionPolicy(
            account_id=uid,
            device_id=None,
            keep_last_n_auto=2,
            auto_expire_days=None,
            keep_labeled_forever=True,
        )
        db.add(pol)
        db.commit()
    finally:
        db.close()

    # Trigger retention as admin
    admin_tok, _ = _register(client, role=Role.admin)
    r = client.post(
        "/api/v1/admin/retention/run-now",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert r.status_code == 200

    # The device must still have at least the HEAD + retained snapshots
    lst = client.get(f"/api/v1/devices/{dev}/backups", headers=auth).json()
    # keep_last_n_auto=2 plus the HEAD is protected → at most 3 rows survive
    # and definitely fewer than the original 5.
    assert lst["total"] < 5
