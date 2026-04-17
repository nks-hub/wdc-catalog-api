"""Tests for the admin stats dashboard endpoint."""

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


def test_stats_requires_support(client):
    tok = _register(client)
    r = client.get("/api/v1/admin/stats/overview", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_stats_overview_for_admin(client):
    tok = _register(client, role=Role.admin)
    r = client.get("/api/v1/admin/stats/overview", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert "catalog" in body and "users" in body and "audit" in body
    assert body["users"]["accounts_total"] >= 1
    assert "generated_at" in body
    assert "accounts_by_role" in body["users"]


def test_stats_counts_suspended(client):
    tok_admin = _register(client, role=Role.admin)
    victim_email = f"stats-victim-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    client.post("/api/v1/auth/register",
                json={"email": victim_email, "password": "pass12345678"})
    db = next(get_session())
    try:
        victim_id = db.query(Account.id).filter(Account.email == victim_email).scalar()
    finally:
        db.close()
    client.post(
        f"/api/v1/admin/users/{victim_id}/suspend",
        headers={"Authorization": f"Bearer {tok_admin}"},
    )
    r = client.get(
        "/api/v1/admin/stats/overview",
        headers={"Authorization": f"Bearer {tok_admin}"},
    )
    assert r.status_code == 200
    assert r.json()["users"]["accounts_suspended"] >= 1
