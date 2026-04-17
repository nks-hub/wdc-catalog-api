"""Tests for admin-issued signed invite flow."""

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


def _register(client, *, role=Role.user) -> tuple[str, str]:
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
    tok = client.post(
        "/api/v1/auth/login", json={"email": email, "password": pwd}
    ).json()["token"]
    return email, tok


def test_admin_can_create_invite_and_invitee_accepts(client):
    _, admin_token = _register(client, role=Role.admin)
    invitee_email = f"invited-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/admin/invites",
        json={"email": invitee_email, "role": "support"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == invitee_email
    assert body["role"] == "support"
    invite_token = body["token"]

    # Invitee accepts
    accept = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": invite_token, "password": "invitedpass123"},
    )
    assert accept.status_code == 200
    assert accept.json()["email"] == invitee_email
    assert accept.json()["role"] == "support"

    # Login as the new account
    login = client.post(
        "/api/v1/auth/login",
        json={"email": invitee_email, "password": "invitedpass123"},
    )
    assert login.status_code == 200


def test_admin_cannot_invite_owner(client):
    _, admin_token = _register(client, role=Role.admin)
    r = client.post(
        "/api/v1/admin/invites",
        json={"email": f"new-owner-{uuid.uuid4().hex[:8]}@nks-wdc.dev", "role": "owner"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 403


def test_owner_can_invite_owner(client):
    _, owner_token = _register(client, role=Role.owner)
    invitee = f"co-owner-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/admin/invites",
        json={"email": invitee, "role": "owner"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 200
    accept = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": r.json()["token"], "password": "co-owner-pass-1234"},
    )
    assert accept.status_code == 200
    assert accept.json()["role"] == "owner"


def test_invite_cannot_be_replayed(client):
    _, admin_token = _register(client, role=Role.admin)
    invitee = f"replay-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/admin/invites",
        json={"email": invitee, "role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    token = r.json()["token"]
    first = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": token, "password": "replaytest123"},
    )
    assert first.status_code == 200
    second = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": token, "password": "replaytest123"},
    )
    assert second.status_code == 409


def test_invite_for_existing_email_rejected(client):
    email, admin_token = _register(client, role=Role.admin)
    r = client.post(
        "/api/v1/admin/invites",
        json={"email": email, "role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409


def test_tampered_invite_token_rejected(client):
    _, admin_token = _register(client, role=Role.admin)
    r = client.post(
        "/api/v1/admin/invites",
        json={"email": f"tamper-{uuid.uuid4().hex[:8]}@nks-wdc.dev", "role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    bad = r.json()["token"][:-4] + "XXXX"
    out = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": bad, "password": "whatever12345"},
    )
    assert out.status_code == 400
