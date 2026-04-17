"""Replay-safety for Idempotency-Key header on POST /backups."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _setup(client: TestClient) -> tuple[str, str]:
    email = f"idem-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    token = r.json()["token"]
    dev = f"idem-dev-{uuid.uuid4().hex[:6]}"
    client.post(
        "/api/v1/sync/config",
        json={"device_id": dev, "payload": {"seed": True}},
        headers={"Authorization": f"Bearer {token}"},
    )
    return token, dev


def test_same_key_returns_first_response(client: TestClient):
    token, dev = _setup(client)
    key = uuid.uuid4().hex
    first = client.post(
        f"/api/v1/devices/{dev}/backups",
        json={"kind": "manual", "label": "idem-test", "payload": {"v": 1}},
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": key,
        },
    )
    assert first.status_code == 201
    first_id = first.json()["id"]

    # Replay with the same key + different body → should return the
    # original response, NOT create a second snapshot.
    second = client.post(
        f"/api/v1/devices/{dev}/backups",
        json={"kind": "manual", "label": "should-be-ignored", "payload": {"v": 2}},
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": key,
        },
    )
    assert second.status_code == 201
    assert second.headers.get("idempotency-replay") == "true"
    assert second.json()["id"] == first_id
    assert second.json()["label"] == "idem-test"


def test_different_keys_create_distinct_snapshots(client: TestClient):
    token, dev = _setup(client)
    auth = {"Authorization": f"Bearer {token}"}
    r1 = client.post(
        f"/api/v1/devices/{dev}/backups",
        json={"kind": "manual", "label": "a", "payload": {"v": 1}},
        headers={**auth, "Idempotency-Key": uuid.uuid4().hex},
    )
    r2 = client.post(
        f"/api/v1/devices/{dev}/backups",
        json={"kind": "manual", "label": "b", "payload": {"v": 2}},
        headers={**auth, "Idempotency-Key": uuid.uuid4().hex},
    )
    assert r1.json()["id"] != r2.json()["id"]


def test_no_key_header_disables_replay(client: TestClient):
    token, dev = _setup(client)
    auth = {"Authorization": f"Bearer {token}"}
    r1 = client.post(
        f"/api/v1/devices/{dev}/backups",
        json={"kind": "manual", "label": "no-key-a", "payload": {"v": 1}},
        headers=auth,
    )
    r2 = client.post(
        f"/api/v1/devices/{dev}/backups",
        json={"kind": "manual", "label": "no-key-b", "payload": {"v": 2}},
        headers=auth,
    )
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["id"] != r2.json()["id"]
    assert r2.headers.get("idempotency-replay") is None


def test_short_key_rejected(client: TestClient):
    token, dev = _setup(client)
    r = client.post(
        f"/api/v1/devices/{dev}/backups",
        json={"kind": "manual", "payload": {"x": 1}},
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "abc",
        },
    )
    assert r.status_code == 400


def test_different_accounts_have_separate_keyspace(client: TestClient):
    shared_key = uuid.uuid4().hex
    t1, d1 = _setup(client)
    t2, d2 = _setup(client)
    client.post(
        f"/api/v1/devices/{d1}/backups",
        json={"kind": "manual", "label": "acct-1", "payload": {"v": 1}},
        headers={"Authorization": f"Bearer {t1}", "Idempotency-Key": shared_key},
    )
    # Account 2 uses the same key but on its own device; must produce a
    # fresh response (keys are scoped by account).
    r = client.post(
        f"/api/v1/devices/{d2}/backups",
        json={"kind": "manual", "label": "acct-2", "payload": {"v": 2}},
        headers={"Authorization": f"Bearer {t2}", "Idempotency-Key": shared_key},
    )
    assert r.status_code == 201
    assert r.headers.get("idempotency-replay") is None
    assert r.json()["label"] == "acct-2"
