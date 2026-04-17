"""HEAD /api/v1/sync/config/{id} — resource-oriented existence probe."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _token(client: TestClient) -> str:
    email = f"head-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    return r.json()["token"]


def test_head_404_when_device_unknown(client: TestClient):
    tok = _token(client)
    r = client.head(
        "/api/v1/sync/config/unknown-device-xyz",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 404
    assert r.text == ""


def test_head_200_after_sync(client: TestClient):
    tok = _token(client)
    auth = {"Authorization": f"Bearer {tok}"}
    dev = f"head-dev-{uuid.uuid4().hex[:6]}"
    client.post(
        "/api/v1/sync/config",
        json={"device_id": dev, "payload": {"seed": True}},
        headers=auth,
    )
    r = client.head(f"/api/v1/sync/config/{dev}", headers=auth)
    assert r.status_code == 200
    assert r.text == ""
    assert "last-modified" in {k.lower() for k in r.headers.keys()}


def test_legacy_exists_endpoint_marked_deprecated(client: TestClient):
    tok = _token(client)
    auth = {"Authorization": f"Bearer {tok}"}
    dev = f"head-dep-{uuid.uuid4().hex[:6]}"
    client.post(
        "/api/v1/sync/config",
        json={"device_id": dev, "payload": {"seed": True}},
        headers=auth,
    )
    r = client.get(f"/api/v1/sync/config/{dev}/exists", headers=auth)
    assert r.status_code == 200
    assert r.headers.get("deprecation") == "true"
    link = r.headers.get("link", "")
    assert "successor-version" in link
    assert r.json()["has_config"] is True


def test_head_requires_auth(client: TestClient):
    r = client.head("/api/v1/sync/config/any-device")
    assert r.status_code == 401
