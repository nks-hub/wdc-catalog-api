"""Tests for account registration, JWT auth, and device management."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


_test_email = f"test-{__import__('uuid').uuid4().hex[:8]}@nks-wdc.dev"
_test_password = "testpass123"


@pytest.fixture(scope="module")
def auth_token(client: TestClient) -> str:
    r = client.post("/api/v1/auth/register", json={
        "email": _test_email,
        "password": _test_password,
    })
    assert r.status_code == 200, f"Register failed ({r.status_code}): {r.text}"
    return r.json()["token"]


def test_register_creates_account(client: TestClient) -> None:
    r = client.post("/api/v1/auth/register", json={
        "email": "another@nks-wdc.dev",
        "password": "pass4567long",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "another@nks-wdc.dev"
    assert "token" in body


def test_register_duplicate_email_rejects(client: TestClient, auth_token: str) -> None:
    # auth_token fixture registers test@nks-wdc.dev first, so this is a dup
    r = client.post("/api/v1/auth/register", json={
        "email": _test_email,
        "password": "anything",
    })
    assert r.status_code == 409


def test_login_valid_credentials(client: TestClient) -> None:
    r = client.post("/api/v1/auth/login", json={
        "email": _test_email,
        "password": "testpass123",
    })
    assert r.status_code == 200
    assert r.json()["email"] == _test_email


def test_login_bad_password(client: TestClient) -> None:
    r = client.post("/api/v1/auth/login", json={
        "email": _test_email,
        "password": "wrong",
    })
    assert r.status_code == 401


def test_me_returns_account(client: TestClient, auth_token: str) -> None:
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code == 200
    assert r.json()["email"] == _test_email


def test_me_rejects_no_token(client: TestClient) -> None:
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 401


def test_devices_empty_initially(client: TestClient, auth_token: str) -> None:
    r = client.get("/api/v1/devices", headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code == 200
    assert r.json() == []


def test_sync_push_auto_links_device(client: TestClient, auth_token: str) -> None:
    r = client.post("/api/v1/sync/config", json={
        "device_id": "test-device-001",
        "payload": {
            "settings": {"sync.deviceName": "Test PC"},
            "sites": [{"domain": "a.loc"}, {"domain": "b.loc"}],
            "system": {"os": {"tag": "windows", "arch": "x64"}},
        },
    }, headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code == 200

    # Device should now appear in the fleet
    r2 = client.get("/api/v1/devices", headers={"Authorization": f"Bearer {auth_token}"})
    devices = r2.json()
    assert len(devices) == 1
    d = devices[0]
    assert d["device_id"] == "test-device-001"
    assert d["name"] == "Test PC"
    assert d["os"] == "windows"
    assert d["arch"] == "x64"
    assert d["site_count"] == 2


def test_device_config_readable(client: TestClient, auth_token: str) -> None:
    r = client.get(
        "/api/v1/devices/test-device-001/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert r.json()["payload"]["settings"]["sync.deviceName"] == "Test PC"


def test_list_devices_is_current_flag(client: TestClient, auth_token: str) -> None:
    """The caller can pass ?current_device_id to flag its own row with
    is_current=true. Without the param all rows stay is_current=false
    (back-compat with pre-flag clients)."""
    # No param → all False
    r = client.get("/api/v1/devices", headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code == 200
    assert all(d["is_current"] is False for d in r.json())

    # With matching param → exactly one True
    r = client.get(
        "/api/v1/devices?current_device_id=test-device-001",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    flagged = [d for d in r.json() if d["is_current"]]
    assert len(flagged) == 1
    assert flagged[0]["device_id"] == "test-device-001"

    # With non-matching param → all False (no crash)
    r = client.get(
        "/api/v1/devices?current_device_id=nonexistent-device",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert all(d["is_current"] is False for d in r.json())


def test_push_config_between_devices(client: TestClient, auth_token: str) -> None:
    # Create a second device
    client.post("/api/v1/sync/config", json={
        "device_id": "test-device-002",
        "payload": {"settings": {}, "sites": []},
    }, headers={"Authorization": f"Bearer {auth_token}"})

    # Push from device-001 to device-002
    r = client.post(
        "/api/v1/devices/test-device-002/push-config",
        json={"source_device_id": "test-device-001"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert r.json()["pushed_from"] == "test-device-001"

    # Verify target now has the source's payload
    r2 = client.get(
        "/api/v1/devices/test-device-002/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r2.json()["payload"]["settings"]["sync.deviceName"] == "Test PC"


def test_delete_device(client: TestClient, auth_token: str) -> None:
    r = client.delete(
        "/api/v1/devices/test-device-002",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert r.json()["removed"] == "test-device-002"

    # Should be gone from fleet
    r2 = client.get("/api/v1/devices", headers={"Authorization": f"Bearer {auth_token}"})
    assert len(r2.json()) == 1
