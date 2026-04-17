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
    r = client.post(
        "/api/v1/auth/register",
        json={
            "email": _test_email,
            "password": _test_password,
        },
    )
    assert r.status_code == 200, f"Register failed ({r.status_code}): {r.text}"
    return r.json()["token"]


def test_register_creates_account(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/register",
        json={
            "email": "another@nks-wdc.dev",
            "password": "pass4567long",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "another@nks-wdc.dev"
    assert "token" in body


def test_register_duplicate_email_rejects(client: TestClient, auth_token: str) -> None:
    # auth_token fixture registers test@nks-wdc.dev first, so this is a dup
    r = client.post(
        "/api/v1/auth/register",
        json={
            "email": _test_email,
            "password": "anything",
        },
    )
    assert r.status_code == 409


def test_login_valid_credentials(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/login",
        json={
            "email": _test_email,
            "password": "testpass123",
        },
    )
    assert r.status_code == 200
    assert r.json()["email"] == _test_email


def test_login_bad_password(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/login",
        json={
            "email": _test_email,
            "password": "wrong",
        },
    )
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
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0


def test_sync_push_auto_links_device(client: TestClient, auth_token: str) -> None:
    r = client.post(
        "/api/v1/sync/config",
        json={
            "device_id": "test-device-001",
            "payload": {
                "settings": {"sync.deviceName": "Test PC"},
                "sites": [{"domain": "a.loc"}, {"domain": "b.loc"}],
                "system": {"os": {"tag": "windows", "arch": "x64"}},
            },
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200

    # Device should now appear in the fleet
    r2 = client.get(
        "/api/v1/devices", headers={"Authorization": f"Bearer {auth_token}"}
    )
    devices = r2.json()["items"]
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
    assert all(d["is_current"] is False for d in r.json()["items"])

    # With matching param → exactly one True
    r = client.get(
        "/api/v1/devices?current_device_id=test-device-001",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    flagged = [d for d in r.json()["items"] if d["is_current"]]
    assert len(flagged) == 1
    assert flagged[0]["device_id"] == "test-device-001"

    # With non-matching param → all False (no crash)
    r = client.get(
        "/api/v1/devices?current_device_id=nonexistent-device",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert all(d["is_current"] is False for d in r.json()["items"])


def test_push_config_between_devices(client: TestClient, auth_token: str) -> None:
    # Create a second device
    client.post(
        "/api/v1/sync/config",
        json={
            "device_id": "test-device-002",
            "payload": {"settings": {}, "sites": []},
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )

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


class TestSyncOwnershipGuards:
    """Regression tests for F-11: anonymous/cross-account overwrite of owned device."""

    def test_anonymous_cannot_overwrite_owned_device(
        self, client: TestClient, auth_token: str
    ) -> None:
        """Anonymous POST /sync/config must be rejected outright — used to
        require auth only to protect owned rows, now required for every
        write to close the device-id squat vector (M9)."""
        device_id = "ownership-guard-test-dev"
        # Owner establishes the device
        r = client.post(
            "/api/v1/sync/config",
            json={"device_id": device_id, "payload": {"k": "owner"}},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert r.status_code == 200
        # Anonymous attempts overwrite → 401 (no token), not 403.
        r2 = client.post(
            "/api/v1/sync/config",
            json={"device_id": device_id, "payload": {"k": "attacker"}},
        )
        assert r2.status_code == 401
        # Original payload must survive
        r3 = client.get(
            f"/api/v1/devices/{device_id}/config",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert r3.status_code == 200
        assert r3.json()["payload"] == {"k": "owner"}

    def test_other_account_cannot_overwrite_owned_device(
        self, client: TestClient, auth_token: str
    ) -> None:
        """A different account's token must also be rejected."""
        import uuid

        other_email = f"other-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
        reg = client.post(
            "/api/v1/auth/register",
            json={"email": other_email, "password": "otherpass12345"},
        )
        assert reg.status_code == 200
        other_token = reg.json()["token"]

        device_id = "ownership-guard-cross"
        r = client.post(
            "/api/v1/sync/config",
            json={"device_id": device_id, "payload": {"k": "owner"}},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert r.status_code == 200

        r2 = client.post(
            "/api/v1/sync/config",
            json={"device_id": device_id, "payload": {"k": "attacker"}},
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert r2.status_code == 403


class TestSyncConfigAuthRequired:
    """F-12: GET/HEAD/DELETE /sync/config/{id} must require auth + ownership."""

    def test_anonymous_get_rejected(self, client: TestClient) -> None:
        r = client.get("/api/v1/sync/config/some-device")
        assert r.status_code == 401

    def test_anonymous_delete_rejected(self, client: TestClient) -> None:
        r = client.delete("/api/v1/sync/config/some-device")
        assert r.status_code == 401

    def test_anonymous_exists_rejected(self, client: TestClient) -> None:
        r = client.get("/api/v1/sync/config/some-device/exists")
        assert r.status_code == 401

    def test_owner_can_get(self, client: TestClient, auth_token: str) -> None:
        dev = "auth-required-dev-1"
        client.post(
            "/api/v1/sync/config",
            json={"device_id": dev, "payload": {"k": "v"}},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        r = client.get(
            f"/api/v1/sync/config/{dev}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert r.status_code == 200
        assert r.json()["payload"] == {"k": "v"}

    def test_other_account_sees_404(self, client: TestClient, auth_token: str) -> None:
        import uuid

        dev = "auth-required-dev-2"
        client.post(
            "/api/v1/sync/config",
            json={"device_id": dev, "payload": {"k": "owner"}},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        other_email = f"other-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
        reg = client.post(
            "/api/v1/auth/register",
            json={"email": other_email, "password": "otherpass12345"},
        )
        other_token = reg.json()["token"]
        # Must not leak existence — 404, not 403
        r = client.get(
            f"/api/v1/sync/config/{dev}",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert r.status_code == 404


def test_delete_device(client: TestClient, auth_token: str) -> None:
    r = client.delete(
        "/api/v1/devices/test-device-002",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert r.json()["removed"] == "test-device-002"

    # Should be gone from fleet
    r2 = client.get(
        "/api/v1/devices", headers={"Authorization": f"Bearer {auth_token}"}
    )
    device_ids = {d["device_id"] for d in r2.json()["items"]}
    assert "test-device-002" not in device_ids
