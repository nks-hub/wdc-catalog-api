"""Tests for account-scoped retention policy CRUD."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _register(client) -> str:
    email = f"pol-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    return r.json()["token"]


def _seed_device(client, token, device_id):
    client.post(
        "/api/v1/sync/config",
        json={"device_id": device_id, "payload": {"seed": True}},
        headers={"Authorization": f"Bearer {token}"},
    )


class TestPolicyCrud:
    def test_account_default_upsert(self, client):
        tok = _register(client)
        r = client.put(
            "/api/v1/retention/policies",
            json={"keep_last_n_auto": 12, "auto_expire_days": 30},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 200
        assert r.json()["device_id"] is None
        assert r.json()["keep_last_n_auto"] == 12

        # Second PUT updates in place, doesn't insert
        r2 = client.put(
            "/api/v1/retention/policies",
            json={"keep_last_n_auto": 7},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r2.status_code == 200
        assert r2.json()["id"] == r.json()["id"]
        assert r2.json()["keep_last_n_auto"] == 7

    def test_device_override(self, client):
        tok = _register(client)
        dev = f"pol-dev-{uuid.uuid4().hex[:6]}"
        _seed_device(client, tok, dev)
        r = client.put(
            "/api/v1/retention/policies",
            json={"device_id": dev, "keep_last_n_auto": 3},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 200
        assert r.json()["device_id"] == dev

    def test_device_override_requires_ownership(self, client):
        tok = _register(client)
        r = client.put(
            "/api/v1/retention/policies",
            json={"device_id": "someone-elses-device", "keep_last_n_auto": 1},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 404

    def test_list_returns_defaults_and_overrides(self, client):
        tok = _register(client)
        dev = f"pol-list-{uuid.uuid4().hex[:6]}"
        _seed_device(client, tok, dev)
        client.put(
            "/api/v1/retention/policies",
            json={"keep_last_n_auto": 10},
            headers={"Authorization": f"Bearer {tok}"},
        )
        client.put(
            "/api/v1/retention/policies",
            json={"device_id": dev, "keep_last_n_auto": 5},
            headers={"Authorization": f"Bearer {tok}"},
        )
        r = client.get(
            "/api/v1/retention/policies",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 2
        device_ids = {i["device_id"] for i in body["items"]}
        assert None in device_ids and dev in device_ids

    def test_list_filter_by_device(self, client):
        tok = _register(client)
        dev = f"pol-flt-{uuid.uuid4().hex[:6]}"
        _seed_device(client, tok, dev)
        client.put(
            "/api/v1/retention/policies",
            json={"keep_last_n_auto": 10},
            headers={"Authorization": f"Bearer {tok}"},
        )
        client.put(
            "/api/v1/retention/policies",
            json={"device_id": dev, "keep_last_n_auto": 4},
            headers={"Authorization": f"Bearer {tok}"},
        )
        r = client.get(
            f"/api/v1/retention/policies?device_id={dev}",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["device_id"] == dev

    def test_delete_policy(self, client):
        tok = _register(client)
        r = client.put(
            "/api/v1/retention/policies",
            json={"keep_last_n_auto": 9},
            headers={"Authorization": f"Bearer {tok}"},
        )
        pid = r.json()["id"]
        d = client.delete(
            f"/api/v1/retention/policies/{pid}",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert d.status_code == 204
        r2 = client.get(
            "/api/v1/retention/policies",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert all(i["id"] != pid for i in r2.json()["items"])


class TestPolicyValidation:
    def test_keep_last_n_auto_bounds(self, client):
        tok = _register(client)
        r = client.put(
            "/api/v1/retention/policies",
            json={"keep_last_n_auto": 0},  # below min
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 422

    def test_auto_expire_days_cap(self, client):
        tok = _register(client)
        r = client.put(
            "/api/v1/retention/policies",
            json={"keep_last_n_auto": 10, "auto_expire_days": 99999},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 422
