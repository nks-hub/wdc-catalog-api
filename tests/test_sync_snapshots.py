"""Tests for sync snapshot endpoints (task 34).

Covers:
- list returns only the caller's snapshots
- retrieve wrong account → 404
- restore returns same payload shape as pull
- delete removes from DB
- auto-snapshot on push creates row; 11th push rotates to 10
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _register(client: TestClient) -> str:
    email = f"snap-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _push(client: TestClient, token: str, device_id: str, payload: dict) -> None:
    r = client.post(
        "/api/v1/sync/config",
        json={"device_id": device_id, "payload": payload},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text


class TestListSnapshots:
    def test_empty_list_for_new_account(self, client: TestClient):
        tok = _register(client)
        r = client.get("/api/v1/sync/snapshots", headers=_auth(tok))
        assert r.status_code == 200
        assert r.json() == {"snapshots": []}

    def test_list_only_returns_own_snapshots(self, client: TestClient):
        tok_a = _register(client)
        tok_b = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"

        # Push twice so A has a snapshot (first push has no previous, second does).
        _push(client, tok_a, dev, {"v": 1})
        _push(client, tok_a, dev, {"v": 2})

        r_a = client.get("/api/v1/sync/snapshots", headers=_auth(tok_a))
        r_b = client.get("/api/v1/sync/snapshots", headers=_auth(tok_b))

        assert r_a.status_code == 200
        snaps_a = r_a.json()["snapshots"]
        assert len(snaps_a) == 1  # one pre-push snapshot captured

        assert r_b.status_code == 200
        assert r_b.json()["snapshots"] == []

    def test_filter_by_device_id(self, client: TestClient):
        tok = _register(client)
        dev1 = f"dev1-{uuid.uuid4().hex[:6]}"
        dev2 = f"dev2-{uuid.uuid4().hex[:6]}"

        _push(client, tok, dev1, {"src": "dev1", "x": 1})
        _push(client, tok, dev1, {"src": "dev1", "x": 2})
        _push(client, tok, dev2, {"src": "dev2", "x": 1})
        _push(client, tok, dev2, {"src": "dev2", "x": 2})

        r = client.get(f"/api/v1/sync/snapshots?device_id={dev1}", headers=_auth(tok))
        assert r.status_code == 200
        snaps = r.json()["snapshots"]
        assert all(s["device_id"] == dev1 for s in snaps)

    def test_list_requires_auth(self, client: TestClient):
        r = client.get("/api/v1/sync/snapshots")
        assert r.status_code == 401


class TestGetSnapshot:
    def test_retrieve_includes_payload(self, client: TestClient):
        tok = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"
        _push(client, tok, dev, {"original": True})
        _push(client, tok, dev, {"updated": True})

        r_list = client.get("/api/v1/sync/snapshots", headers=_auth(tok))
        snap_id = r_list.json()["snapshots"][0]["id"]

        r = client.get(f"/api/v1/sync/snapshots/{snap_id}", headers=_auth(tok))
        assert r.status_code == 200
        body = r.json()
        assert "payload" in body
        assert body["payload"] == {"original": True}
        assert body["device_id"] == dev
        assert "created_at" in body

    def test_retrieve_wrong_account_returns_404(self, client: TestClient):
        tok_a = _register(client)
        tok_b = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"
        _push(client, tok_a, dev, {"v": 1})
        _push(client, tok_a, dev, {"v": 2})

        r_list = client.get("/api/v1/sync/snapshots", headers=_auth(tok_a))
        snap_id = r_list.json()["snapshots"][0]["id"]

        r = client.get(f"/api/v1/sync/snapshots/{snap_id}", headers=_auth(tok_b))
        assert r.status_code == 404

    def test_retrieve_nonexistent_returns_404(self, client: TestClient):
        tok = _register(client)
        r = client.get("/api/v1/sync/snapshots/999999999", headers=_auth(tok))
        assert r.status_code == 404


class TestRestoreSnapshot:
    def test_restore_matches_pull_shape(self, client: TestClient):
        tok = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"
        original_payload = {"key": "value", "sites": [1, 2, 3]}
        _push(client, tok, dev, original_payload)
        _push(client, tok, dev, {"key": "new-value"})

        r_list = client.get("/api/v1/sync/snapshots", headers=_auth(tok))
        snap_id = r_list.json()["snapshots"][0]["id"]

        r = client.post(f"/api/v1/sync/snapshots/{snap_id}/restore", headers=_auth(tok))
        assert r.status_code == 200
        body = r.json()
        # Must match ConfigSyncEntry shape (same as GET /sync/config/{device_id})
        assert set(body.keys()) >= {"device_id", "updated_at", "payload"}
        assert body["device_id"] == dev
        assert body["payload"] == original_payload

    def test_restore_wrong_account_returns_404(self, client: TestClient):
        tok_a = _register(client)
        tok_b = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"
        _push(client, tok_a, dev, {"v": 1})
        _push(client, tok_a, dev, {"v": 2})

        r_list = client.get("/api/v1/sync/snapshots", headers=_auth(tok_a))
        snap_id = r_list.json()["snapshots"][0]["id"]

        r = client.post(
            f"/api/v1/sync/snapshots/{snap_id}/restore", headers=_auth(tok_b)
        )
        assert r.status_code == 404


class TestDeleteSnapshot:
    def test_delete_removes_from_db(self, client: TestClient):
        tok = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"
        _push(client, tok, dev, {"v": 1})
        _push(client, tok, dev, {"v": 2})

        r_list = client.get("/api/v1/sync/snapshots", headers=_auth(tok))
        snap_id = r_list.json()["snapshots"][0]["id"]

        r = client.delete(f"/api/v1/sync/snapshots/{snap_id}", headers=_auth(tok))
        assert r.status_code == 204

        # Confirm it's gone
        r2 = client.get(f"/api/v1/sync/snapshots/{snap_id}", headers=_auth(tok))
        assert r2.status_code == 404

    def test_delete_wrong_account_returns_404(self, client: TestClient):
        tok_a = _register(client)
        tok_b = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"
        _push(client, tok_a, dev, {"v": 1})
        _push(client, tok_a, dev, {"v": 2})

        r_list = client.get("/api/v1/sync/snapshots", headers=_auth(tok_a))
        snap_id = r_list.json()["snapshots"][0]["id"]

        r = client.delete(f"/api/v1/sync/snapshots/{snap_id}", headers=_auth(tok_b))
        assert r.status_code == 404


class TestAutoSnapshot:
    def test_first_push_creates_no_snapshot(self, client: TestClient):
        """First push has no prior content — no snapshot should be created."""
        tok = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"
        _push(client, tok, dev, {"v": 1})

        r = client.get("/api/v1/sync/snapshots", headers=_auth(tok))
        snaps = r.json()["snapshots"]
        assert len(snaps) == 0

    def test_second_push_creates_snapshot_of_previous(self, client: TestClient):
        tok = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"
        _push(client, tok, dev, {"v": 1})
        _push(client, tok, dev, {"v": 2})

        r = client.get("/api/v1/sync/snapshots", headers=_auth(tok))
        snaps = r.json()["snapshots"]
        assert len(snaps) == 1

        snap_id = snaps[0]["id"]
        r2 = client.get(f"/api/v1/sync/snapshots/{snap_id}", headers=_auth(tok))
        assert r2.json()["payload"] == {"v": 1}

    def test_eleven_pushes_keeps_only_ten(self, client: TestClient):
        """11th push must trigger rotation — at most 10 snapshots remain."""
        tok = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"

        for i in range(12):
            _push(client, tok, dev, {"v": i})

        r = client.get(f"/api/v1/sync/snapshots?device_id={dev}", headers=_auth(tok))
        snaps = r.json()["snapshots"]
        assert len(snaps) <= 10

    def test_snapshots_ordered_newest_first(self, client: TestClient):
        tok = _register(client)
        dev = f"dev-{uuid.uuid4().hex[:8]}"

        for i in range(4):
            _push(client, tok, dev, {"v": i})

        r = client.get(f"/api/v1/sync/snapshots?device_id={dev}", headers=_auth(tok))
        snaps = r.json()["snapshots"]
        # created_at should be descending
        times = [s["created_at"] for s in snaps]
        assert times == sorted(times, reverse=True)
