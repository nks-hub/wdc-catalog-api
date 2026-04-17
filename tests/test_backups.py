"""Integration tests for the public backup API."""

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
    email = f"backup-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    assert r.status_code == 200
    return r.json()["token"]


def _seed_device(client: TestClient, token: str, device_id: str, payload: dict) -> None:
    r = client.post(
        "/api/v1/sync/config",
        json={"device_id": device_id, "payload": payload},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text


class TestBackupCreateAndList:
    def test_create_manual_then_list(self, client):
        token = _register(client)
        dev = f"bkp-dev-{uuid.uuid4().hex[:6]}"
        _seed_device(client, token, dev, {"sites": ["a.loc"]})

        r = client.post(
            f"/api/v1/devices/{dev}/backups",
            json={"label": "before-upgrade", "kind": "manual"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 201
        assert r.json()["label"] == "before-upgrade"
        assert r.json()["kind"] == "manual"

        lst = client.get(
            f"/api/v1/devices/{dev}/backups",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert lst.status_code == 200
        body = lst.json()
        assert body["total"] >= 2  # at least the auto + manual
        assert body["head_id"] is not None

    def test_create_returns_413_when_payload_too_big(self, client):
        import base64, os as _os
        token = _register(client)
        dev = f"bkp-big-{uuid.uuid4().hex[:6]}"
        _seed_device(client, token, dev, {"seed": True})

        huge = {"k": base64.b64encode(_os.urandom(3 * 1024 * 1024)).decode("ascii")}
        r = client.post(
            f"/api/v1/devices/{dev}/backups",
            json={"kind": "manual", "payload": huge},
            headers={"Authorization": f"Bearer {token}"},
        )
        # Either the FastAPI payload-size middleware (at Content-Length),
        # or the snapshot service (413) rejects it.
        assert r.status_code == 413


class TestBackupFetch:
    def test_get_detail_includes_payload(self, client):
        token = _register(client)
        dev = f"bkp-get-{uuid.uuid4().hex[:6]}"
        _seed_device(client, token, dev, {"marker": 1})
        auth = {"Authorization": f"Bearer {token}"}

        lst = client.get(f"/api/v1/devices/{dev}/backups", headers=auth).json()
        head_id = lst["head_id"]
        r = client.get(f"/api/v1/devices/{dev}/backups/{head_id}", headers=auth)
        assert r.status_code == 200
        body = r.json()
        assert body["payload"]["marker"] == 1

    def test_download_returns_envelope(self, client):
        token = _register(client)
        dev = f"bkp-dl-{uuid.uuid4().hex[:6]}"
        _seed_device(client, token, dev, {"marker": "dl"})
        auth = {"Authorization": f"Bearer {token}"}
        head_id = client.get(
            f"/api/v1/devices/{dev}/backups", headers=auth
        ).json()["head_id"]

        r = client.get(
            f"/api/v1/devices/{dev}/backups/{head_id}/download", headers=auth
        )
        assert r.status_code == 200
        assert "attachment" in r.headers["content-disposition"].lower()
        envelope = r.json()
        assert envelope["schema"] == "nks-wdc-snapshot-v1"
        assert envelope["payload"]["marker"] == "dl"

    def test_foreign_device_returns_404(self, client):
        mine = _register(client)
        theirs = _register(client)
        dev = f"bkp-foreign-{uuid.uuid4().hex[:6]}"
        _seed_device(client, mine, dev, {"owner": "mine"})

        r = client.get(
            f"/api/v1/devices/{dev}/backups",
            headers={"Authorization": f"Bearer {theirs}"},
        )
        assert r.status_code == 404


class TestBackupDelete:
    def test_cannot_delete_head(self, client):
        token = _register(client)
        dev = f"bkp-del-head-{uuid.uuid4().hex[:6]}"
        _seed_device(client, token, dev, {"s": 1})
        auth = {"Authorization": f"Bearer {token}"}
        head_id = client.get(
            f"/api/v1/devices/{dev}/backups", headers=auth
        ).json()["head_id"]

        r = client.delete(f"/api/v1/devices/{dev}/backups/{head_id}", headers=auth)
        assert r.status_code == 409

    def test_delete_non_head(self, client):
        token = _register(client)
        dev = f"bkp-del-old-{uuid.uuid4().hex[:6]}"
        auth = {"Authorization": f"Bearer {token}"}
        _seed_device(client, token, dev, {"version": 1})
        _seed_device(client, token, dev, {"version": 2})  # advances HEAD

        lst = client.get(f"/api/v1/devices/{dev}/backups", headers=auth).json()
        non_head = next(i for i in lst["items"] if i["id"] != lst["head_id"])
        r = client.delete(
            f"/api/v1/devices/{dev}/backups/{non_head['id']}", headers=auth
        )
        assert r.status_code == 204


class TestBackupRestore:
    def test_restore_moves_head_and_creates_pre_restore(self, client):
        token = _register(client)
        dev = f"bkp-restore-{uuid.uuid4().hex[:6]}"
        auth = {"Authorization": f"Bearer {token}"}
        _seed_device(client, token, dev, {"state": "A"})
        a_id = client.get(
            f"/api/v1/devices/{dev}/backups", headers=auth
        ).json()["head_id"]
        _seed_device(client, token, dev, {"state": "B"})

        r = client.post(
            f"/api/v1/devices/{dev}/backups/restore",
            json={"snapshot_id": a_id},
            headers=auth,
        )
        assert r.status_code == 200
        lst = client.get(f"/api/v1/devices/{dev}/backups", headers=auth).json()
        assert lst["head_id"] == a_id
        kinds = [i["kind"] for i in lst["items"]]
        assert "pre_restore" in kinds


class TestBackupDiff:
    def test_diff_between_two_snapshots(self, client):
        token = _register(client)
        dev = f"bkp-diff-{uuid.uuid4().hex[:6]}"
        auth = {"Authorization": f"Bearer {token}"}
        _seed_device(client, token, dev, {"sites": ["a"]})
        first = client.get(
            f"/api/v1/devices/{dev}/backups", headers=auth
        ).json()["head_id"]
        _seed_device(client, token, dev, {"sites": ["a", "b"]})
        second = client.get(
            f"/api/v1/devices/{dev}/backups", headers=auth
        ).json()["head_id"]

        r = client.get(
            f"/api/v1/devices/{dev}/backups/diff",
            params={"from": first, "to": second},
            headers=auth,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["from_id"] == first
        assert body["to_id"] == second
        assert len(body["patch"]) >= 1
