"""Zero-knowledge passphrase-protected snapshots (Encryption Variant B)."""

from __future__ import annotations

import uuid

import pytest

from app import crypto, snapshots
from app.db import Account, DeviceConfig, create_all, get_session


@pytest.fixture(scope="module", autouse=True)
def _ensure_schema():
    create_all()
    yield


def _account_device() -> tuple[int, str]:
    from app.auth import hash_password

    db = next(get_session())
    try:
        acc = Account(
            email=f"v-b-{uuid.uuid4().hex[:8]}@nks-wdc.dev",
            password_hash=hash_password("pass12345678"),
        )
        db.add(acc)
        db.flush()
        device_id = f"v-b-{uuid.uuid4().hex[:8]}"
        db.add(DeviceConfig(device_id=device_id, user_id=acc.id, payload={}))
        db.commit()
        return acc.id, device_id
    finally:
        db.close()


class TestArgon2Derivation:
    def test_derive_produces_stable_key_for_same_input(self):
        salt = b"\x00" * 16
        k1 = crypto.derive_key_from_passphrase("hunter2-is-bad", salt)
        k2 = crypto.derive_key_from_passphrase("hunter2-is-bad", salt)
        assert k1 == k2
        assert len(k1) == 32

    def test_different_salt_yields_different_key(self):
        k1 = crypto.derive_key_from_passphrase("pass-good-enough", b"\x00" * 16)
        k2 = crypto.derive_key_from_passphrase("pass-good-enough", b"\x11" * 16)
        assert k1 != k2

    def test_short_passphrase_rejected(self):
        with pytest.raises(ValueError):
            crypto.derive_key_from_passphrase("short", b"\x00" * 16)

    def test_short_salt_rejected(self):
        with pytest.raises(ValueError):
            crypto.derive_key_from_passphrase("pass-good-enough", b"\x00" * 8)


class TestVariantBSnapshots:
    def test_passphrase_snapshot_round_trip(self):
        account_id, device_id = _account_device()
        db = next(get_session())
        try:
            snap = snapshots.create_snapshot(
                db,
                device_id=device_id,
                account_id=account_id,
                payload={"vault": "top-secret"},
                kind="manual",
                label="encrypted-b",
                passphrase="correct-horse-battery",
            )
            db.commit()
            assert snap.encryption_kid is not None

            # Key row must record Variant B source
            from app.db import AccountEncryptionKey

            key = db.get(AccountEncryptionKey, snap.encryption_kid)
            assert key.kek_source == "password-derived"

            # With the same passphrase we recover the payload
            recovered = snapshots.unpack_payload(
                snap, db=db, passphrase="correct-horse-battery"
            )
            assert recovered == {"vault": "top-secret"}
        finally:
            db.close()

    def test_missing_passphrase_raises_permission_error(self):
        account_id, device_id = _account_device()
        db = next(get_session())
        try:
            snap = snapshots.create_snapshot(
                db,
                device_id=device_id,
                account_id=account_id,
                payload={"vault": "x"},
                kind="manual",
                label="enc-b-nopp",
                passphrase="right-passphrase-123",
            )
            db.commit()
            with pytest.raises(PermissionError):
                snapshots.unpack_payload(snap, db=db)
        finally:
            db.close()

    def test_wrong_passphrase_fails_decrypt(self):
        account_id, device_id = _account_device()
        db = next(get_session())
        try:
            snap = snapshots.create_snapshot(
                db,
                device_id=device_id,
                account_id=account_id,
                payload={"vault": "x"},
                kind="manual",
                label="enc-b-wrong",
                passphrase="right-passphrase-456",
            )
            db.commit()
            with pytest.raises(Exception):
                snapshots.unpack_payload(snap, db=db, passphrase="totally-different-pw")
        finally:
            db.close()

    def test_variant_a_and_b_keys_coexist(self):
        account_id, device_id = _account_device()
        db = next(get_session())
        try:
            snap_a = snapshots.create_snapshot(
                db,
                device_id=device_id,
                account_id=account_id,
                payload={"mode": "A"},
                kind="manual",
                label="a",
                encrypt=True,
            )
            snap_b = snapshots.create_snapshot(
                db,
                device_id=device_id,
                account_id=account_id,
                payload={"mode": "B"},
                kind="manual",
                label="b",
                passphrase="variant-b-secret-pw",
            )
            db.commit()
            assert snap_a.encryption_kid != snap_b.encryption_kid
            # A unpacks without passphrase
            assert snapshots.unpack_payload(snap_a, db=db) == {"mode": "A"}
            # B unpacks only with passphrase
            assert snapshots.unpack_payload(
                snap_b, db=db, passphrase="variant-b-secret-pw"
            ) == {"mode": "B"}
        finally:
            db.close()


class TestVariantBOverHTTP:
    """End-to-end: passphrase flows through X-WDC-Passphrase header."""

    def test_create_and_get_via_header(self):
        from fastapi.testclient import TestClient
        from app.main import app

        with TestClient(app) as client:
            email = f"v-b-http-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
            r = client.post(
                "/api/v1/auth/register",
                json={"email": email, "password": "pass12345678"},
            )
            tok = r.json()["token"]
            auth = {"Authorization": f"Bearer {tok}"}

            dev = f"v-b-http-{uuid.uuid4().hex[:6]}"
            client.post(
                "/api/v1/sync/config",
                json={"device_id": dev, "payload": {"seed": True}},
                headers=auth,
            )

            create = client.post(
                f"/api/v1/devices/{dev}/backups",
                json={
                    "kind": "manual",
                    "label": "zero-knowledge",
                    "payload": {"secret": "data"},
                },
                headers={**auth, "X-WDC-Passphrase": "my-unique-pw-1234"},
            )
            assert create.status_code == 201
            snap_id = create.json()["id"]

            # Fetching without passphrase fails
            r = client.get(
                f"/api/v1/devices/{dev}/backups/{snap_id}",
                headers=auth,
            )
            assert r.status_code == 401

            # With correct passphrase succeeds
            r = client.get(
                f"/api/v1/devices/{dev}/backups/{snap_id}",
                headers={**auth, "X-WDC-Passphrase": "my-unique-pw-1234"},
            )
            assert r.status_code == 200
            assert r.json()["payload"] == {"secret": "data"}
