"""Tests for crypto envelope encryption + encrypted snapshot round-trip."""

from __future__ import annotations

import uuid

import pytest

from app import crypto
from app.db import Account, DeviceConfig, create_all, get_session
from app.snapshots import create_snapshot, unpack_payload


@pytest.fixture(scope="module", autouse=True)
def _ensure_schema():
    create_all()
    yield


class TestCryptoPrimitives:
    def test_wrap_unwrap_round_trip(self):
        dek = crypto.generate_dek()
        salt = b"\x00" * 16
        wrapped = crypto.wrap_dek(dek, account_id=7, salt=salt)
        recovered = crypto.unwrap_dek(wrapped, account_id=7, salt=salt)
        assert recovered == dek

    def test_wrong_account_id_fails_auth(self):
        dek = crypto.generate_dek()
        salt = b"\x01" * 16
        wrapped = crypto.wrap_dek(dek, account_id=7, salt=salt)
        with pytest.raises(Exception):
            crypto.unwrap_dek(wrapped, account_id=42, salt=salt)

    def test_payload_encrypt_decrypt_round_trip(self):
        dek = crypto.generate_dek()
        plaintext = b"hello encrypted snapshot"
        ct = crypto.encrypt_payload(plaintext, dek, aad=b"device-x")
        assert crypto.decrypt_payload(ct, dek, aad=b"device-x") == plaintext


class TestEncryptedSnapshots:
    def _fresh_account_and_device(self):
        from app.auth import hash_password

        db = next(get_session())
        try:
            email = f"enc-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
            acc = Account(email=email, password_hash=hash_password("pass12345678"))
            db.add(acc)
            db.flush()
            device_id = f"enc-dev-{uuid.uuid4().hex[:8]}"
            dev = DeviceConfig(device_id=device_id, user_id=acc.id, payload={})
            db.add(dev)
            db.commit()
            return acc.id, device_id
        finally:
            db.close()

    def test_encrypted_payload_round_trip(self):
        account_id, device_id = self._fresh_account_and_device()
        db = next(get_session())
        try:
            snap = create_snapshot(
                db,
                device_id=device_id,
                account_id=account_id,
                payload={"sensitive": "hunter2", "sites": ["blog.loc"]},
                kind="manual",
                label="encrypted",
                encrypt=True,
            )
            db.commit()
            assert snap.encryption_kid is not None
            assert snap.payload_json is None
            assert snap.payload_blob is not None

            recovered = unpack_payload(snap, db=db)
            assert recovered == {"sensitive": "hunter2", "sites": ["blog.loc"]}
        finally:
            db.close()

    def test_tampered_ciphertext_rejected(self):
        account_id, device_id = self._fresh_account_and_device()
        db = next(get_session())
        try:
            snap = create_snapshot(
                db,
                device_id=device_id,
                account_id=account_id,
                payload={"secret": True},
                kind="manual",
                label="enc-tamper",
                encrypt=True,
            )
            db.commit()
            tampered = bytearray(snap.payload_blob)
            tampered[-1] ^= 0x01
            snap.payload_blob = bytes(tampered)
            db.commit()
            with pytest.raises(Exception):
                unpack_payload(snap, db=db)
        finally:
            db.close()
