"""Unit tests for the snapshot service module."""

from __future__ import annotations

import uuid

import pytest

from app import snapshots as snap
from app.db import Account, DeviceConfig, DeviceSnapshot, create_all, get_session
from app.snapshots import (
    PayloadTooLarge,
    create_snapshot,
    diff,
    get_head,
    list_snapshots,
    pack_payload,
    purge_auto_older_than,
    unpack_payload,
)


@pytest.fixture(scope="module", autouse=True)
def _ensure_schema():
    create_all()
    yield


@pytest.fixture()
def sample_account() -> int:
    from app.auth import hash_password

    db = next(get_session())
    try:
        email = f"snap-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
        acc = Account(email=email, password_hash=hash_password("pass12345678"))
        db.add(acc)
        db.flush()
        db.commit()
        return acc.id
    finally:
        db.close()


@pytest.fixture()
def sample_device(sample_account: int) -> str:
    db = next(get_session())
    try:
        device_id = f"snap-device-{uuid.uuid4().hex[:8]}"
        dev = DeviceConfig(
            device_id=device_id,
            user_id=sample_account,
            payload={"seed": True},
        )
        db.add(dev)
        db.commit()
        return device_id
    finally:
        db.close()


class TestPackPayload:
    def test_tiny_payload_goes_inline(self):
        stored = pack_payload({"hello": "world"})
        assert stored.column == "payload_json"
        assert stored.json_value is not None
        assert stored.compression is None

    def test_medium_payload_goes_to_blob(self):
        import base64
        import os as _os

        # Random data → incompressible, forces the raw size over the
        # inline threshold so the blob lane is exercised even after zstd.
        big = {"k": base64.b64encode(_os.urandom(200_000)).decode("ascii")}
        stored = pack_payload(big)
        assert stored.column == "payload_blob"
        assert stored.blob_value is not None
        assert stored.compression == "zstd"

    def test_oversized_payload_raises(self):
        import base64
        import os as _os

        # ~3.2 MB of random base64 → compresses to ~3.2 MB → over 2 MB ceiling.
        huge = {"k": base64.b64encode(_os.urandom(3 * 1024 * 1024)).decode("ascii")}
        with pytest.raises(PayloadTooLarge):
            pack_payload(huge)

    def test_checksum_is_stable_for_identical_content(self):
        a = pack_payload({"a": 1, "b": 2})
        b = pack_payload({"b": 2, "a": 1})  # different key order
        assert a.checksum == b.checksum


class TestCreateSnapshot:
    def test_creates_and_advances_head(self, sample_device, sample_account):
        db = next(get_session())
        try:
            snap_row = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"sites": ["a.loc", "b.loc"]},
                kind="auto",
            )
            db.commit()
            assert snap_row.id is not None
            head = get_head(db, sample_device)
            assert head is not None
            assert head.id == snap_row.id
        finally:
            db.close()

    def test_dedup_when_identical_payload_pushed(self, sample_device, sample_account):
        db = next(get_session())
        try:
            first = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"stable": "value"},
            )
            db.commit()
            second = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"stable": "value"},
            )
            db.commit()
            assert first.id == second.id
        finally:
            db.close()

    def test_manual_label_creates_new_row_even_if_dedup_matches(
        self, sample_device, sample_account
    ):
        db = next(get_session())
        try:
            first = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"same": 1},
            )
            db.commit()
            labeled = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"same": 1},
                kind="manual",
                label="before-upgrade",
            )
            db.commit()
            assert labeled.id != first.id
            assert labeled.label == "before-upgrade"
        finally:
            db.close()


class TestUnpackAndDiff:
    def test_round_trip_inline_payload(self, sample_device, sample_account):
        db = next(get_session())
        try:
            snap_row = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"sites": [1, 2, 3]},
            )
            db.commit()
            assert unpack_payload(snap_row) == {"sites": [1, 2, 3]}
        finally:
            db.close()

    def test_round_trip_blob_payload(self, sample_device, sample_account):
        db = next(get_session())
        try:
            big = {"k": "x" * 150_000}
            snap_row = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload=big,
            )
            db.commit()
            restored = unpack_payload(snap_row)
            assert restored == big
        finally:
            db.close()

    def test_diff_emits_json_patch(self, sample_device, sample_account):
        db = next(get_session())
        try:
            a = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"sites": ["a"]},
            )
            db.commit()
            b = create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"sites": ["a", "b"]},
            )
            db.commit()
            patch = diff(a, b)
            assert any(op.get("op") == "add" for op in patch)
        finally:
            db.close()


class TestListSnapshots:
    def test_list_requires_ownership(self, sample_device, sample_account):
        db = next(get_session())
        try:
            create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"x": 1},
            )
            db.commit()
            owned, total = list_snapshots(
                db, device_id=sample_device, account_id=sample_account
            )
            assert total == 1
            not_mine, _ = list_snapshots(
                db, device_id=sample_device, account_id=sample_account + 9999
            )
            assert not_mine == []
        finally:
            db.close()


class TestRetention:
    def test_keeps_last_n_and_labeled(self, sample_device, sample_account):
        db = next(get_session())
        try:
            # Produce 6 auto snapshots with distinct payloads (dedup skips identical)
            for i in range(6):
                create_snapshot(
                    db,
                    device_id=sample_device,
                    account_id=sample_account,
                    payload={"version": i},
                )
            create_snapshot(
                db,
                device_id=sample_device,
                account_id=sample_account,
                payload={"version": 99},
                kind="manual",
                label="keep-me",
            )
            db.commit()

            deleted = purge_auto_older_than(
                db,
                account_id=sample_account,
                keep_last_n=3,
                auto_expire_days=None,
                keep_labeled=True,
            )
            db.commit()
            # 6 autos - 3 kept (newest) - 1 HEAD overlap = 2 or 3 deleted
            assert deleted >= 1
            # Labeled survives
            remaining_labels = [
                s.label
                for s in db.scalars(
                    snap.select(DeviceSnapshot).where(  # type: ignore[attr-defined]
                        DeviceSnapshot.device_id == sample_device
                    )
                ).all()
                if s.label is not None
            ]
            assert "keep-me" in remaining_labels
        finally:
            db.close()
