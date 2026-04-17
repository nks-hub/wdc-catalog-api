"""Round-trip tests for the S3/MinIO blob backend using moto."""

from __future__ import annotations

import base64
import os
import uuid

import pytest

# moto 5.x uses `mock_aws` universal decorator; older versions used `mock_s3`.
try:
    from moto import mock_aws as _moto_aws
except ImportError:  # pragma: no cover
    from moto import mock_s3 as _moto_aws  # type: ignore

from app import blob_store, snapshots
from app.db import Account, DeviceConfig, create_all, get_session


@pytest.fixture(scope="module", autouse=True)
def _ensure_schema():
    create_all()
    yield


@pytest.fixture()
def s3_env(monkeypatch):
    """Spin up an in-process S3 fake + point the blob backend at it."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("NKS_WDC_BLOB_S3_BUCKET", "nks-wdc-test-bucket")
    monkeypatch.setenv("NKS_WDC_BLOB_S3_ENDPOINT", "https://s3.us-east-1.amazonaws.com")
    monkeypatch.setenv("NKS_WDC_BLOB_S3_ACCESS_KEY", "testing")
    monkeypatch.setenv("NKS_WDC_BLOB_S3_SECRET_KEY", "testing")
    with _moto_aws():
        import boto3

        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket="nks-wdc-test-bucket"
        )
        yield


class TestBlobBackend:
    def test_not_configured_raises(self, monkeypatch):
        monkeypatch.delenv("NKS_WDC_BLOB_S3_BUCKET", raising=False)
        assert blob_store.is_configured() is False
        with pytest.raises(blob_store.BlobBackendNotConfigured):
            blob_store.upload(b"x", account_id=1)

    def test_upload_download_round_trip(self, s3_env):
        assert blob_store.is_configured() is True
        uri = blob_store.upload(b"hello world", account_id=42)
        assert uri.startswith("s3://nks-wdc-test-bucket/snapshots/42/")
        assert blob_store.download(uri) == b"hello world"

    def test_delete_removes_object(self, s3_env):
        uri = blob_store.upload(b"will-be-gone", account_id=1)
        blob_store.delete(uri)
        with pytest.raises(Exception):
            blob_store.download(uri)


class TestSnapshotSpillover:
    def _account_device(self):
        from app.auth import hash_password

        db = next(get_session())
        try:
            acc = Account(
                email=f"spill-{uuid.uuid4().hex[:8]}@nks-wdc.dev",
                password_hash=hash_password("pass12345678"),
            )
            db.add(acc)
            db.flush()
            device_id = f"spill-{uuid.uuid4().hex[:8]}"
            db.add(DeviceConfig(device_id=device_id, user_id=acc.id, payload={}))
            db.commit()
            return acc.id, device_id
        finally:
            db.close()

    def test_oversize_payload_spills_to_blob_uri(self, s3_env, monkeypatch):
        # Force both thresholds low so a modest payload spills to S3.
        monkeypatch.setattr(snapshots, "INLINE_THRESHOLD", 1024)
        monkeypatch.setattr(snapshots, "BLOB_THRESHOLD", 2048)
        account_id, device_id = self._account_device()
        db = next(get_session())
        try:
            # Random bytes don't compress much → exceeds BLOB_THRESHOLD
            big = {
                "k": base64.b64encode(os.urandom(8_000)).decode("ascii"),
            }
            snap = snapshots.create_snapshot(
                db,
                device_id=device_id,
                account_id=account_id,
                payload=big,
                kind="manual",
                label="overflow",
            )
            db.commit()
            assert snap.blob_uri is not None
            assert snap.blob_uri.startswith("s3://nks-wdc-test-bucket/snapshots/")
            assert snap.payload_json is None
            assert snap.payload_blob is None

            # Round-trip through download + zstd decompress
            recovered = snapshots.unpack_payload(snap, db=db)
            assert recovered == big
        finally:
            db.close()

    def test_oversize_without_backend_raises(self, monkeypatch):
        monkeypatch.delenv("NKS_WDC_BLOB_S3_BUCKET", raising=False)
        monkeypatch.setattr(snapshots, "INLINE_THRESHOLD", 1024)
        monkeypatch.setattr(snapshots, "BLOB_THRESHOLD", 2048)
        with pytest.raises(snapshots.PayloadTooLarge):
            snapshots.pack_payload(
                {"k": base64.b64encode(os.urandom(8_000)).decode("ascii")},
                account_id=1,
            )
