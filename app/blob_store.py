"""S3/MinIO-compatible blob backend for oversized snapshot payloads.

When a compressed snapshot exceeds ``BLOB_THRESHOLD`` (2 MiB by default)
the snapshot service spills it into this backend and records an opaque
``blob_uri`` on the ``DeviceSnapshot`` row. The URI scheme is:

    s3://<bucket>/<key>

so a simple ``s3://`` prefix check distinguishes externally-stored
payloads from in-DB ones. Keys are UUID-based to avoid collisions
across accounts and to let the retention runner delete blobs without
coordinating paths with callers.

Configuration (env vars):

- ``NKS_WDC_BLOB_S3_ENDPOINT``   — e.g. ``https://minio.internal:9000``
- ``NKS_WDC_BLOB_S3_BUCKET``     — bucket to use (must already exist)
- ``NKS_WDC_BLOB_S3_ACCESS_KEY``
- ``NKS_WDC_BLOB_S3_SECRET_KEY``
- ``NKS_WDC_BLOB_S3_REGION``     — optional, defaults to ``us-east-1``
- ``NKS_WDC_BLOB_S3_SSE``        — optional ``AES256`` (server-side encryption)

When ``NKS_WDC_BLOB_S3_BUCKET`` is unset this module raises
``BlobBackendNotConfigured`` — the snapshot service then falls back to
its legacy ``PayloadTooLarge`` behaviour. Operators who enable MinIO
must create the bucket out-of-band (we do not auto-create to avoid
accidental data leak into wrong-scope buckets).
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


class BlobBackendNotConfigured(RuntimeError):
    """Raised when code asks for blob storage but env vars are unset."""


@dataclass
class BlobBackendConfig:
    endpoint: str
    bucket: str
    access_key: str
    secret_key: str
    region: str
    sse: Optional[str]


def _config() -> BlobBackendConfig:
    bucket = os.environ.get("NKS_WDC_BLOB_S3_BUCKET")
    if not bucket:
        raise BlobBackendNotConfigured(
            "NKS_WDC_BLOB_S3_BUCKET must be set to enable external blob storage"
        )
    endpoint = os.environ.get("NKS_WDC_BLOB_S3_ENDPOINT", "https://s3.amazonaws.com")
    access_key = os.environ.get("NKS_WDC_BLOB_S3_ACCESS_KEY", "")
    secret_key = os.environ.get("NKS_WDC_BLOB_S3_SECRET_KEY", "")
    region = os.environ.get("NKS_WDC_BLOB_S3_REGION", "us-east-1")
    sse = os.environ.get("NKS_WDC_BLOB_S3_SSE")
    return BlobBackendConfig(
        endpoint=endpoint,
        bucket=bucket,
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        sse=sse,
    )


def _client():
    # Lazy-imported so apps that never upload > 2 MiB payloads don't pay
    # boto3's ~30 MB import cost at startup.
    import boto3
    cfg = _config()
    kwargs = {
        "service_name": "s3",
        "endpoint_url": cfg.endpoint,
        "region_name": cfg.region,
    }
    if cfg.access_key:
        kwargs["aws_access_key_id"] = cfg.access_key
    if cfg.secret_key:
        kwargs["aws_secret_access_key"] = cfg.secret_key
    return boto3.client(**kwargs), cfg


def is_configured() -> bool:
    return bool(os.environ.get("NKS_WDC_BLOB_S3_BUCKET"))


def upload(body: bytes, *, account_id: Optional[int] = None) -> str:
    """Upload a blob, return its canonical ``s3://bucket/key`` URI."""
    client, cfg = _client()
    key = f"snapshots/{account_id or 'shared'}/{uuid.uuid4().hex}.bin"
    put_kwargs: dict = {
        "Bucket": cfg.bucket,
        "Key": key,
        "Body": body,
        "ContentType": "application/octet-stream",
    }
    if cfg.sse:
        put_kwargs["ServerSideEncryption"] = cfg.sse
    client.put_object(**put_kwargs)
    log.info(
        "uploaded blob %s/%s (%d bytes, account=%s)",
        cfg.bucket, key, len(body), account_id,
    )
    return f"s3://{cfg.bucket}/{key}"


def download(uri: str) -> bytes:
    """Fetch bytes for a previously uploaded ``s3://`` URI."""
    if not uri.startswith("s3://"):
        raise ValueError(f"Unsupported blob URI scheme: {uri!r}")
    client, _ = _client()
    _, _, rest = uri.partition("s3://")
    bucket, _, key = rest.partition("/")
    resp = client.get_object(Bucket=bucket, Key=key)
    return resp["Body"].read()


def delete(uri: str) -> None:
    """Remove a blob when its snapshot row is deleted by retention."""
    if not uri.startswith("s3://"):
        raise ValueError(f"Unsupported blob URI scheme: {uri!r}")
    client, _ = _client()
    _, _, rest = uri.partition("s3://")
    bucket, _, key = rest.partition("/")
    client.delete_object(Bucket=bucket, Key=key)
    log.info("deleted blob %s/%s", bucket, key)


__all__ = [
    "BlobBackendNotConfigured",
    "BlobBackendConfig",
    "is_configured",
    "upload",
    "download",
    "delete",
]
