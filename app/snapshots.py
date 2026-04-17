"""Snapshot service — versioned per-device config storage.

Responsibilities:
- Packing / unpacking payloads with storage tiering (inline JSON vs
  compressed blob) and optional envelope encryption.
- ``create_snapshot`` — append a new immutable row + move HEAD.
- ``get_head`` / ``set_head`` — restore is a HEAD pointer move.
- ``diff`` — RFC 6902 JSON Patch between two snapshots.
- ``list_snapshots`` — owner-scoped, paginated listing.
- ``purge_auto_older_than`` — retention runner entry point.

Storage thresholds (override via env):
- ``<= 64 KiB`` serialized JSON → inline ``payload_json`` (queryable).
- ``<= 2 MiB`` → zstd-compressed ``payload_blob`` (ACID, still in DB).
- > 2 MiB → future external object store; currently raises.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import zstandard as zstd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import crypto as _crypto
from .db import AccountEncryptionKey, DeviceHead, DeviceSnapshot


INLINE_THRESHOLD = int(os.environ.get("NKS_WDC_SNAP_INLINE_MAX", 64 * 1024))
BLOB_THRESHOLD = int(os.environ.get("NKS_WDC_SNAP_BLOB_MAX", 2 * 1024 * 1024))


class PayloadTooLarge(ValueError):
    """Raised when a snapshot exceeds the in-DB blob ceiling."""


@dataclass
class PackedPayload:
    column: str
    json_value: Optional[dict]
    blob_value: Optional[bytes]
    uri_value: Optional[str]
    compression: Optional[str]
    size_bytes: int
    checksum: str


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pack_payload(payload: dict) -> PackedPayload:
    raw = _canonical_bytes(payload)
    checksum = hashlib.sha256(raw).hexdigest()
    if len(raw) <= INLINE_THRESHOLD:
        return PackedPayload(
            column="payload_json",
            json_value=payload,
            blob_value=None,
            uri_value=None,
            compression=None,
            size_bytes=len(raw),
            checksum=checksum,
        )
    compressed = zstd.ZstdCompressor(level=10).compress(raw)
    if len(compressed) <= BLOB_THRESHOLD:
        return PackedPayload(
            column="payload_blob",
            json_value=None,
            blob_value=compressed,
            uri_value=None,
            compression="zstd",
            size_bytes=len(compressed),
            checksum=checksum,
        )
    raise PayloadTooLarge(
        f"Snapshot {len(compressed)} bytes exceeds BLOB_THRESHOLD "
        f"{BLOB_THRESHOLD}; external object store not yet implemented."
    )


def unpack_payload(snap: DeviceSnapshot, *, db: Optional[Session] = None) -> dict:
    if snap.payload_json is not None:
        return snap.payload_json
    if snap.payload_blob is not None:
        raw = snap.payload_blob
        if snap.encryption_kid:
            if db is None:
                raise RuntimeError(
                    "Cannot unpack encrypted snapshot without a DB session"
                )
            raw = _decrypt_with_kid(db, snap.encryption_kid, snap.account_id, raw)
        if snap.compression == "zstd":
            raw = zstd.ZstdDecompressor().decompress(raw)
        return json.loads(raw)
    if snap.blob_uri is not None:
        raise NotImplementedError("External blob storage not yet implemented")
    raise RuntimeError(f"Snapshot {snap.id} has no payload lane populated")


# ── Encryption helpers ─────────────────────────────────────────────────

def _active_key(db: Session, account_id: int) -> AccountEncryptionKey:
    """Return (or create) the currently-active encryption key for the account."""
    row = db.scalar(
        select(AccountEncryptionKey)
        .where(
            AccountEncryptionKey.account_id == account_id,
            AccountEncryptionKey.retired_at.is_(None),
        )
        .order_by(AccountEncryptionKey.created_at.desc())
        .limit(1)
    )
    if row is not None:
        return row
    dek = _crypto.generate_dek()
    salt = os.urandom(16)
    wrapped = _crypto.wrap_dek(dek, account_id, salt) + b"||SALT||" + salt
    kid = uuid.uuid4().hex
    row = AccountEncryptionKey(
        kid=kid,
        account_id=account_id,
        wrapped_dek=wrapped,
        wrap_algo="aes-256-gcm",
        kek_source=("dev-ephemeral" if os.environ.get("NKS_WDC_CATALOG_DEV") == "1"
                     else "master"),
    )
    db.add(row)
    db.flush()
    return row


def _unwrap(row: AccountEncryptionKey) -> bytes:
    wrapped, _, salt = row.wrapped_dek.partition(b"||SALT||")
    return _crypto.unwrap_dek(wrapped, row.account_id, salt)


def _decrypt_with_kid(
    db: Session, kid: str, account_id: Optional[int], ciphertext: bytes
) -> bytes:
    row = db.get(AccountEncryptionKey, kid)
    if row is None:
        raise RuntimeError(f"Encryption key {kid} no longer exists")
    dek = _unwrap(row)
    aad = f"nks-wdc-snapshot-{account_id or 0}".encode("ascii")
    return _crypto.decrypt_payload(ciphertext, dek, aad=aad)


def create_snapshot(
    db: Session,
    *,
    device_id: str,
    account_id: Optional[int],
    payload: dict,
    kind: str = "auto",
    label: Optional[str] = None,
    created_by_ip: Optional[str] = None,
    encrypt: bool = False,
) -> DeviceSnapshot:
    """Append a snapshot + advance HEAD.

    Identical-payload syncs reuse the existing HEAD (dedup) *unless* a
    label is provided — labeled snapshots always allocate a new row so
    operators can mark known-good points before upgrades.

    When ``encrypt=True`` (and ``account_id`` is present) the payload is
    zstd-compressed then AES-GCM encrypted with the account's active DEK.
    The envelope ``(nonce || ciphertext)`` lives in ``payload_blob`` and
    ``encryption_kid`` pins which DEK unwraps it.
    """
    packed = pack_payload(payload)

    head = get_head(db, device_id)
    if head is not None and head.checksum == packed.checksum and label is None:
        return head

    encryption_kid: Optional[str] = None
    if encrypt and account_id is not None:
        key_row = _active_key(db, account_id)
        encryption_kid = key_row.kid
        # Serialize to bytes (compressed if the inline lane was chosen),
        # then AES-GCM encrypt.
        raw = _canonical_bytes(payload)
        compressed = zstd.ZstdCompressor(level=10).compress(raw)
        dek = _unwrap(key_row)
        aad = f"nks-wdc-snapshot-{account_id}".encode("ascii")
        envelope = _crypto.encrypt_payload(compressed, dek, aad=aad)
        packed = PackedPayload(
            column="payload_blob",
            json_value=None,
            blob_value=envelope,
            uri_value=None,
            compression="zstd",
            size_bytes=len(envelope),
            checksum=packed.checksum,
        )

    snap = DeviceSnapshot(
        device_id=device_id,
        account_id=account_id,
        label=label,
        kind=kind,
        size_bytes=packed.size_bytes,
        payload_json=packed.json_value,
        payload_blob=packed.blob_value,
        blob_uri=packed.uri_value,
        checksum=packed.checksum,
        compression=packed.compression,
        encryption_kid=encryption_kid,
        parent_snapshot_id=head.id if head else None,
        created_by_ip=created_by_ip,
    )
    db.add(snap)
    db.flush()
    set_head(db, device_id, snap.id, updated_by=kind)
    try:
        from .observability import SNAPSHOTS_CREATED
        SNAPSHOTS_CREATED.labels(kind=kind).inc()
    except Exception:
        pass  # metrics are optional — never fail a write because of them
    return snap


def set_head(
    db: Session, device_id: str, snapshot_id: int, *, updated_by: str = "sync"
) -> DeviceHead:
    row = db.get(DeviceHead, device_id)
    if row is None:
        row = DeviceHead(
            device_id=device_id,
            current_snapshot_id=snapshot_id,
            updated_by=updated_by,
        )
        db.add(row)
    else:
        row.current_snapshot_id = snapshot_id
        row.updated_by = updated_by
    db.flush()
    return row


def get_head(db: Session, device_id: str) -> Optional[DeviceSnapshot]:
    row = db.get(DeviceHead, device_id)
    if row is None:
        return None
    return db.get(DeviceSnapshot, row.current_snapshot_id)


def list_snapshots(
    db: Session,
    *,
    device_id: str,
    account_id: int,
    kind: Optional[str] = None,
    label_like: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[DeviceSnapshot], int]:
    stmt = select(DeviceSnapshot).where(
        DeviceSnapshot.device_id == device_id,
        DeviceSnapshot.account_id == account_id,
    )
    if kind:
        stmt = stmt.where(DeviceSnapshot.kind == kind)
    if label_like:
        stmt = stmt.where(DeviceSnapshot.label.like(f"%{label_like}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(DeviceSnapshot.created_at.desc())
        .offset(max(0, offset))
        .limit(max(1, min(limit, 200)))
    ).all()
    return list(rows), total


def diff(
    a: DeviceSnapshot,
    b: DeviceSnapshot,
    *,
    db: Optional[Session] = None,
) -> list[dict]:
    """RFC 6902 JSON Patch going *from* ``a`` *to* ``b``."""
    import jsonpatch
    payload_a = unpack_payload(a, db=db)
    payload_b = unpack_payload(b, db=db)
    return list(jsonpatch.make_patch(payload_a, payload_b).patch)


def purge_auto_older_than(
    db: Session,
    *,
    account_id: int,
    keep_last_n: int = 30,
    auto_expire_days: Optional[int] = None,
    keep_labeled: bool = True,
) -> int:
    head_ids = set(
        db.scalars(
            select(DeviceHead.current_snapshot_id)
            .join(DeviceSnapshot, DeviceSnapshot.device_id == DeviceHead.device_id)
            .where(DeviceSnapshot.account_id == account_id)
        ).all()
    )

    by_device: dict[str, list[DeviceSnapshot]] = {}
    stmt = select(DeviceSnapshot).where(
        DeviceSnapshot.account_id == account_id,
        DeviceSnapshot.kind == "auto",
    )
    if keep_labeled:
        stmt = stmt.where(DeviceSnapshot.label.is_(None))
    for row in db.scalars(stmt.order_by(DeviceSnapshot.created_at.desc())).all():
        by_device.setdefault(row.device_id, []).append(row)

    cutoff = None
    if auto_expire_days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=auto_expire_days)

    deleted = 0
    for _device_id, rows in by_device.items():
        for idx, snap in enumerate(rows):
            if snap.id in head_ids:
                continue
            if idx < keep_last_n:
                continue
            if cutoff is not None and snap.created_at > cutoff.replace(tzinfo=None):
                continue
            db.delete(snap)
            deleted += 1
    db.flush()
    return deleted


__all__ = [
    "PackedPayload",
    "PayloadTooLarge",
    "pack_payload",
    "unpack_payload",
    "create_snapshot",
    "set_head",
    "get_head",
    "list_snapshots",
    "diff",
    "purge_auto_older_than",
    "select",
]
