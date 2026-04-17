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
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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


ZSTD_LEVEL = int(os.environ.get("NKS_WDC_ZSTD_LEVEL", "6"))
"""Compression level for snapshot blobs.

Level 6 is the sweet spot: ~3× faster than level 10 on typical 100 KB
JSON configs with only ~3 % worse compression ratio. Bump via env when
storage cost dominates CPU.
"""

_ZSTD_CMP = zstd.ZstdCompressor(level=ZSTD_LEVEL)
_ZSTD_CMP_HIGH = zstd.ZstdCompressor(level=10)
_ZSTD_DEC = zstd.ZstdDecompressor()
"""Module-level compressors/decompressor — reused across requests.

zstandard compressors are thread-safe for ``.compress()``/``.decompress()``
calls, so a single instance avoids the allocation+teardown of a fresh C
context on every snapshot.
"""


def _pack_from_raw(
    raw: bytes,
    checksum: str,
    payload: dict,
    *,
    account_id: Optional[int],
) -> "PackedPayload":
    """Skip the canonical-bytes + checksum work when the caller has
    already computed them (dedup fast path does this)."""
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
    compressed = _ZSTD_CMP.compress(raw)
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
    from . import blob_store

    if blob_store.is_configured():
        uri = blob_store.upload(compressed, account_id=account_id)
        return PackedPayload(
            column="blob_uri",
            json_value=None,
            blob_value=None,
            uri_value=uri,
            compression="zstd",
            size_bytes=len(compressed),
            checksum=checksum,
        )
    raise PayloadTooLarge(
        f"Snapshot {len(compressed)} bytes exceeds BLOB_THRESHOLD "
        f"{BLOB_THRESHOLD}; configure NKS_WDC_BLOB_S3_* to enable external storage."
    )


def pack_payload(payload: dict, *, account_id: Optional[int] = None) -> PackedPayload:
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
    compressed = _ZSTD_CMP.compress(raw)
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
    # Overflow — upload to S3/MinIO if operator opted in.
    from . import blob_store

    if blob_store.is_configured():
        uri = blob_store.upload(compressed, account_id=account_id)
        return PackedPayload(
            column="blob_uri",
            json_value=None,
            blob_value=None,
            uri_value=uri,
            compression="zstd",
            size_bytes=len(compressed),
            checksum=checksum,
        )
    raise PayloadTooLarge(
        f"Snapshot {len(compressed)} bytes exceeds BLOB_THRESHOLD "
        f"{BLOB_THRESHOLD}; configure NKS_WDC_BLOB_S3_* to enable external storage."
    )


def unpack_payload(
    snap: DeviceSnapshot,
    *,
    db: Optional[Session] = None,
    passphrase: Optional[str] = None,
) -> dict:
    if snap.payload_json is not None:
        return snap.payload_json
    if snap.payload_blob is not None:
        raw = snap.payload_blob
    elif snap.blob_uri is not None:
        from . import blob_store

        raw = blob_store.download(snap.blob_uri)
    else:
        raise RuntimeError(f"Snapshot {snap.id} has no payload lane populated")
    if snap.encryption_kid:
        if db is None:
            raise RuntimeError("Cannot unpack encrypted snapshot without a DB session")
        raw = _decrypt_with_kid(
            db,
            snap.encryption_kid,
            snap.account_id,
            raw,
            passphrase=passphrase,
        )
    if snap.compression == "zstd":
        raw = _ZSTD_DEC.decompress(raw)
    return json.loads(raw)


# ── Encryption helpers ─────────────────────────────────────────────────


def _active_key(
    db: Session, account_id: int, *, passphrase: Optional[str] = None
) -> AccountEncryptionKey:
    """Return (or lazily create) the active encryption key for the account.

    When ``passphrase`` is provided the key is stored as Variant B
    (``kek_source='password-derived'``) and every subsequent use MUST
    supply the same passphrase — the server cannot unwrap it otherwise.
    When absent, fallback to the master-key (KMS/env) Variant A.
    """
    filters = [
        AccountEncryptionKey.account_id == account_id,
        AccountEncryptionKey.retired_at.is_(None),
    ]
    if passphrase is not None:
        filters.append(AccountEncryptionKey.kek_source == "password-derived")
    else:
        filters.append(AccountEncryptionKey.kek_source != "password-derived")
    row = db.scalar(
        select(AccountEncryptionKey)
        .where(*filters)
        .order_by(AccountEncryptionKey.created_at.desc())
        .limit(1)
    )
    if row is not None:
        return row

    dek = _crypto.generate_dek()
    salt = os.urandom(16)
    if passphrase is not None:
        kek = _crypto.derive_key_from_passphrase(passphrase, salt)
        wrapped_core = _crypto.wrap_dek_with_kek(dek, kek, account_id)
        kek_source = "password-derived"
    else:
        wrapped_core = _crypto.wrap_dek(dek, account_id, salt)
        kek_source = (
            "dev-ephemeral"
            if os.environ.get("NKS_WDC_CATALOG_DEV") == "1"
            else "master"
        )
    kid = uuid.uuid4().hex
    row = AccountEncryptionKey(
        kid=kid,
        account_id=account_id,
        wrapped_dek=_pack_wrapped_dek(wrapped_core, salt),
        wrap_algo="aes-256-gcm",
        kek_source=kek_source,
    )
    # Partial unique index on (account_id, kek_source) WHERE retired_at
    # IS NULL makes the race between two concurrent snapshot creations
    # visible as an IntegrityError on the losing transaction. Instead of
    # bubbling the 500, retry the SELECT inside a SAVEPOINT — the winner
    # has committed its row by now and the loser reuses it.
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        existing = db.scalar(
            select(AccountEncryptionKey).where(*filters).limit(1)
        )
        if existing is None:
            raise
        return existing
    return row


# ── Wrapped DEK binary format ──────────────────────────────────────────
# v1: ``b"v1" + uint32_be(len_wrapped) + wrapped + salt`` — explicit
# length prefix eliminates the old ``||SALT||`` separator which could
# collide with random GCM ciphertext bytes (~1 in 7.2e16 per row).
# Legacy rows without the ``v1`` magic keep working via the partition
# fallback branch in ``_unpack_wrapped_dek``.

_WRAPPED_DEK_MAGIC = b"v1"
_LEGACY_SEP = b"||SALT||"


def _pack_wrapped_dek(wrapped: bytes, salt: bytes) -> bytes:
    return _WRAPPED_DEK_MAGIC + len(wrapped).to_bytes(4, "big") + wrapped + salt


def _unpack_wrapped_dek(blob: bytes) -> tuple[bytes, bytes]:
    if blob.startswith(_WRAPPED_DEK_MAGIC):
        body = blob[len(_WRAPPED_DEK_MAGIC) :]
        n = int.from_bytes(body[:4], "big")
        return body[4 : 4 + n], body[4 + n :]
    # Legacy rows written before the v1 magic — fall back to the old
    # separator-based partition. New writes always go through the
    # length-prefixed format, so this branch is read-only.
    wrapped, _, salt = blob.partition(_LEGACY_SEP)
    return wrapped, salt


def _unwrap(row: AccountEncryptionKey, *, passphrase: Optional[str] = None) -> bytes:
    wrapped, salt = _unpack_wrapped_dek(row.wrapped_dek)
    if row.kek_source == "password-derived":
        if not passphrase:
            raise PermissionError(
                "Snapshot was encrypted with a passphrase; supply X-WDC-Passphrase"
            )
        kek = _crypto.derive_key_from_passphrase(passphrase, salt)
        return _crypto.unwrap_dek_with_kek(wrapped, kek, row.account_id)
    return _crypto.unwrap_dek(wrapped, row.account_id, salt)


def _decrypt_with_kid(
    db: Session,
    kid: str,
    account_id: Optional[int],
    ciphertext: bytes,
    *,
    passphrase: Optional[str] = None,
) -> bytes:
    row = db.get(AccountEncryptionKey, kid)
    if row is None:
        raise RuntimeError(f"Encryption key {kid} no longer exists")
    dek = _unwrap(row, passphrase=passphrase)
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
    passphrase: Optional[str] = None,
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
    # Cheap path: hash the canonical JSON before we spend CPU on zstd.
    # If the HEAD already matches + we're not taking the labeled branch
    # and not encrypting, we can skip the whole pack/compress dance.
    raw = _canonical_bytes(payload)
    checksum = hashlib.sha256(raw).hexdigest()

    head = get_head(db, device_id)
    if (
        head is not None
        and head.checksum == checksum
        and label is None
        and not (encrypt or passphrase)
    ):
        return head

    packed = _pack_from_raw(raw, checksum, payload, account_id=account_id)

    encryption_kid: Optional[str] = None
    if (encrypt or passphrase) and account_id is not None:
        key_row = _active_key(db, account_id, passphrase=passphrase)
        encryption_kid = key_row.kid
        raw = _canonical_bytes(payload)
        compressed = _ZSTD_CMP_HIGH.compress(raw)
        dek = _unwrap(key_row, passphrase=passphrase)
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
    from .db import count_query

    total = count_query(db, stmt)
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
    """Purge quota-exceeded or TTL-expired auto snapshots.

    Implementation uses a window-function CTE so the "which rows rank past
    ``keep_last_n`` within their device partition" decision happens
    entirely in SQL. Previous implementation materialized every matching
    snapshot into a Python dict keyed by device_id and iterated — fine
    for a tenant with 50 devices × 30 rows; OOM on 1k devices × 30+ rows.

    The CTE approach loads only the candidate ids + blob URIs (small
    projection), so even a 500k-row account stays well under memory
    budget. Postgres + SQLite 3.25+ both honour ROW_NUMBER() in CTEs.
    """
    from sqlalchemy import and_, delete as sql_delete, func, or_

    cutoff_naive: Optional[datetime] = None
    if auto_expire_days is not None:
        cutoff_naive = (
            datetime.now(timezone.utc) - timedelta(days=auto_expire_days)
        ).replace(tzinfo=None)

    # Build the ranked subquery once, then filter by (rn > keep_last_n
    # OR created_at <= cutoff).
    base_filters = [
        DeviceSnapshot.account_id == account_id,
        DeviceSnapshot.kind == "auto",
    ]
    if keep_labeled:
        base_filters.append(DeviceSnapshot.label.is_(None))

    rn = (
        func.row_number()
        .over(
            partition_by=DeviceSnapshot.device_id,
            order_by=DeviceSnapshot.created_at.desc(),
        )
        .label("rn")
    )
    ranked = (
        select(
            DeviceSnapshot.id.label("id"),
            DeviceSnapshot.blob_uri.label("blob_uri"),
            DeviceSnapshot.created_at.label("created_at"),
            rn,
        )
        .where(*base_filters)
        .subquery("ranked")
    )

    head_subq = (
        select(DeviceHead.current_snapshot_id)
        .join(DeviceSnapshot, DeviceSnapshot.device_id == DeviceHead.device_id)
        .where(DeviceSnapshot.account_id == account_id)
    ).subquery("heads")

    reasons = [ranked.c.rn > keep_last_n]
    if cutoff_naive is not None:
        reasons.append(ranked.c.created_at <= cutoff_naive)

    to_delete_stmt = select(ranked.c.id, ranked.c.blob_uri).where(
        and_(
            or_(*reasons),
            ~ranked.c.id.in_(select(head_subq.c.current_snapshot_id)),
        )
    )
    candidates = db.execute(to_delete_stmt).all()
    if not candidates:
        return 0

    doomed_ids: list[int] = []
    blob_uris: list[str] = []
    for row in candidates:
        doomed_ids.append(row.id)
        if row.blob_uri:
            blob_uris.append(row.blob_uri)

    if blob_uris:
        from . import blob_store

        for uri in blob_uris:
            try:
                blob_store.delete(uri)
            except Exception as exc:  # noqa: BLE001
                import logging as _log

                _log.getLogger(__name__).warning(
                    "failed to delete blob %s: %s", uri, exc
                )
                try:
                    from .observability import BLOB_ORPHAN_TOTAL

                    BLOB_ORPHAN_TOTAL.inc()
                except Exception:
                    pass

    # Chunk the DELETE to keep the IN(...) list bounded under SQLite's
    # default 999-parameter ceiling.
    deleted = 0
    CHUNK = 500
    for i in range(0, len(doomed_ids), CHUNK):
        batch = doomed_ids[i : i + CHUNK]
        res = db.execute(
            sql_delete(DeviceSnapshot).where(DeviceSnapshot.id.in_(batch))
        )
        deleted += res.rowcount or 0
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
