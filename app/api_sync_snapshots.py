"""Sync-snapshot endpoints — lightweight per-push rollback store.

GET    /api/v1/sync/snapshots              list snapshots for caller
GET    /api/v1/sync/snapshots/{id}         retrieve with decompressed payload
POST   /api/v1/sync/snapshots/{id}/restore return payload in ConfigSyncEntry shape
DELETE /api/v1/sync/snapshots/{id}         hard delete

Rotation (keep=10 per device) is enforced by the push path in api_sync.py.
"""

from __future__ import annotations

import gzip
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Account, SyncSnapshot, get_session
from .devices import get_current_account
from .schemas import ConfigSyncEntry

log = logging.getLogger(__name__)
router = APIRouter(tags=["sync"])

KEEP_PER_DEVICE = 10


# ── Pydantic response shapes ───────────────────────────────────────────


class SyncSnapshotMeta(BaseModel):
    id: int
    device_id: str
    created_at: str
    size_bytes: int


class SyncSnapshotDetail(SyncSnapshotMeta):
    payload: dict


class SyncSnapshotListResponse(BaseModel):
    snapshots: list[SyncSnapshotMeta]


# ── Helpers ────────────────────────────────────────────────────────────


def _require_snapshot(snapshot_id: int, account: Account, db: Session) -> SyncSnapshot:
    """Load a SyncSnapshot, enforcing ownership. Returns 404 for wrong account."""
    row = db.get(SyncSnapshot, snapshot_id)
    if row is None or row.account_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Snapshot not found")
    return row


def _decompress(row: SyncSnapshot) -> dict:
    raw = gzip.decompress(row.content_gzip)
    return json.loads(raw)


def _meta(row: SyncSnapshot) -> SyncSnapshotMeta:
    return SyncSnapshotMeta(
        id=row.id,
        device_id=row.device_id,
        created_at=row.created_at.isoformat(),
        size_bytes=row.size_bytes,
    )


# ── Public helpers used by api_sync.py push path ───────────────────────


def create_sync_snapshot(
    db: Session,
    *,
    device_id: str,
    account_id: int,
    payload: dict,
) -> SyncSnapshot:
    """Compress payload, insert a SyncSnapshot row, rotate to keep=10."""
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw, compresslevel=6)
    snap = SyncSnapshot(
        device_id=device_id,
        account_id=account_id,
        size_bytes=len(compressed),
        content_gzip=compressed,
    )
    db.add(snap)
    db.flush()
    _rotate(db, device_id=device_id, account_id=account_id)
    return snap


def _rotate(db: Session, *, device_id: str, account_id: int) -> None:
    """Delete oldest rows beyond KEEP_PER_DEVICE for this device+account."""
    stmt = (
        select(SyncSnapshot.id)
        .where(
            SyncSnapshot.device_id == device_id,
            SyncSnapshot.account_id == account_id,
        )
        .order_by(SyncSnapshot.created_at.desc())
        .offset(KEEP_PER_DEVICE)
    )
    old_ids = list(db.scalars(stmt).all())
    if old_ids:
        for row_id in old_ids:
            row = db.get(SyncSnapshot, row_id)
            if row is not None:
                db.delete(row)
        db.flush()


# ── Endpoints ──────────────────────────────────────────────────────────


@router.get("/api/v1/sync/snapshots", response_model=SyncSnapshotListResponse)
def list_sync_snapshots(
    device_id: Optional[str] = Query(None),
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> SyncSnapshotListResponse:
    stmt = (
        select(SyncSnapshot)
        .where(SyncSnapshot.account_id == account.id)
        .order_by(SyncSnapshot.created_at.desc())
        .limit(50)
    )
    if device_id is not None:
        stmt = stmt.where(SyncSnapshot.device_id == device_id)
    rows = list(db.scalars(stmt).all())
    return SyncSnapshotListResponse(snapshots=[_meta(r) for r in rows])


@router.get("/api/v1/sync/snapshots/{snapshot_id}", response_model=SyncSnapshotDetail)
def get_sync_snapshot(
    snapshot_id: int,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> SyncSnapshotDetail:
    row = _require_snapshot(snapshot_id, account, db)
    return SyncSnapshotDetail(
        id=row.id,
        device_id=row.device_id,
        created_at=row.created_at.isoformat(),
        size_bytes=row.size_bytes,
        payload=_decompress(row),
    )


@router.post(
    "/api/v1/sync/snapshots/{snapshot_id}/restore",
    response_model=ConfigSyncEntry,
)
def restore_sync_snapshot(
    snapshot_id: int,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> ConfigSyncEntry:
    """Return the snapshot payload in the same shape as GET /sync/config/{device_id}."""
    row = _require_snapshot(snapshot_id, account, db)
    payload = _decompress(row)
    return ConfigSyncEntry(
        device_id=row.device_id,
        updated_at=row.created_at.isoformat(),
        payload=payload,
    )


@router.delete(
    "/api/v1/sync/snapshots/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_sync_snapshot(
    snapshot_id: int,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> None:
    row = _require_snapshot(snapshot_id, account, db)
    db.delete(row)


__all__ = ["router", "create_sync_snapshot"]
