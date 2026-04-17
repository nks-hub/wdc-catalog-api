"""Public backup API — versioned config snapshots per device.

Endpoints live under ``/api/v1/devices/{device_id}/backups`` and require
a JWT for the account that owns the device. The snapshot service in
``app.snapshots`` does the actual heavy lifting.
"""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import audit, idempotency, snapshots
from .db import Account, DeviceConfig, DeviceSnapshot, get_session
from .devices import get_current_account

router = APIRouter(
    prefix="/api/v1/devices/{device_id}/backups",
    tags=["backups"],
)


# ── Schemas ─────────────────────────────────────────────────────────────


class SnapshotMeta(BaseModel):
    id: int
    device_id: str
    created_at: Optional[str]
    label: Optional[str]
    kind: str
    size_bytes: int
    checksum: str
    compression: Optional[str]
    parent_snapshot_id: Optional[int]


class SnapshotDetail(SnapshotMeta):
    payload: dict


class SnapshotList(BaseModel):
    items: list[SnapshotMeta]
    total: int
    head_id: Optional[int]


class CreateSnapshotRequest(BaseModel):
    label: Optional[str] = Field(None, max_length=128)
    kind: str = Field("manual", pattern=r"^(auto|manual)$")
    payload: Optional[dict] = Field(
        None,
        description="Payload to snapshot. When omitted, the current device "
        "config (as reported by the last sync) is re-snapshotted.",
    )
    encrypt: bool = Field(
        False,
        description="When true, encrypt payload at rest with the account's "
        "active KEK (Variant A) or with the header-supplied "
        "passphrase (Variant B).",
    )


class RestoreRequest(BaseModel):
    snapshot_id: int


class ImportSnapshotRequest(BaseModel):
    """Body of ``POST /backups/import``. Accepts the envelope emitted
    by ``GET /backups/{id}/download`` — ``schema`` + ``payload`` are
    mandatory, every other field is advisory (for operator context)."""

    schema_: str = Field(..., alias="schema", pattern=r"^nks-wdc-snapshot-v1$")
    payload: dict
    label: Optional[str] = Field(None, max_length=128)
    original_id: Optional[int] = Field(None, alias="id")
    original_device_id: Optional[str] = Field(None, alias="device_id")
    created_at: Optional[str] = None
    kind: Optional[str] = None
    checksum: Optional[str] = None

    model_config = {"populate_by_name": True}


class DiffResponse(BaseModel):
    from_id: int
    to_id: int
    patch: list[dict]


# ── Helpers ─────────────────────────────────────────────────────────────


def _owned_device(device_id: str, account: Account, db: Session) -> DeviceConfig:
    dev = db.get(DeviceConfig, device_id.lower())
    if dev is None or dev.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    return dev


def _row(snap: DeviceSnapshot) -> SnapshotMeta:
    return SnapshotMeta(
        id=snap.id,
        device_id=snap.device_id,
        created_at=snap.created_at.isoformat() if snap.created_at else None,
        label=snap.label,
        kind=snap.kind,
        size_bytes=snap.size_bytes,
        checksum=snap.checksum,
        compression=snap.compression,
        parent_snapshot_id=snap.parent_snapshot_id,
    )


# ── Endpoints ───────────────────────────────────────────────────────────


@router.get("", response_model=SnapshotList)
def list_backups(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    kind: Optional[str] = None,
    label: Optional[str] = None,
) -> SnapshotList:
    _owned_device(device_id, account, db)
    rows, total = snapshots.list_snapshots(
        db,
        device_id=device_id.lower(),
        account_id=account.id,
        kind=kind,
        label_like=label,
        offset=offset,
        limit=limit,
    )
    head = snapshots.get_head(db, device_id.lower())
    return SnapshotList(
        items=[_row(r) for r in rows],
        total=total,
        head_id=head.id if head else None,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
def create_backup(
    device_id: str,
    body: CreateSnapshotRequest,
    request: Request,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
    x_wdc_passphrase: Optional[str] = Header(default=None, alias="X-WDC-Passphrase"),
) -> Response:
    cached = idempotency.replay_if_present(db, request, account)
    if cached is not None:
        return cached

    dev = _owned_device(device_id, account, db)
    payload = body.payload if body.payload is not None else (dev.payload or {})
    try:
        snap = snapshots.create_snapshot(
            db,
            device_id=device_id.lower(),
            account_id=account.id,
            payload=payload,
            kind=body.kind,
            label=body.label,
            created_by_ip=request.client.host if request.client else None,
            encrypt=body.encrypt,
            passphrase=x_wdc_passphrase,
        )
    except snapshots.PayloadTooLarge as exc:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    audit.emit(
        db,
        actor=account,
        action="backup.created",
        request=request,
        resource_type="snapshot",
        resource_id=snap.id,
        detail={"device_id": device_id, "kind": snap.kind, "label": snap.label},
    )
    return idempotency.wrap_json(
        db,
        request,
        account,
        _row(snap).model_dump(),
        status_code=status.HTTP_201_CREATED,
    )


@router.get("/diff", response_model=DiffResponse)
def diff_backups(
    device_id: str,
    from_id: int = Query(..., alias="from"),
    to_id: int = Query(..., alias="to"),
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> DiffResponse:
    _owned_device(device_id, account, db)
    a = db.get(DeviceSnapshot, from_id)
    b = db.get(DeviceSnapshot, to_id)
    for snap in (a, b):
        if (
            snap is None
            or snap.device_id != device_id.lower()
            or snap.account_id != account.id
        ):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Snapshot not found")
    return DiffResponse(from_id=from_id, to_id=to_id, patch=snapshots.diff(a, b, db=db))


@router.get("/{snapshot_id}", response_model=SnapshotDetail)
def get_backup(
    device_id: str,
    snapshot_id: int,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
    x_wdc_passphrase: Optional[str] = Header(default=None, alias="X-WDC-Passphrase"),
) -> SnapshotDetail:
    _owned_device(device_id, account, db)
    snap = db.get(DeviceSnapshot, snapshot_id)
    if (
        snap is None
        or snap.device_id != device_id.lower()
        or snap.account_id != account.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Snapshot not found")
    try:
        payload = snapshots.unpack_payload(snap, db=db, passphrase=x_wdc_passphrase)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc))
    return SnapshotDetail(**_row(snap).model_dump(), payload=payload)


@router.get("/{snapshot_id}/download")
def download_backup(
    device_id: str,
    snapshot_id: int,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> Response:
    _owned_device(device_id, account, db)
    snap = db.get(DeviceSnapshot, snapshot_id)
    if (
        snap is None
        or snap.device_id != device_id.lower()
        or snap.account_id != account.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Snapshot not found")
    envelope = {
        "schema": "nks-wdc-snapshot-v1",
        "id": snap.id,
        "device_id": snap.device_id,
        "created_at": snap.created_at.isoformat() if snap.created_at else None,
        "label": snap.label,
        "kind": snap.kind,
        "checksum": snap.checksum,
        "payload": snapshots.unpack_payload(snap, db=db),
    }
    body = json.dumps(envelope, indent=2).encode("utf-8")
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="snapshot-{snap.device_id}-{snap.id}.json"'
            ),
        },
    )


@router.delete("/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_backup(
    device_id: str,
    snapshot_id: int,
    request: Request,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> None:
    _owned_device(device_id, account, db)
    snap = db.get(DeviceSnapshot, snapshot_id)
    if (
        snap is None
        or snap.device_id != device_id.lower()
        or snap.account_id != account.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Snapshot not found")
    head = snapshots.get_head(db, device_id.lower())
    if head is not None and head.id == snap.id:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Cannot delete the current HEAD — restore to another snapshot first",
        )
    audit.emit(
        db,
        actor=account,
        action="backup.deleted",
        request=request,
        resource_type="snapshot",
        resource_id=snap.id,
        detail={"device_id": device_id, "kind": snap.kind, "label": snap.label},
    )
    db.delete(snap)


@router.post("/import", status_code=status.HTTP_201_CREATED)
def import_backup(
    device_id: str,
    body: ImportSnapshotRequest,
    request: Request,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> Response:
    """Import a snapshot envelope (e.g. produced by ``/download`` on
    another instance) onto the target device. Accepts ``Idempotency-Key``
    so repeat uploads from a flaky client land on the same row."""
    cached = idempotency.replay_if_present(db, request, account)
    if cached is not None:
        return cached

    _owned_device(device_id, account, db)
    label = body.label or (
        f"imported-from-{body.original_device_id}-#{body.original_id}"
        if body.original_id is not None
        else "imported-snapshot"
    )
    try:
        snap = snapshots.create_snapshot(
            db,
            device_id=device_id.lower(),
            account_id=account.id,
            payload=body.payload,
            kind="import",
            label=label,
            created_by_ip=request.client.host if request.client else None,
        )
    except snapshots.PayloadTooLarge as exc:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc))
    audit.emit(
        db,
        actor=account,
        action="backup.imported",
        request=request,
        resource_type="snapshot",
        resource_id=snap.id,
        detail={
            "device_id": device_id,
            "source_device_id": body.original_device_id,
            "source_id": body.original_id,
            "label": label,
        },
    )
    return idempotency.wrap_json(
        db,
        request,
        account,
        _row(snap).model_dump(),
        status_code=status.HTTP_201_CREATED,
    )


@router.post("/restore")
def restore_backup(
    device_id: str,
    body: RestoreRequest,
    request: Request,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> Response:
    """Move HEAD to a prior snapshot. Emits a ``pre_restore`` snapshot
    of the current HEAD first so restore is reversible. Honours
    ``Idempotency-Key`` so a retried restore doesn't double-stack
    ``pre_restore`` rows."""
    cached = idempotency.replay_if_present(db, request, account)
    if cached is not None:
        return cached

    _owned_device(device_id, account, db)
    target = db.get(DeviceSnapshot, body.snapshot_id)
    if (
        target is None
        or target.device_id != device_id.lower()
        or target.account_id != account.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target snapshot not found")
    current = snapshots.get_head(db, device_id.lower())
    if current is not None and current.id != target.id:
        snapshots.create_snapshot(
            db,
            device_id=device_id.lower(),
            account_id=account.id,
            payload=snapshots.unpack_payload(current, db=db),
            kind="pre_restore",
            label=f"pre-restore-to-#{target.id}",
        )
    snapshots.set_head(db, device_id.lower(), target.id, updated_by="restore")
    audit.emit(
        db,
        actor=account,
        action="backup.restored",
        request=request,
        resource_type="snapshot",
        resource_id=target.id,
        detail={"device_id": device_id, "from_head": current.id if current else None},
    )
    return idempotency.wrap_json(
        db,
        request,
        account,
        _row(target).model_dump(),
        status_code=status.HTTP_200_OK,
    )


__all__ = ["router"]
