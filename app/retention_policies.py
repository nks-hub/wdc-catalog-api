"""Account-scoped retention policy CRUD.

Endpoints live under ``/api/v1/retention/policies`` and let the owning
account tune how aggressively the scheduled runner prunes their auto
snapshots. ``device_id = null`` rows are account-wide defaults; rows
with ``device_id`` set override the default for that single device.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .db import Account, DeviceConfig, SnapshotRetentionPolicy, get_session
from .devices import get_current_account

router = APIRouter(prefix="/api/v1/retention/policies", tags=["retention"])


# ── Schemas ─────────────────────────────────────────────────────────────


class PolicyRow(BaseModel):
    id: int
    device_id: Optional[str]
    keep_last_n_auto: int
    auto_expire_days: Optional[int]
    keep_labeled_forever: bool
    max_total_bytes: Optional[int]
    updated_at: Optional[str]


class PolicyList(BaseModel):
    items: list[PolicyRow]
    total: int


class PolicyUpsert(BaseModel):
    device_id: Optional[str] = Field(
        None,
        description="Specific device scope. Omit or null to set the "
        "account-wide default.",
    )
    keep_last_n_auto: int = Field(30, ge=1, le=1000)
    auto_expire_days: Optional[int] = Field(None, ge=1, le=3650)
    keep_labeled_forever: bool = True
    max_total_bytes: Optional[int] = Field(None, ge=0)


# ── Helpers ─────────────────────────────────────────────────────────────


def _row_to_model(row: SnapshotRetentionPolicy) -> PolicyRow:
    return PolicyRow(
        id=row.id,
        device_id=row.device_id,
        keep_last_n_auto=row.keep_last_n_auto,
        auto_expire_days=row.auto_expire_days,
        keep_labeled_forever=row.keep_labeled_forever,
        max_total_bytes=row.max_total_bytes,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def _assert_device_owned(
    db: Session, account: Account, device_id: Optional[str]
) -> None:
    """Device-scoped policies must reference a device the caller owns."""
    if device_id is None:
        return
    dev = db.get(DeviceConfig, device_id.lower())
    if dev is None or dev.user_id != account.id:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Device {device_id!r} not found or not owned by this account",
        )


# ── Endpoints ───────────────────────────────────────────────────────────


@router.get("", response_model=PolicyList)
def list_policies(
    device_id: Optional[str] = Query(
        None,
        description="Filter to a single device's override. Omit to list all.",
    ),
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> PolicyList:
    stmt = select(SnapshotRetentionPolicy).where(
        SnapshotRetentionPolicy.account_id == account.id
    )
    if device_id is not None:
        stmt = stmt.where(SnapshotRetentionPolicy.device_id == device_id.lower())
    rows = db.scalars(
        stmt.order_by(SnapshotRetentionPolicy.device_id.nullsfirst())
    ).all()
    return PolicyList(items=[_row_to_model(r) for r in rows], total=len(rows))


@router.put("", response_model=PolicyRow)
def upsert_policy(
    body: PolicyUpsert,
    request: Request,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> PolicyRow:
    """Insert or update the policy for the given scope.

    ``(account_id, device_id=NULL)`` is the default bucket; everything
    else is a device-specific override. The scheduled retention runner
    picks device > account-default > global policy.
    """
    device_id = body.device_id.lower() if body.device_id else None
    _assert_device_owned(db, account, device_id)
    row = db.scalar(
        select(SnapshotRetentionPolicy).where(
            SnapshotRetentionPolicy.account_id == account.id,
            SnapshotRetentionPolicy.device_id.is_(device_id)
            if device_id is None
            else SnapshotRetentionPolicy.device_id == device_id,
        )
    )
    if row is None:
        row = SnapshotRetentionPolicy(
            account_id=account.id,
            device_id=device_id,
            keep_last_n_auto=body.keep_last_n_auto,
            auto_expire_days=body.auto_expire_days,
            keep_labeled_forever=body.keep_labeled_forever,
            max_total_bytes=body.max_total_bytes,
        )
        db.add(row)
    else:
        row.keep_last_n_auto = body.keep_last_n_auto
        row.auto_expire_days = body.auto_expire_days
        row.keep_labeled_forever = body.keep_labeled_forever
        row.max_total_bytes = body.max_total_bytes
    db.flush()
    audit.emit(
        db,
        actor=account,
        action="retention.policy_set",
        request=request,
        resource_type="retention_policy",
        resource_id=str(row.id),
        detail={
            "device_id": device_id,
            "keep_last_n_auto": body.keep_last_n_auto,
            "auto_expire_days": body.auto_expire_days,
            "keep_labeled_forever": body.keep_labeled_forever,
            "max_total_bytes": body.max_total_bytes,
        },
    )
    return _row_to_model(row)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: int,
    request: Request,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> None:
    row = db.get(SnapshotRetentionPolicy, policy_id)
    if row is None or row.account_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    audit.emit(
        db,
        actor=account,
        action="retention.policy_deleted",
        request=request,
        resource_type="retention_policy",
        resource_id=str(policy_id),
        detail={"device_id": row.device_id},
    )
    db.delete(row)


__all__ = ["router"]
