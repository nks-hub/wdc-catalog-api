"""Admin endpoints for reading/writing the global policy singleton."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import audit
from .db import Account, GlobalPolicy, get_session
from .permissions import require_role
from .roles import Role

router = APIRouter(prefix="/api/v1/admin/policy", tags=["admin:policy"])


class PolicyResponse(BaseModel):
    snapshot_keep_last_n: int
    snapshot_retain_days: int
    max_bytes_per_user: Optional[int]
    registration_enabled: bool
    default_role: str
    banner_message: Optional[str]
    updated_at: Optional[str]
    updated_by_email: Optional[str]


class PolicyUpdate(BaseModel):
    snapshot_keep_last_n: Optional[int] = Field(None, ge=1, le=1000)
    snapshot_retain_days: Optional[int] = Field(None, ge=1, le=3650)
    max_bytes_per_user: Optional[int] = Field(None, ge=0)
    registration_enabled: Optional[bool] = None
    default_role: Optional[Role] = None
    banner_message: Optional[str] = Field(None, max_length=512)


def _get_or_create(db: Session) -> GlobalPolicy:
    """Lazy-load (and insert if missing) the singleton row."""
    row = db.get(GlobalPolicy, 1)
    if row is None:
        row = GlobalPolicy(id=1)
        db.add(row)
        db.flush()
    return row


def _to_response(row: GlobalPolicy) -> PolicyResponse:
    return PolicyResponse(
        snapshot_keep_last_n=row.snapshot_keep_last_n,
        snapshot_retain_days=row.snapshot_retain_days,
        max_bytes_per_user=row.max_bytes_per_user,
        registration_enabled=row.registration_enabled,
        default_role=row.default_role,
        banner_message=row.banner_message,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        updated_by_email=row.updated_by_email,
    )


@router.get("", response_model=PolicyResponse)
def get_policy(
    _: Account = Depends(require_role(Role.support)),
    db: Session = Depends(get_session),
) -> PolicyResponse:
    return _to_response(_get_or_create(db))


@router.put("", response_model=PolicyResponse)
def update_policy(
    body: PolicyUpdate,
    request: Request,
    caller: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
) -> PolicyResponse:
    row = _get_or_create(db)
    changes: dict = {}
    updates = body.model_dump(exclude_unset=True)
    for field, value in updates.items():
        if field == "default_role" and value is not None:
            value = value.value if isinstance(value, Role) else value
        old = getattr(row, field)
        if old != value:
            setattr(row, field, value)
            changes[field] = {"from": old, "to": value}
    if changes:
        row.updated_by_email = caller.email
        db.flush()
        audit.emit(
            db, actor=caller, action="policy.updated", request=request,
            resource_type="global_policy", resource_id="1",
            detail={"changes": changes},
        )
    return _to_response(row)


__all__ = ["router"]
