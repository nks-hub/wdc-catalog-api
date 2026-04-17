"""JSON admin endpoints for managing accounts.

The existing admin UI (``/admin/*`` in main.py) uses server-rendered
Jinja templates; this module adds a JSON API on ``/api/v1/admin/users``
so the Electron client's admin panel can consume the same data, and so
operators can script common tasks.

HTML pages that share the same data will be added in a later step.
"""

from __future__ import annotations

import secrets as _secrets
import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from .auth import hash_password
from .db import Account, DeviceConfig, get_session
from .permissions import require_role
from .roles import Role

router = APIRouter(prefix="/api/v1/admin/users", tags=["admin:users"])


# ── Response models ────────────────────────────────────────────────────

class AdminUserRow(BaseModel):
    id: int
    email: str
    role: str
    suspended: bool
    created_at: Optional[str]
    last_login_at: Optional[str]
    device_count: int


class AdminUserDetail(AdminUserRow):
    devices: list[dict]


class AdminUserList(BaseModel):
    items: list[AdminUserRow]
    total: int


class ChangeRoleRequest(BaseModel):
    role: Role = Field(..., description="New role. Only `owner` may assign/remove `owner`.")


class ResetPasswordResponse(BaseModel):
    email: str
    temp_password: str = Field(..., description="One-time password — show once, never again.")


# ── Helpers ─────────────────────────────────────────────────────────────

def _row(account: Account, device_count: int) -> AdminUserRow:
    return AdminUserRow(
        id=account.id,
        email=account.email,
        role=account.role,
        suspended=account.suspended_at is not None,
        created_at=account.created_at.isoformat() if account.created_at else None,
        last_login_at=account.last_login_at.isoformat() if account.last_login_at else None,
        device_count=device_count,
    )


def _target_or_404(db: Session, user_id: int) -> Account:
    target = db.get(Account, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    return target


# ── Endpoints ───────────────────────────────────────────────────────────

@router.get("", response_model=AdminUserList)
def list_users(
    _: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
    offset: int = 0,
    limit: int = 50,
) -> AdminUserList:
    """List all accounts with device counts. Admins and above."""
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    total = db.scalar(select(func.count(Account.id))) or 0
    accounts = db.scalars(
        select(Account).order_by(Account.created_at.desc()).offset(offset).limit(limit)
    ).all()
    if not accounts:
        return AdminUserList(items=[], total=total)
    device_counts = dict(
        db.execute(
            select(DeviceConfig.user_id, func.count(DeviceConfig.device_id))
            .where(DeviceConfig.user_id.in_([a.id for a in accounts]))
            .group_by(DeviceConfig.user_id)
        ).all()
    )
    return AdminUserList(
        items=[_row(a, device_counts.get(a.id, 0)) for a in accounts],
        total=total,
    )


@router.get("/{user_id}", response_model=AdminUserDetail)
def get_user(
    user_id: int,
    _: Account = Depends(require_role(Role.support)),
    db: Session = Depends(get_session),
) -> AdminUserDetail:
    """Detailed view — support role may read for helpdesk scenarios."""
    target = _target_or_404(db, user_id)
    devices = db.scalars(
        select(DeviceConfig).where(DeviceConfig.user_id == user_id)
    ).all()
    device_rows = [
        {
            "device_id": d.device_id,
            "name": d.name,
            "os": d.os,
            "arch": d.arch,
            "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
            "site_count": d.site_count,
        }
        for d in devices
    ]
    base = _row(target, len(devices)).model_dump()
    return AdminUserDetail(**base, devices=device_rows)


@router.post("/{user_id}/role", response_model=AdminUserRow)
def change_role(
    user_id: int,
    body: ChangeRoleRequest,
    request: Request,
    caller: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
) -> AdminUserRow:
    """Change a user's role.

    - Anyone below admin has been rejected before reaching this handler.
    - Non-owner admins may not assign ``owner`` nor demote an ``owner``.
    - The last ``owner`` in the system cannot be demoted (would orphan
      the recovery path).
    """
    target = _target_or_404(db, user_id)
    caller_role = Role(caller.role)
    target_role = Role(target.role)
    new_role = body.role

    if new_role == Role.owner and caller_role != Role.owner:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only owners can assign owner role")
    if target_role == Role.owner and caller_role != Role.owner:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only owners can modify an owner")
    if target_role == Role.owner and new_role != Role.owner:
        remaining = db.scalar(
            select(func.count(Account.id)).where(Account.role == Role.owner.value)
        ) or 0
        if remaining <= 1:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Cannot demote the last owner",
            )

    old_role = target.role
    target.role = new_role.value
    db.flush()
    audit.emit(
        db, actor=caller, action="user.role_changed", request=request,
        resource_type="account", resource_id=target.id,
        detail={"from": old_role, "to": new_role.value, "target_email": target.email},
    )
    device_count = db.scalar(
        select(func.count(DeviceConfig.device_id)).where(DeviceConfig.user_id == user_id)
    ) or 0
    return _row(target, device_count)


@router.post("/{user_id}/suspend", response_model=AdminUserRow)
def suspend_user(
    user_id: int,
    request: Request,
    caller: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
) -> AdminUserRow:
    target = _target_or_404(db, user_id)
    if Role(target.role) == Role.owner:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot suspend an owner account")
    target.suspended_at = datetime.now(timezone.utc)
    db.flush()
    audit.emit(
        db, actor=caller, action="user.suspended", request=request,
        resource_type="account", resource_id=target.id,
        detail={"target_email": target.email},
    )
    device_count = db.scalar(
        select(func.count(DeviceConfig.device_id)).where(DeviceConfig.user_id == user_id)
    ) or 0
    return _row(target, device_count)


@router.post("/{user_id}/resume", response_model=AdminUserRow)
def resume_user(
    user_id: int,
    request: Request,
    caller: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
) -> AdminUserRow:
    target = _target_or_404(db, user_id)
    target.suspended_at = None
    db.flush()
    audit.emit(
        db, actor=caller, action="user.resumed", request=request,
        resource_type="account", resource_id=target.id,
        detail={"target_email": target.email},
    )
    device_count = db.scalar(
        select(func.count(DeviceConfig.device_id)).where(DeviceConfig.user_id == user_id)
    ) or 0
    return _row(target, device_count)


@router.post("/{user_id}/reset-password", response_model=ResetPasswordResponse)
def reset_password(
    user_id: int,
    request: Request,
    caller: Account = Depends(require_role(Role.support)),
    db: Session = Depends(get_session),
) -> ResetPasswordResponse:
    """Generate a one-time 16-char password, bcrypt-hash it, return in
    plaintext so the operator can relay it via an out-of-band channel."""
    target = _target_or_404(db, user_id)
    if Role(target.role) == Role.owner and Role(caller.role) != Role.owner:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only owners can reset an owner's password"
        )
    temp = _secrets.token_urlsafe(12)
    target.password_hash = hash_password(temp)
    db.flush()
    audit.emit(
        db, actor=caller, action="user.password_reset", request=request,
        resource_type="account", resource_id=target.id,
        detail={"target_email": target.email},
    )
    return ResetPasswordResponse(email=target.email, temp_password=temp)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    request: Request,
    caller: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
) -> None:
    """GDPR-style hard delete. Owner accounts are protected."""
    target = _target_or_404(db, user_id)
    if Role(target.role) == Role.owner:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot delete an owner account")
    if target.id == caller.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot delete your own account")
    audit.emit(
        db, actor=caller, action="user.deleted", request=request,
        resource_type="account", resource_id=target.id,
        detail={"target_email": target.email},
    )
    db.delete(target)


__all__ = ["router"]
