"""JSON admin endpoints for managing accounts.

The existing admin UI (``/admin/*`` in main.py) uses server-rendered
Jinja templates; this module adds a JSON API on ``/api/v1/admin/users``
so the Electron client's admin panel can consume the same data, and so
operators can script common tasks.

HTML pages that share the same data will be added in a later step.
"""

from __future__ import annotations

import secrets as _secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from ._cache import invalidate_stats
from .auth import hash_password
from .db import Account, DeviceConfig, RevokedToken, get_session
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
    role: Role = Field(
        ..., description="New role. Only `owner` may assign/remove `owner`."
    )


class SessionSummary(BaseModel):
    email: str
    token_version: int
    revoked_tokens_active: int
    devices_linked: int
    last_login_at: Optional[str]
    suspended: bool


class RevokedTokenRow(BaseModel):
    jti: str
    reason: Optional[str]
    revoked_at: Optional[str]
    expires_at: Optional[str]


class SessionDetail(SessionSummary):
    revoked_tokens: list[RevokedTokenRow]


class ResetPasswordResponse(BaseModel):
    email: str
    temp_password: str = Field(
        ..., description="One-time password — show once, never again."
    )


# ── Helpers ─────────────────────────────────────────────────────────────


def _row(account: Account, device_count: int) -> AdminUserRow:
    return AdminUserRow(
        id=account.id,
        email=account.email,
        role=account.role,
        suspended=account.suspended_at is not None,
        created_at=account.created_at.isoformat() if account.created_at else None,
        last_login_at=account.last_login_at.isoformat()
        if account.last_login_at
        else None,
        device_count=device_count,
    )


def _target_or_404(db: Session, user_id: int) -> Account:
    target = db.get(Account, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    return target


def _revoke_all_for(db: Session, account_id: int, *, reason: str) -> int:
    """Bump the account's ``token_version`` so every outstanding JWT
    (which carries the old ``tv``) fails authentication on next use.

    Returns 1 when the column was bumped, 0 when the account is gone.
    The reason is recorded separately via ``audit.emit`` by the caller.
    """
    target = db.get(Account, account_id)
    if target is None:
        return 0
    target.token_version += 1
    _ = reason  # reserved for future fine-grained tracking
    return 1


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
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only owners can assign owner role"
        )
    if target_role == Role.owner and caller_role != Role.owner:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only owners can modify an owner"
        )
    if target_role == Role.owner and new_role != Role.owner:
        remaining = (
            db.scalar(
                select(func.count(Account.id)).where(Account.role == Role.owner.value)
            )
            or 0
        )
        if remaining <= 1:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Cannot demote the last owner",
            )

    old_role = target.role
    target.role = new_role.value
    db.flush()
    invalidate_stats()
    audit.emit(
        db,
        actor=caller,
        action="user.role_changed",
        request=request,
        resource_type="account",
        resource_id=target.id,
        detail={"from": old_role, "to": new_role.value, "target_email": target.email},
    )
    device_count = (
        db.scalar(
            select(func.count(DeviceConfig.device_id)).where(
                DeviceConfig.user_id == user_id
            )
        )
        or 0
    )
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
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Cannot suspend an owner account"
        )
    target.suspended_at = datetime.now(timezone.utc)
    # Revoke every outstanding token for the suspended account so the
    # session can't limp along until the next natural expiry.
    _revoke_all_for(db, target.id, reason="suspend")
    db.flush()
    invalidate_stats()
    audit.emit(
        db,
        actor=caller,
        action="user.suspended",
        request=request,
        resource_type="account",
        resource_id=target.id,
        detail={"target_email": target.email},
    )
    device_count = (
        db.scalar(
            select(func.count(DeviceConfig.device_id)).where(
                DeviceConfig.user_id == user_id
            )
        )
        or 0
    )
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
    invalidate_stats()
    audit.emit(
        db,
        actor=caller,
        action="user.resumed",
        request=request,
        resource_type="account",
        resource_id=target.id,
        detail={"target_email": target.email},
    )
    device_count = (
        db.scalar(
            select(func.count(DeviceConfig.device_id)).where(
                DeviceConfig.user_id == user_id
            )
        )
        or 0
    )
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
    # Password reset must invalidate every JWT the old password issued.
    _revoke_all_for(db, target.id, reason="password-reset")
    db.flush()
    audit.emit(
        db,
        actor=caller,
        action="user.password_reset",
        request=request,
        resource_type="account",
        resource_id=target.id,
        detail={"target_email": target.email},
    )
    return ResetPasswordResponse(email=target.email, temp_password=temp)


@router.get("/{user_id}/sessions", response_model=SessionDetail)
def list_sessions(
    user_id: int,
    _: Account = Depends(require_role(Role.support)),
    db: Session = Depends(get_session),
) -> SessionDetail:
    """Snapshot of a user's session + token state for ops triage.

    Support role or higher can read this view; it's read-only and never
    exposes password hashes or raw tokens."""
    target = _target_or_404(db, user_id)
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    revoked_rows = db.scalars(
        select(RevokedToken)
        .where(RevokedToken.account_id == user_id)
        .order_by(RevokedToken.revoked_at.desc())
    ).all()
    active = [r for r in revoked_rows if r.expires_at is None or r.expires_at > now]
    device_count = (
        db.scalar(
            select(func.count(DeviceConfig.device_id)).where(
                DeviceConfig.user_id == user_id
            )
        )
        or 0
    )
    return SessionDetail(
        email=target.email,
        token_version=target.token_version,
        revoked_tokens_active=len(active),
        devices_linked=device_count,
        last_login_at=target.last_login_at.isoformat()
        if target.last_login_at
        else None,
        suspended=target.suspended_at is not None,
        revoked_tokens=[
            RevokedTokenRow(
                jti=r.jti,
                reason=r.reason,
                revoked_at=r.revoked_at.isoformat() if r.revoked_at else None,
                expires_at=r.expires_at.isoformat() if r.expires_at else None,
            )
            for r in revoked_rows
        ],
    )


@router.post("/{user_id}/revoke-tokens", response_model=AdminUserRow)
def revoke_user_tokens(
    user_id: int,
    request: Request,
    caller: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
) -> AdminUserRow:
    """Invalidate every JWT previously issued to this account by bumping
    the account's ``token_version``. The user must re-login."""
    target = _target_or_404(db, user_id)
    if Role(target.role) == Role.owner and Role(caller.role) != Role.owner:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only owners can revoke an owner's tokens"
        )
    _revoke_all_for(db, target.id, reason="admin-revoke")
    db.flush()
    audit.emit(
        db,
        actor=caller,
        action="user.tokens_revoked",
        request=request,
        resource_type="account",
        resource_id=target.id,
        detail={
            "target_email": target.email,
            "new_token_version": target.token_version,
        },
    )
    device_count = (
        db.scalar(
            select(func.count(DeviceConfig.device_id)).where(
                DeviceConfig.user_id == user_id
            )
        )
        or 0
    )
    return _row(target, device_count)


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
        db,
        actor=caller,
        action="user.deleted",
        request=request,
        resource_type="account",
        resource_id=target.id,
        detail={"target_email": target.email},
    )
    db.delete(target)
    invalidate_stats()


__all__ = ["router"]
