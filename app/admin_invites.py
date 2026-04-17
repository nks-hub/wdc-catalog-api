"""Admin-issued signed invite tokens with pre-assigned role.

An admin (or owner) mints a signed invite carrying {email, role, exp}.
The invitee hits ``POST /api/v1/auth/accept-invite`` with the token +
chosen password; we verify the signature + expiry, create the Account,
honour the role restriction rules from ``admin_users.change_role``, and
return a fresh JWT.

We re-use the session signer (`app.auth._signer`) so there's only one
secret to rotate. Tokens are opaque URL-safe strings carrying the
base64-encoded payload separated by `.`.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .auth import _secret_key, hash_password
from .db import Account, get_session
from .devices import create_token
from .permissions import require_role
from .ratelimit import limiter
from .roles import Role

admin_router = APIRouter(prefix="/api/v1/admin/invites", tags=["admin:invites"])
public_router = APIRouter(prefix="/api/v1/auth", tags=["accounts", "devices"])

INVITE_SALT = "nks-wdc-invite-v1"
DEFAULT_INVITE_TTL_HOURS = 48


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_secret_key(), salt=INVITE_SALT)


# ── Schemas ─────────────────────────────────────────────────────────────

class CreateInviteRequest(BaseModel):
    email: str = Field(..., max_length=128)
    role: Role = Role.user
    ttl_hours: int = Field(DEFAULT_INVITE_TTL_HOURS, ge=1, le=168)


class CreateInviteResponse(BaseModel):
    token: str
    email: str
    role: str
    expires_at: str


class AcceptInviteRequest(BaseModel):
    token: str
    password: str = Field(..., min_length=8, max_length=128)


class AcceptInviteResponse(BaseModel):
    token: str
    email: str
    role: str


# ── Admin endpoints ─────────────────────────────────────────────────────

@admin_router.post("", response_model=CreateInviteResponse)
def create_invite(
    body: CreateInviteRequest,
    request: Request,
    caller: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
) -> CreateInviteResponse:
    """Mint a signed invite token. Only ``owner`` may invite another owner."""
    email = body.email.strip().lower()
    if not email or "@" not in email or len(email) < 5:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid email")
    if body.role == Role.owner and Role(caller.role) != Role.owner:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only owners can invite a new owner"
        )
    if db.scalar(select(Account).where(Account.email == email)):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An account with that email already exists"
        )

    expires = datetime.now(timezone.utc) + timedelta(hours=body.ttl_hours)
    payload = {
        "email": email,
        "role": body.role.value,
        "nonce": uuid.uuid4().hex,
    }
    token = _serializer().dumps(payload)

    audit.emit(
        db, actor=caller, action="invite.created", request=request,
        resource_type="invite", resource_id=email,
        detail={"role": body.role.value, "expires_at": expires.isoformat()},
    )

    return CreateInviteResponse(
        token=token,
        email=email,
        role=body.role.value,
        expires_at=expires.isoformat(),
    )


# ── Public accept endpoint ──────────────────────────────────────────────

@public_router.post("/accept-invite", response_model=AcceptInviteResponse)
@limiter.limit("10/hour")
def accept_invite(
    request: Request,
    body: AcceptInviteRequest,
    db: Session = Depends(get_session),
) -> AcceptInviteResponse:
    """Create an account from a valid invite token."""
    max_age = DEFAULT_INVITE_TTL_HOURS * 3600
    try:
        payload = _serializer().loads(body.token, max_age=max_age)
    except SignatureExpired:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invite has expired")
    except BadSignature:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invite is invalid")

    email = str(payload.get("email", "")).strip().lower()
    try:
        role = Role(payload.get("role", "user"))
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invite has unknown role")

    if db.scalar(select(Account).where(Account.email == email)):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Account already exists — log in instead"
        )

    account = Account(
        email=email,
        password_hash=hash_password(body.password),
        role=role.value,
    )
    db.add(account)
    db.flush()
    account.last_login_at = datetime.now(timezone.utc)
    audit.emit(
        db, actor=None, action="invite.accepted", request=request,
        resource_type="account", resource_id=account.id,
        detail={"email": email, "role": role.value},
    )
    token = create_token(account.id, email, token_version=account.token_version)
    return AcceptInviteResponse(token=token, email=email, role=role.value)


__all__ = ["admin_router", "public_router"]
