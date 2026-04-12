"""Account registration, JWT auth, and device management endpoints.

Provides a user-scoped device management layer on top of the existing
config-sync store. Accounts authenticate via email+password → JWT.
Devices automatically link to the account on the first authenticated
sync push, so there's no explicit "register device" step.

JWT secrets default to a dev fallback — set NKS_WDC_CATALOG_SECRET in
production. Tokens expire after 30 days so Electron clients don't need
frequent re-auth.
"""

from __future__ import annotations

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import hash_password, verify_password
from .db import Account, DeviceConfig, get_session

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["accounts", "devices"])

JWT_SECRET = os.environ.get("NKS_WDC_CATALOG_SECRET", "dev-only-jwt-secret-change-in-prod")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 30

security = HTTPBearer(auto_error=False)


# ── Schemas ─────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    token: str
    email: str


class DeviceInfo(BaseModel):
    device_id: str
    name: str | None = None
    os: str | None = None
    arch: str | None = None
    site_count: int | None = None
    last_seen_at: str | None = None
    updated_at: str | None = None
    online: bool = False
    is_current: bool = False


class PushConfigRequest(BaseModel):
    source_device_id: str


# ── JWT helpers ─────────────────────────────────────────────────────────

def create_token(account_id: int, email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS)
    return jwt.encode(
        {"sub": str(account_id), "email": email, "exp": expire},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


# ── Dependencies ────────────────────────────────────────────────────────

def get_current_account(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)] = None,
    db: Session = Depends(get_session),
) -> Account:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        payload = decode_token(credentials.credentials)
        account_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}")
    account = db.get(Account, account_id)
    if account is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account not found")
    return account


def optional_account(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)] = None,
    db: Session = Depends(get_session),
) -> Account | None:
    if credentials is None:
        return None
    try:
        payload = decode_token(credentials.credentials)
        account_id = int(payload["sub"])
        return db.get(Account, account_id)
    except Exception:
        return None


# ── Auth endpoints ──────────────────────────────────────────────────────

@router.post("/auth/register", response_model=TokenResponse)
def register(body: RegisterRequest, db: Session = Depends(get_session)) -> TokenResponse:
    email = body.email.strip().lower()
    if not email or len(email) < 5:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid email")
    existing = db.scalar(select(Account).where(Account.email == email))
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    account = Account(
        email=email,
        password_hash=hash_password(body.password),
    )
    db.add(account)
    db.flush()
    token = create_token(account.id, email)
    return TokenResponse(token=token, email=email)


@router.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_session)) -> TokenResponse:
    email = body.email.strip().lower()
    account = db.scalar(select(Account).where(Account.email == email))
    if account is None or not verify_password(body.password, account.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    account.last_login_at = datetime.now(timezone.utc)
    token = create_token(account.id, email)
    return TokenResponse(token=token, email=email)


@router.get("/auth/me")
def auth_me(account: Account = Depends(get_current_account)) -> dict:
    return {
        "id": account.id,
        "email": account.email,
        "created_at": account.created_at.isoformat() if account.created_at else None,
    }


# ── Device endpoints ────────────────────────────────────────────────────

@router.get("/devices", response_model=list[DeviceInfo])
def list_devices(
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> list[DeviceInfo]:
    devices = db.scalars(
        select(DeviceConfig).where(DeviceConfig.user_id == account.id)
    ).all()
    # SQLite stores datetimes as naive (no tzinfo). Use naive UTC now so
    # the subtraction doesn't throw "can't subtract offset-naive and
    # offset-aware datetimes".
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return [
        DeviceInfo(
            device_id=d.device_id,
            name=d.name,
            os=d.os,
            arch=d.arch,
            site_count=d.site_count,
            last_seen_at=d.last_seen_at.isoformat() if d.last_seen_at else None,
            updated_at=d.updated_at.isoformat() if d.updated_at else None,
            online=d.last_seen_at is not None and (now - d.last_seen_at).total_seconds() < 300,
        )
        for d in devices
    ]


@router.put("/devices/{device_id}")
def update_device(
    device_id: str,
    name: str | None = None,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> dict:
    device = db.get(DeviceConfig, device_id)
    if device is None or device.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    if name is not None:
        device.name = name
    return {"ok": True, "device_id": device_id}


@router.delete("/devices/{device_id}")
def delete_device(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> dict:
    device = db.get(DeviceConfig, device_id)
    if device is None or device.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    db.delete(device)
    return {"ok": True, "removed": device_id}


@router.get("/devices/{device_id}/config")
def get_device_config(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> dict:
    device = db.get(DeviceConfig, device_id)
    if device is None or device.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    return {
        "device_id": device.device_id,
        "name": device.name,
        "payload": device.payload,
        "updated_at": device.updated_at.isoformat() if device.updated_at else None,
    }


@router.post("/devices/{device_id}/push-config")
def push_config_to_device(
    device_id: str,
    body: PushConfigRequest,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> dict:
    source = db.get(DeviceConfig, body.source_device_id)
    target = db.get(DeviceConfig, device_id)
    if source is None or source.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source device not found")
    if target is None or target.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target device not found")
    target.payload = source.payload
    target.updated_at = datetime.now(timezone.utc)
    return {"ok": True, "pushed_from": body.source_device_id, "pushed_to": device_id}
