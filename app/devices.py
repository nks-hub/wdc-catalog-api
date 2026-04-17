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

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt import InvalidTokenError as JWTError
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import hash_password, verify_password
from .db import Account, DeviceConfig, RevokedToken, get_session
from .ratelimit import limiter

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["accounts", "devices"])

JWT_SECRET = os.environ.get("NKS_WDC_JWT_SECRET") or os.environ.get("NKS_WDC_CATALOG_SECRET", "")
if not JWT_SECRET:
    if os.environ.get("NKS_WDC_CATALOG_DEV") == "1":
        import secrets as _secrets
        JWT_SECRET = _secrets.token_urlsafe(32)
        log.warning("NKS_WDC_CATALOG_DEV=1 → ephemeral JWT secret (tokens invalid after restart)")
    else:
        raise RuntimeError(
            "NKS_WDC_JWT_SECRET (or legacy NKS_WDC_CATALOG_SECRET) must be set in production. "
            "Set NKS_WDC_CATALOG_DEV=1 for local development."
        )
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 30

security = HTTPBearer(auto_error=False)


# ── Schemas ─────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
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


class UpdateDeviceRequest(BaseModel):
    name: str | None = Field(None, max_length=128)


class DeviceList(BaseModel):
    items: list[DeviceInfo]
    total: int
    limit: int
    offset: int


class AuthMe(BaseModel):
    id: int
    email: str
    role: str
    created_at: str | None = None
    last_login_at: str | None = None


class SimpleOk(BaseModel):
    ok: bool
    device_id: str | None = None
    removed: str | None = None
    pushed_from: str | None = None
    pushed_to: str | None = None


# ── JWT helpers ─────────────────────────────────────────────────────────

def create_token(account_id: int, email: str, *, token_version: int = 1) -> str:
    """Mint a JWT with ``jti`` + account ``tv`` (token version).

    Individual tokens can be added to ``revoked_tokens`` via logout;
    bumping ``Account.token_version`` invalidates every outstanding
    token for the account in one shot — cheap bulk revocation without
    tracking each jti.
    """
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS)
    jti = __import__("uuid").uuid4().hex
    return jwt.encode(
        {
            "sub": str(account_id), "email": email,
            "exp": expire, "jti": jti, "tv": token_version,
        },
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
        jti = payload.get("jti")
    except (JWTError, KeyError, ValueError) as exc:
        log.info("JWT decode failed: %s", exc)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    if jti and db.get(RevokedToken, jti) is not None:
        log.info("JWT %s is revoked — rejecting", jti)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token has been revoked")
    account = db.get(Account, account_id)
    if account is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account not found")
    token_version = payload.get("tv", 1)
    if token_version != account.token_version:
        log.info("JWT tv=%s stale for account %s (current %s)",
                 token_version, account_id, account.token_version)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token has been revoked")
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
    except Exception as exc:  # noqa: BLE001
        # Log at debug so operators can grep for clients that send
        # invalid tokens to public endpoints — useful signal when
        # diagnosing misbehaving desktop clients or probing traffic.
        log.debug("optional_account rejected token: %s", exc)
        return None


# ── Auth endpoints ──────────────────────────────────────────────────────

@router.post("/auth/register", response_model=TokenResponse)
@limiter.limit("3/hour")
def register(
    request: Request, body: RegisterRequest, db: Session = Depends(get_session)
) -> TokenResponse:
    # EmailStr + min_length=8 already validated by Pydantic; we only
    # need to normalize casing here.
    email = body.email.strip().lower()
    existing = db.scalar(select(Account).where(Account.email == email))
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    account = Account(
        email=email,
        password_hash=hash_password(body.password),
    )
    db.add(account)
    db.flush()
    token = create_token(account.id, email, token_version=account.token_version)
    return TokenResponse(token=token, email=email)


@router.post("/auth/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(
    request: Request, body: LoginRequest, db: Session = Depends(get_session)
) -> TokenResponse:
    email = body.email.strip().lower()
    account = db.scalar(select(Account).where(Account.email == email))
    if account is None or not verify_password(body.password, account.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    if account.suspended_at is not None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is suspended")
    account.last_login_at = datetime.now(timezone.utc)
    token = create_token(account.id, email, token_version=account.token_version)
    return TokenResponse(token=token, email=email)


@router.post("/auth/logout")
def logout(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)] = None,
    db: Session = Depends(get_session),
) -> dict:
    """Revoke the presented token by adding its jti to the denylist."""
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        payload = decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    jti = payload.get("jti")
    if not jti:
        return {"ok": True, "revoked": False, "note": "Token predates jti support"}
    if db.get(RevokedToken, jti) is None:
        account_id = int(payload.get("sub") or 0) or None
        expires_at = None
        if "exp" in payload:
            expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        db.add(RevokedToken(
            jti=jti, account_id=account_id,
            reason="logout", expires_at=expires_at,
        ))
    return {"ok": True, "revoked": True, "jti": jti}


@router.get("/auth/me", response_model=AuthMe)
def auth_me(account: Account = Depends(get_current_account)) -> AuthMe:
    return AuthMe(
        id=account.id,
        email=account.email,
        role=account.role,
        created_at=account.created_at.isoformat() if account.created_at else None,
        last_login_at=account.last_login_at.isoformat()
            if account.last_login_at else None,
    )


# ── Device endpoints ────────────────────────────────────────────────────

@router.get("/devices", response_model=DeviceList)
def list_devices(
    current_device_id: str | None = None,
    offset: int = 0,
    limit: int = 50,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> DeviceList:
    """List all devices registered to the authenticated account.

    ``offset``/``limit`` apply cursor-style pagination (limit capped at
    200). ``current_device_id`` tags the caller's own row with
    ``is_current=true`` so the UI can highlight the local device.
    """
    from sqlalchemy import func
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    stmt = select(DeviceConfig).where(DeviceConfig.user_id == account.id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    devices = db.scalars(
        stmt.order_by(DeviceConfig.last_seen_at.desc().nullslast())
        .offset(offset).limit(limit)
    ).all()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    current = (current_device_id or "").strip().lower()
    items = [
        DeviceInfo(
            device_id=d.device_id,
            name=d.name,
            os=d.os,
            arch=d.arch,
            site_count=d.site_count,
            last_seen_at=d.last_seen_at.isoformat() if d.last_seen_at else None,
            updated_at=d.updated_at.isoformat() if d.updated_at else None,
            online=d.last_seen_at is not None and (now - d.last_seen_at).total_seconds() < 300,
            is_current=bool(current) and d.device_id == current,
        )
        for d in devices
    ]
    return DeviceList(items=items, total=total, limit=limit, offset=offset)


@router.put("/devices/{device_id}", response_model=SimpleOk)
def update_device(
    device_id: str,
    body: UpdateDeviceRequest,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> SimpleOk:
    """Update a device's user-visible name. Accepts a JSON body so the
    value is never logged through access logs or reverse-proxy caches
    (query parameters are indexed by most web servers)."""
    device = db.get(DeviceConfig, device_id)
    if device is None or device.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    if body.name is not None:
        device.name = body.name
    return SimpleOk(ok=True, device_id=device_id)


@router.delete("/devices/{device_id}", response_model=SimpleOk)
def delete_device(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> SimpleOk:
    device = db.get(DeviceConfig, device_id)
    if device is None or device.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    db.delete(device)
    return SimpleOk(ok=True, removed=device_id)


class DeviceConfigDetail(BaseModel):
    device_id: str
    name: str | None = None
    payload: dict
    updated_at: str | None = None


@router.get("/devices/{device_id}/config", response_model=DeviceConfigDetail)
def get_device_config(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> DeviceConfigDetail:
    device = db.get(DeviceConfig, device_id)
    if device is None or device.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    return DeviceConfigDetail(
        device_id=device.device_id,
        name=device.name,
        payload=device.payload or {},
        updated_at=device.updated_at.isoformat() if device.updated_at else None,
    )


@router.post("/devices/{device_id}/push-config", response_model=SimpleOk)
def push_config_to_device(
    device_id: str,
    body: PushConfigRequest,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> SimpleOk:
    source = db.get(DeviceConfig, body.source_device_id)
    target = db.get(DeviceConfig, device_id)
    if source is None or source.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source device not found")
    if target is None or target.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target device not found")
    target.payload = source.payload
    target.updated_at = datetime.now(timezone.utc)
    return SimpleOk(
        ok=True, pushed_from=body.source_device_id, pushed_to=device_id
    )
