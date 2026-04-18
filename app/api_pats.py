"""Personal Access Token management JSON endpoints.

Scoped to the authenticated caller. An admin revoking another user's
token goes through ``/api/v1/admin/users/{id}/revoke-tokens`` which
bumps ``Account.token_version`` (the JWT-level kill switch); PATs are
separate data and must be revoked per-row.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from . import audit, pats
from .db import Account, get_session
from .devices import get_current_account


router = APIRouter(prefix="/api/v1/auth/tokens", tags=["accounts", "auth"])


class TokenCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    ttl_days: int | None = Field(default=None, ge=1, le=365)
    read_only: bool = Field(default=False)
    ip_allowlist: list[str] | None = Field(default=None)

    @field_validator("ip_allowlist", mode="before")
    @classmethod
    def validate_cidrs(cls, v: object) -> object:
        import ipaddress

        if v is None:
            return v
        if not isinstance(v, list):
            raise ValueError("ip_allowlist must be a list of CIDR strings")
        for entry in v:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                raise ValueError(f"Invalid CIDR: {entry!r}")
        return v


class TokenCreateResponse(BaseModel):
    id: int
    name: str
    token: str  # plaintext — returned once, never again
    created_at: str
    expires_at: str | None


class TokenRow(BaseModel):
    id: int
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None
    revoked_at: str | None
    expires_at: str | None


class TokenList(BaseModel):
    items: list[TokenRow]


@router.post("", response_model=TokenCreateResponse, status_code=201)
def create_token(
    body: TokenCreateRequest,
    request: Request,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> TokenCreateResponse:
    expires_at = None
    if body.ttl_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.ttl_days)
    row, plaintext = pats.issue(
        db,
        account_id=account.id,
        name=body.name,
        expires_at=expires_at,
        read_only=body.read_only,
        ip_allowlist=body.ip_allowlist,
    )
    audit.emit(
        db,
        request=request,
        actor=account,
        action="pat.created",
        resource_type="pat",
        resource_id=str(row.id),
        detail={
            "name": row.name,
            "prefix": row.token_prefix,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "read_only": body.read_only,
            "ip_allowlist_count": len(body.ip_allowlist) if body.ip_allowlist else 0,
        },
    )
    return TokenCreateResponse(
        id=row.id,
        name=row.name,
        token=plaintext,
        created_at=row.created_at.isoformat() if row.created_at else "",
        expires_at=row.expires_at.isoformat() if row.expires_at else None,
    )


@router.get("", response_model=TokenList)
def list_tokens(
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> TokenList:
    rows = pats.list_for(db, account_id=account.id)
    return TokenList(
        items=[
            TokenRow(
                id=r.id,
                name=r.name,
                prefix=r.token_prefix,
                created_at=r.created_at.isoformat() if r.created_at else "",
                last_used_at=r.last_used_at.isoformat() if r.last_used_at else None,
                revoked_at=r.revoked_at.isoformat() if r.revoked_at else None,
                expires_at=r.expires_at.isoformat() if r.expires_at else None,
            )
            for r in rows
        ]
    )


@router.delete("/{token_id}", status_code=204)
def revoke_token(
    token_id: int,
    request: Request,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
):
    ok = pats.revoke(db, account_id=account.id, token_id=token_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    audit.emit(
        db,
        request=request,
        actor=account,
        action="pat.revoked",
        resource_type="pat",
        resource_id=str(token_id),
    )


__all__ = ["router"]
