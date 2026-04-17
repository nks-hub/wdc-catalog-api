"""Admin audit-log viewer endpoint."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Account, AuditEvent, get_session
from .permissions import require_role
from .roles import Role

router = APIRouter(prefix="/api/v1/admin/audit", tags=["admin:audit"])


class AuditEventRow(BaseModel):
    id: int
    actor_id: Optional[int]
    actor_email: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    detail: Optional[dict]
    ip: Optional[str]
    user_agent: Optional[str]
    created_at: Optional[str]


class AuditEventList(BaseModel):
    items: list[AuditEventRow]
    total: int


@router.get("", response_model=AuditEventList)
def list_events(
    _: Account = Depends(require_role(Role.support)),
    db: Session = Depends(get_session),
    actor_id: Optional[int] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    offset: int = 0,
    limit: int = Query(50, ge=1, le=500),
) -> AuditEventList:
    """Paginated, filterable audit log view. Support role or higher."""
    stmt = select(AuditEvent)
    if actor_id is not None:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == str(resource_id))

    from .db import count_query

    total = count_query(db, stmt)

    rows = db.scalars(
        stmt.order_by(AuditEvent.created_at.desc()).offset(max(0, offset)).limit(limit)
    ).all()

    return AuditEventList(
        items=[
            AuditEventRow(
                id=r.id,
                actor_id=r.actor_id,
                actor_email=r.actor_email,
                action=r.action,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                detail=r.detail,
                ip=r.ip,
                user_agent=r.user_agent,
                created_at=r.created_at.isoformat() if r.created_at else None,
            )
            for r in rows
        ],
        total=total,
    )


__all__ = ["router"]
