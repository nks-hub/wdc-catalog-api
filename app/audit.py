"""Audit-log helpers — single `emit()` entry point used by admin routes.

Call ``audit.emit(db, request, actor, action, resource_type, resource_id, detail)``
at the mutation site. The helper flushes so the event is durable even if
the surrounding transaction rolls back due to a later error; callers that
want strict "event iff success" semantics can instead call this at the
very end of the handler right before ``db.commit()``.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from .db import Account, AuditEvent


def emit(
    db: Session,
    *,
    actor: Optional[Account],
    action: str,
    request: Optional[Request] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
) -> AuditEvent:
    """Append an audit event row and return it (for tests + debugging)."""
    ip = None
    user_agent = None
    if request is not None:
        client = request.client
        ip = client.host if client else None
        user_agent = request.headers.get("user-agent")
    event = AuditEvent(
        actor_id=actor.id if actor else None,
        actor_email=actor.email if actor else None,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        detail=detail,
        ip=ip,
        user_agent=user_agent,
    )
    db.add(event)
    db.flush()
    return event


__all__ = ["emit"]
