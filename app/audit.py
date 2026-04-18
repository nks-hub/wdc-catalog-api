"""Audit-log helpers — single `emit()` entry point used by admin routes.

Call ``audit.emit(db, request, actor, action, resource_type, resource_id, detail)``
at the mutation site. The helper flushes so the event is durable even if
the surrounding transaction rolls back due to a later error; callers that
want strict "event iff success" semantics can instead call this at the
very end of the handler right before ``db.commit()``.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from .db import Account, AuditEvent

log = logging.getLogger(__name__)


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
        # Honour the same trusted-proxy logic as the rate limiter so the
        # audit record reflects the *real* client IP rather than the
        # reverse-proxy loopback address.
        from .ratelimit import client_ip

        ip = client_ip(request)
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

    payload = {
        "id": event.id,
        "created_at": event.created_at.isoformat() if event.created_at else None,
        "actor_id": event.actor_id,
        "actor_email": event.actor_email,
        "action": event.action,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "ip": event.ip,
        "detail": event.detail,
    }

    try:
        from . import event_bus

        event_bus.publish(payload)
    except Exception as exc:
        log.warning("event_bus publish failed: %s", exc)

    try:
        from . import webhooks as _webhooks

        _webhooks.fire(payload, db=db)
    except Exception as exc:
        log.warning("webhooks.fire failed: %s", exc)

    # Security-metric increment — separate from the webhook try/except so
    # neither path can break the other. Only actions on the curated
    # allowlist move the counter so cardinality stays bounded.
    try:
        from . import observability as _obs

        _obs.inc_security_event(action)
    except Exception as exc:
        log.warning("security metric increment failed: %s", exc)

    return event


__all__ = ["emit"]
