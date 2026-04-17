"""Admin endpoint for triggering a retention pass on-demand."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import audit, retention
from .db import Account, get_session
from .permissions import require_role
from .roles import Role

router = APIRouter(prefix="/api/v1/admin/retention", tags=["admin:retention"])


class RunNowResponse(BaseModel):
    accounts: int
    deleted: int
    idempotency_purged: int = 0
    revoked_tokens_purged: int = 0


@router.post("/run-now", response_model=RunNowResponse)
def run_now(
    request: Request,
    caller: Account = Depends(require_role(Role.admin)),
    db: Session = Depends(get_session),
) -> RunNowResponse:
    """Trigger a retention pass immediately. Uses the caller's session so
    deletions participate in the outer transaction; the scheduler job
    opens its own session."""
    summary = retention.run_retention(db=db)
    audit.emit(
        db, actor=caller, action="retention.manual_run", request=request,
        resource_type="retention", resource_id="global",
        detail=summary,
    )
    return RunNowResponse(**summary)


__all__ = ["router"]
