"""Role-based authorization dependencies for FastAPI routes.

Usage::

    from app.permissions import require_role
    from app.roles import Role

    @router.get("/admin/users", dependencies=[Depends(require_role(Role.admin))])
    def list_users(...): ...

``require_role(role)`` returns a dependency callable that resolves the
current account (via the existing JWT flow), then raises 403 unless the
account's role *implies* the required role. ``owner`` always passes.
"""

from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .db import Account, get_session
from .devices import get_current_account
from .roles import Role


def require_role(required: Role) -> Callable[..., Account]:
    """Return a FastAPI dependency that rejects accounts below *required*.

    On denial, emit an audit event (``permission.denied``) so operators
    can spot credential-stuffed or privilege-escalation attempts after
    the fact — the 403 alone leaves no trail.
    """

    def _dep(
        request: Request,
        account: Account = Depends(get_current_account),
        db: Session = Depends(get_session),
    ) -> Account:
        if account.suspended_at is not None:
            _emit_deny(db, account, request, "suspended", required)
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Account is suspended",
            )
        try:
            role = Role(account.role)
        except ValueError:
            role = Role.readonly
        if not role.implies(required):
            _emit_deny(db, account, request, role.value, required)
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Requires role {required.value} or higher",
            )
        return account

    return _dep


def _emit_deny(
    db: Session,
    account: Account,
    request: Request,
    actual: str,
    required: Role,
) -> None:
    """Best-effort audit log on RBAC denial. Failures don't block the
    403 — better to miss a row than to 500 on legitimate access checks."""
    try:
        from . import audit

        audit.emit(
            db,
            actor=account,
            action="permission.denied",
            request=request,
            resource_type="route",
            resource_id=request.url.path,
            detail={"required": required.value, "actual": actual},
        )
    except Exception:  # noqa: BLE001
        pass


__all__ = ["require_role"]
