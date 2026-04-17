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

from fastapi import Depends, HTTPException, status

from .db import Account
from .devices import get_current_account
from .roles import Role


def require_role(required: Role) -> Callable[..., Account]:
    """Return a FastAPI dependency that rejects accounts below *required*."""

    def _dep(account: Account = Depends(get_current_account)) -> Account:
        if account.suspended_at is not None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Account is suspended",
            )
        try:
            role = Role(account.role)
        except ValueError:
            # Unknown role in DB — default to the lowest tier for safety.
            role = Role.readonly
        if not role.implies(required):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Requires role {required.value} or higher",
            )
        return account

    return _dep


__all__ = ["require_role"]
