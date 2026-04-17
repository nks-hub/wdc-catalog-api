"""Role-based access control — shared enum + helpers.

Roles (least → most privileged):

- ``readonly``  — account disabled; cannot log in, data preserved for audit.
- ``user``      — default for desktop-registered accounts; self-service own devices.
- ``support``   — read-only user data, may reset passwords; no catalog mutations.
- ``operator``  — catalog edits (releases, downloads, generators); may suspend users.
- ``admin``     — full management except role changes on ``owner``.
- ``owner``     — superuser; cannot be demoted; only one per instance.

``Role`` values are stored as strings in the DB so alembic migrations +
SQLite backfills stay predictable.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    readonly = "readonly"
    user = "user"
    support = "support"
    operator = "operator"
    admin = "admin"
    owner = "owner"

    @property
    def rank(self) -> int:
        """Numeric ordering for privilege comparisons (higher = more)."""
        return _ROLE_RANK[self]

    def implies(self, other: "Role") -> bool:
        """True if *self* is at least as privileged as *other*.

        ``owner.implies(admin)`` is True; ``user.implies(admin)`` is False.
        Use this over equality when gating features so new roles slot in
        cleanly.
        """
        return self.rank >= other.rank


_ROLE_RANK: dict[Role, int] = {
    Role.readonly: 0,
    Role.user: 10,
    Role.support: 20,
    Role.operator: 30,
    Role.admin: 40,
    Role.owner: 50,
}


__all__ = ["Role"]
