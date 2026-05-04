"""Merge personal access token and sync snapshot migration heads.

Revision ID: 4f7c1d2a9b30
Revises: b1d4e7c2f809, c3a7f1d8e042
Create Date: 2026-05-04 03:25:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union


# revision identifiers, used by Alembic.
revision: str = "4f7c1d2a9b30"
down_revision: Union[str, Sequence[str], None] = (
    "b1d4e7c2f809",
    "c3a7f1d8e042",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """No-op merge revision."""


def downgrade() -> None:
    """No-op merge revision."""
