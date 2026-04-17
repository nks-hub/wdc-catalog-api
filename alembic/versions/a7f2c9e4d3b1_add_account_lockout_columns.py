"""Add failed_login_count + locked_until to accounts.

Revision ID: a7f2c9e4d3b1
Revises: 8a3d2c5f1e9b
Create Date: 2026-04-17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "a7f2c9e4d3b1"
down_revision: Union[str, Sequence[str], None] = "8a3d2c5f1e9b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("accounts") as batch_op:
        batch_op.add_column(
            sa.Column(
                "failed_login_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column("locked_until", sa.DateTime(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("accounts") as batch_op:
        batch_op.drop_column("locked_until")
        batch_op.drop_column("failed_login_count")
