"""Add idempotency body_hash column and consumed_invites table.

Revision ID: 7c9f1e8a4b21
Revises: a3e8d6238bbe
Create Date: 2026-04-17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "7c9f1e8a4b21"
down_revision: Union[str, Sequence[str], None] = "a3e8d6238bbe"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("idempotency_records") as batch_op:
        batch_op.add_column(sa.Column("body_hash", sa.String(length=64), nullable=True))

    op.create_table(
        "consumed_invites",
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=128), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=False),
        sa.Column("account_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("nonce"),
    )
    op.create_index(
        "ix_consumed_invites_email",
        "consumed_invites",
        ["email"],
    )


def downgrade() -> None:
    op.drop_index("ix_consumed_invites_email", table_name="consumed_invites")
    op.drop_table("consumed_invites")
    with op.batch_alter_table("idempotency_records") as batch_op:
        batch_op.drop_column("body_hash")
