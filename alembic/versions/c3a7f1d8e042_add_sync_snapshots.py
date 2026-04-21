"""add sync_snapshots table

Revision ID: c3a7f1d8e042
Revises: 66b8514f2f37
Create Date: 2026-04-21 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "c3a7f1d8e042"
down_revision: Union[str, Sequence[str], None] = "66b8514f2f37"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sync_snapshots",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_id", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content_gzip", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_sync_snapshots_account_device_created",
        "sync_snapshots",
        ["account_id", "device_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_sync_snapshots_account_id"),
        "sync_snapshots",
        ["account_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_sync_snapshots_device_id"),
        "sync_snapshots",
        ["device_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_sync_snapshots_device_id", table_name="sync_snapshots")
    op.drop_index("ix_sync_snapshots_account_id", table_name="sync_snapshots")
    op.drop_index(
        "ix_sync_snapshots_account_device_created", table_name="sync_snapshots"
    )
    op.drop_table("sync_snapshots")
