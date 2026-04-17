"""Add personal_access_tokens table.

Revision ID: b1d4e7c2f809
Revises: a7f2c9e4d3b1
Create Date: 2026-04-17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "b1d4e7c2f809"
down_revision: Union[str, Sequence[str], None] = "a7f2c9e4d3b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "personal_access_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("account_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("token_prefix", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_personal_access_tokens_account_id",
        "personal_access_tokens",
        ["account_id"],
    )
    op.create_index(
        "ix_personal_access_tokens_token_prefix",
        "personal_access_tokens",
        ["token_prefix"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_personal_access_tokens_token_prefix",
        table_name="personal_access_tokens",
    )
    op.drop_index(
        "ix_personal_access_tokens_account_id",
        table_name="personal_access_tokens",
    )
    op.drop_table("personal_access_tokens")
