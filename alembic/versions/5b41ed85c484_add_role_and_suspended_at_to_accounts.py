"""add role and suspended_at to accounts

Revision ID: 5b41ed85c484
Revises: 621166bcba45
Create Date: 2026-04-17 17:04:53.260690
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '5b41ed85c484'
down_revision: Union[str, Sequence[str], None] = '621166bcba45'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add role + suspended_at to accounts.

    ``server_default='user'`` backfills existing rows so the NOT NULL
    constraint is safe. SQLite requires batch_alter_table to add a NOT
    NULL column via table rewrite.
    """
    with op.batch_alter_table('accounts') as batch_op:
        batch_op.add_column(
            sa.Column('role', sa.String(length=16), nullable=False, server_default='user')
        )
        batch_op.add_column(sa.Column('suspended_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('accounts') as batch_op:
        batch_op.drop_column('suspended_at')
        batch_op.drop_column('role')
