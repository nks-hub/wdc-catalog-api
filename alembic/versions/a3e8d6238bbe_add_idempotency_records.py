"""add idempotency_records

Revision ID: a3e8d6238bbe
Revises: 66b8514f2f37
Create Date: 2026-04-17 18:18:53.581507
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a3e8d6238bbe'
down_revision: Union[str, Sequence[str], None] = '66b8514f2f37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create idempotency_records for the replay cache.

    The spurious ``alter_column`` ops that autogenerate emitted for
    ``device_snapshots.id`` / ``snapshot_exports.id`` were a false
    positive from the ``BigInteger().with_variant(Integer, "sqlite")``
    rework in a prior revision — on SQLite it's a no-op and on Postgres
    the underlying DDL stays BIGINT. They are stripped here.
    """
    op.create_table(
        'idempotency_records',
        sa.Column('key_hash', sa.String(length=64), nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=True),
        sa.Column('method', sa.String(length=8), nullable=False),
        sa.Column('path', sa.String(length=256), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('response_body', sa.LargeBinary(), nullable=False),
        sa.Column('content_type', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('key_hash'),
    )
    op.create_index(
        op.f('ix_idempotency_records_account_id'),
        'idempotency_records', ['account_id'], unique=False,
    )
    op.create_index(
        op.f('ix_idempotency_records_expires_at'),
        'idempotency_records', ['expires_at'], unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f('ix_idempotency_records_expires_at'),
        table_name='idempotency_records',
    )
    op.drop_index(
        op.f('ix_idempotency_records_account_id'),
        table_name='idempotency_records',
    )
    op.drop_table('idempotency_records')
