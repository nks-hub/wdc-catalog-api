"""add token_version and revoked_tokens

Revision ID: 0e529e9dbeae
Revises: f84aaace640f
Create Date: 2026-04-17 17:16:52.640803

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0e529e9dbeae'
down_revision: Union[str, Sequence[str], None] = 'f84aaace640f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'revoked_tokens',
        sa.Column('jti', sa.String(length=64), nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=True),
        sa.Column('reason', sa.String(length=64), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('jti'),
    )
    op.create_index(
        op.f('ix_revoked_tokens_account_id'),
        'revoked_tokens',
        ['account_id'],
        unique=False,
    )
    with op.batch_alter_table('accounts') as batch_op:
        batch_op.add_column(
            sa.Column(
                'token_version', sa.Integer(), nullable=False, server_default='1'
            )
        )


def downgrade() -> None:
    with op.batch_alter_table('accounts') as batch_op:
        batch_op.drop_column('token_version')
    op.drop_index(op.f('ix_revoked_tokens_account_id'), table_name='revoked_tokens')
    op.drop_table('revoked_tokens')
