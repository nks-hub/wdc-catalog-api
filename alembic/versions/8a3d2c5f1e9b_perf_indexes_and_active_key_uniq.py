"""Add perf indexes + unique partial index on active encryption key.

Revision ID: 8a3d2c5f1e9b
Revises: 7c9f1e8a4b21
Create Date: 2026-04-17
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "8a3d2c5f1e9b"
down_revision: Union[str, Sequence[str], None] = "7c9f1e8a4b21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Hot sort key on the device list screen.
    op.create_index(
        "ix_device_configs_last_seen_at",
        "device_configs",
        ["last_seen_at"],
    )
    # Retention sweep filter.
    op.create_index(
        "ix_revoked_tokens_expires_at",
        "revoked_tokens",
        ["expires_at"],
    )
    # At most one ACTIVE encryption key per (account, kek_source). Closes
    # the two-writers-create-duplicate-DEKs race documented in M3.
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            "CREATE UNIQUE INDEX ux_active_key_per_account "
            "ON account_encryption_keys (account_id, kek_source) "
            "WHERE retired_at IS NULL"
        )
    elif dialect == "sqlite":
        op.execute(
            "CREATE UNIQUE INDEX ux_active_key_per_account "
            "ON account_encryption_keys (account_id, kek_source) "
            "WHERE retired_at IS NULL"
        )
    else:
        # Other engines: skip the partial index — the application-side
        # retry on IntegrityError still works, just without DB-level
        # enforcement. Operators on MySQL etc. can add a manual trigger
        # if strict enforcement is required.
        pass


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect in ("postgresql", "sqlite"):
        op.execute("DROP INDEX IF EXISTS ux_active_key_per_account")
    op.drop_index("ix_revoked_tokens_expires_at", table_name="revoked_tokens")
    op.drop_index("ix_device_configs_last_seen_at", table_name="device_configs")
