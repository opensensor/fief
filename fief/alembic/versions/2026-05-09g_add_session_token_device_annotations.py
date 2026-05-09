"""Add device-annotation columns + user_id indexes to session/refresh tokens

Revision ID: 0929dd1d8a8c
Revises: 2efcfe2289f4
Create Date: 2026-05-09 17:00:00.000000

Covers UX-1 plan T3:
- Adds four nullable annotation columns to both ``fief_session_tokens`` and
  ``fief_refresh_tokens`` so we can power the "Active sessions & devices" tab:
    * ``created_ip``         TEXT NULL  -- IP captured at token creation
    * ``created_user_agent`` TEXT NULL  -- UA string captured at creation
    * ``last_seen_at``       TIMESTAMPTZ NULL -- bumped on each request use
    * ``last_seen_ip``       TEXT NULL  -- IP from the most recent use
- Adds an index on ``user_id`` for both tables. Today neither table has a
  ``user_id`` index (verified against ``2023-08-28_initial_migration.py``);
  the new ``list_by_user_id`` repository query introduced by T6/T7 would
  otherwise full-scan.

All columns are nullable with no server default, so existing rows are left
untouched and inserts can omit them. Plain ``op.add_column`` is safe online
on both Postgres and SQLite — no ``op.batch_alter_table`` required.
"""

import sqlalchemy as sa
from alembic import op

import fief

# revision identifiers, used by Alembic.
revision = "0929dd1d8a8c"
down_revision = "2efcfe2289f4"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    # fief_session_tokens — 4 device annotation columns
    op.add_column(
        f"{table_prefix}session_tokens",
        sa.Column("created_ip", sa.Text(), nullable=True),
    )
    op.add_column(
        f"{table_prefix}session_tokens",
        sa.Column("created_user_agent", sa.Text(), nullable=True),
    )
    op.add_column(
        f"{table_prefix}session_tokens",
        sa.Column(
            "last_seen_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        f"{table_prefix}session_tokens",
        sa.Column("last_seen_ip", sa.Text(), nullable=True),
    )

    # fief_refresh_tokens — same 4 columns
    op.add_column(
        f"{table_prefix}refresh_tokens",
        sa.Column("created_ip", sa.Text(), nullable=True),
    )
    op.add_column(
        f"{table_prefix}refresh_tokens",
        sa.Column("created_user_agent", sa.Text(), nullable=True),
    )
    op.add_column(
        f"{table_prefix}refresh_tokens",
        sa.Column(
            "last_seen_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        f"{table_prefix}refresh_tokens",
        sa.Column("last_seen_ip", sa.Text(), nullable=True),
    )

    # user_id indexes (currently missing on both tables)
    op.create_index(
        op.f(f"ix_{table_prefix}session_tokens_user_id"),
        f"{table_prefix}session_tokens",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f(f"ix_{table_prefix}refresh_tokens_user_id"),
        f"{table_prefix}refresh_tokens",
        ["user_id"],
        unique=False,
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    # Drop indexes first
    op.drop_index(
        op.f(f"ix_{table_prefix}refresh_tokens_user_id"),
        table_name=f"{table_prefix}refresh_tokens",
    )
    op.drop_index(
        op.f(f"ix_{table_prefix}session_tokens_user_id"),
        table_name=f"{table_prefix}session_tokens",
    )

    # Then drop all 8 columns in reverse order
    op.drop_column(f"{table_prefix}refresh_tokens", "last_seen_ip")
    op.drop_column(f"{table_prefix}refresh_tokens", "last_seen_at")
    op.drop_column(f"{table_prefix}refresh_tokens", "created_user_agent")
    op.drop_column(f"{table_prefix}refresh_tokens", "created_ip")

    op.drop_column(f"{table_prefix}session_tokens", "last_seen_ip")
    op.drop_column(f"{table_prefix}session_tokens", "last_seen_at")
    op.drop_column(f"{table_prefix}session_tokens", "created_user_agent")
    op.drop_column(f"{table_prefix}session_tokens", "created_ip")
