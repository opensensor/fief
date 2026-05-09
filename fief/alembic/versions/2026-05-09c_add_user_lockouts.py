"""Add fief_user_lockouts table for SEC-1 account lockouts

Revision ID: b400430e70fc
Revises: a1b2c3d4e5f6
Create Date: 2026-05-09 14:00:00.000000

Covers SEC-1 plan T4:
- New table fief_user_lockouts that stores per-user failed login counter
  and the active lockout deadline. PK is user_id (one row per user) with
  ON DELETE CASCADE so deleting a user implicitly drops the lockout.
- Index on locked_until to support the auto-unlock sweep / debugging
  queries that filter active lockouts by deadline.

"""

import sqlalchemy as sa
from alembic import op

import fief

# revision identifiers, used by Alembic.
revision = "b400430e70fc"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.create_table(
        f"{table_prefix}user_lockouts",
        sa.Column("user_id", fief.models.generics.GUID(), nullable=False),
        sa.Column(
            "failed_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "locked_until",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{table_prefix}users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_index(
        op.f(f"ix_{table_prefix}user_lockouts_locked_until"),
        f"{table_prefix}user_lockouts",
        ["locked_until"],
        unique=False,
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.drop_index(
        op.f(f"ix_{table_prefix}user_lockouts_locked_until"),
        table_name=f"{table_prefix}user_lockouts",
    )
    op.drop_table(f"{table_prefix}user_lockouts")
