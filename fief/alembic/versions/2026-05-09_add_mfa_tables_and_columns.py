"""Add MFA tables (totp_secrets, mfa_recovery_codes) and supporting columns

Revision ID: 331683efd325
Revises: f3b1c2d4a5e6
Create Date: 2026-05-09 12:00:00.000000

Covers MFA-1 plan T5:
- New table fief_user_totp_secrets
- New table fief_user_mfa_recovery_codes
- fief_users.mfa_enabled
- fief_tenants.mfa_required
- fief_login_sessions: mfa_pending_user_id, mfa_attempts_count,
  mfa_locked_until
"""

import sqlalchemy as sa
from alembic import op

import fief

# revision identifiers, used by Alembic.
revision = "331683efd325"
down_revision = "f3b1c2d4a5e6"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    # ------------------------------------------------------------------
    # 1) fief_user_totp_secrets
    # ------------------------------------------------------------------
    op.create_table(
        f"{table_prefix}user_totp_secrets",
        sa.Column("user_id", fief.models.generics.GUID(), nullable=False),
        sa.Column("secret_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column(
            "confirmed_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            nullable=True,
        ),
        sa.Column("last_used_step", sa.BigInteger(), nullable=True),
        sa.Column("id", fief.models.generics.GUID(), nullable=False),
        sa.Column(
            "created_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{table_prefix}users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )
    op.create_index(
        op.f(f"ix_{table_prefix}user_totp_secrets_created_at"),
        f"{table_prefix}user_totp_secrets",
        ["created_at"],
        unique=False,
    )

    # ------------------------------------------------------------------
    # 2) fief_user_mfa_recovery_codes
    # ------------------------------------------------------------------
    op.create_table(
        f"{table_prefix}user_mfa_recovery_codes",
        sa.Column("user_id", fief.models.generics.GUID(), nullable=False),
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column(
            "used_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            nullable=True,
        ),
        sa.Column("id", fief.models.generics.GUID(), nullable=False),
        sa.Column(
            "created_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{table_prefix}users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f(f"ix_{table_prefix}user_mfa_recovery_codes_user_id_used_at"),
        f"{table_prefix}user_mfa_recovery_codes",
        ["user_id", "used_at"],
        unique=False,
    )
    op.create_index(
        op.f(f"ix_{table_prefix}user_mfa_recovery_codes_created_at"),
        f"{table_prefix}user_mfa_recovery_codes",
        ["created_at"],
        unique=False,
    )

    # ------------------------------------------------------------------
    # 3) fief_users.mfa_enabled
    # ------------------------------------------------------------------
    op.add_column(
        f"{table_prefix}users",
        sa.Column(
            "mfa_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    # ------------------------------------------------------------------
    # 4) fief_tenants.mfa_required
    # ------------------------------------------------------------------
    op.add_column(
        f"{table_prefix}tenants",
        sa.Column(
            "mfa_required",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    # ------------------------------------------------------------------
    # 5) fief_login_sessions MFA carry-state columns
    # ------------------------------------------------------------------
    op.add_column(
        f"{table_prefix}login_sessions",
        sa.Column("mfa_pending_user_id", fief.models.generics.GUID(), nullable=True),
    )
    op.add_column(
        f"{table_prefix}login_sessions",
        sa.Column(
            "mfa_attempts_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        f"{table_prefix}login_sessions",
        sa.Column(
            "mfa_locked_until",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            nullable=True,
        ),
    )

    # FK from login_sessions.mfa_pending_user_id -> users.id.
    # SQLite cannot ALTER TABLE ADD CONSTRAINT, so use batch mode there.
    fk_name = f"fk_{table_prefix}login_sessions_mfa_pending_user_id_users"
    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        with op.batch_alter_table(
            f"{table_prefix}login_sessions"
        ) as batch_op:
            batch_op.create_foreign_key(
                fk_name,
                f"{table_prefix}users",
                ["mfa_pending_user_id"],
                ["id"],
                ondelete="SET NULL",
            )
    else:
        op.create_foreign_key(
            fk_name,
            f"{table_prefix}login_sessions",
            f"{table_prefix}users",
            ["mfa_pending_user_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    # Reverse order: drop FK + login_sessions cols, tenants col, users col,
    # then recovery codes table, totp secrets table.
    fk_name = f"fk_{table_prefix}login_sessions_mfa_pending_user_id_users"
    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        with op.batch_alter_table(
            f"{table_prefix}login_sessions"
        ) as batch_op:
            batch_op.drop_constraint(fk_name, type_="foreignkey")
    else:
        op.drop_constraint(
            fk_name,
            f"{table_prefix}login_sessions",
            type_="foreignkey",
        )

    op.drop_column(f"{table_prefix}login_sessions", "mfa_locked_until")
    op.drop_column(f"{table_prefix}login_sessions", "mfa_attempts_count")
    op.drop_column(f"{table_prefix}login_sessions", "mfa_pending_user_id")

    op.drop_column(f"{table_prefix}tenants", "mfa_required")
    op.drop_column(f"{table_prefix}users", "mfa_enabled")

    op.drop_index(
        op.f(f"ix_{table_prefix}user_mfa_recovery_codes_created_at"),
        table_name=f"{table_prefix}user_mfa_recovery_codes",
    )
    op.drop_index(
        op.f(f"ix_{table_prefix}user_mfa_recovery_codes_user_id_used_at"),
        table_name=f"{table_prefix}user_mfa_recovery_codes",
    )
    op.drop_table(f"{table_prefix}user_mfa_recovery_codes")

    op.drop_index(
        op.f(f"ix_{table_prefix}user_totp_secrets_created_at"),
        table_name=f"{table_prefix}user_totp_secrets",
    )
    op.drop_table(f"{table_prefix}user_totp_secrets")
