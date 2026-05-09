"""Add fief_user_webauthn_credentials table

Revision ID: 2b952240a094
Revises: 0929dd1d8a8c
Create Date: 2026-05-09 18:00:00.000000

Covers MFA-2 plan T3:
- New table ``fief_user_webauthn_credentials`` storing per-user WebAuthn
  / passkey credentials. One row per registered authenticator.

Schema notes:
- ``credential_id`` (BYTEA / LargeBinary) is the WebAuthn-side credential id;
  unique-indexed so assertion lookup is O(1).
- ``public_key`` is the COSE-encoded public key bytes returned by
  ``verify_registration_response``.
- ``sign_count`` is BIGINT to match WebAuthn's 32-bit unsigned counter
  comfortably (with headroom).
- ``transports`` is a comma-separated TEXT (e.g. ``"internal,hybrid"``)
  rather than ``text[]``. This is an intentional cross-dialect divergence
  from the PRD: comma-separated text works on SQLite (test) and Postgres
  (prod) without needing a Postgres-only array type. Service code parses
  to/from ``list[str]``.
- ``aaguid`` (UUID, nullable) lets us map authenticator identity to a
  friendly device name in a future commit.
- ``backup_eligible`` / ``backup_state`` track multi-device-credential
  state (Apple/Google synced passkeys).
- ``label`` is user-chosen, e.g. ``"MacBook"`` — nullable.
- ``attestation_obj`` keeps the raw attestation for forensics; nullable.
- ``last_used_at`` is bumped on every successful assertion verify.

All columns are either nullable or have server defaults so the table is
fully online-safe to add. The FK to ``fief_users(id)`` cascades on user
delete.
"""

import sqlalchemy as sa
from alembic import op

import fief

# revision identifiers, used by Alembic.
revision = "2b952240a094"
down_revision = "0929dd1d8a8c"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.create_table(
        f"{table_prefix}user_webauthn_credentials",
        sa.Column("user_id", fief.models.generics.GUID(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "sign_count",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("transports", sa.Text(), nullable=True),
        sa.Column("aaguid", fief.models.generics.GUID(), nullable=True),
        sa.Column(
            "backup_eligible",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "backup_state",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("label", sa.Text(), nullable=True),
        sa.Column("attestation_obj", sa.LargeBinary(), nullable=True),
        sa.Column(
            "last_used_at",
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
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f(f"ix_{table_prefix}user_webauthn_credentials_credential_id"),
        f"{table_prefix}user_webauthn_credentials",
        ["credential_id"],
        unique=True,
    )
    op.create_index(
        op.f(f"ix_{table_prefix}user_webauthn_credentials_user_id"),
        f"{table_prefix}user_webauthn_credentials",
        ["user_id"],
        unique=False,
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.drop_index(
        op.f(f"ix_{table_prefix}user_webauthn_credentials_user_id"),
        table_name=f"{table_prefix}user_webauthn_credentials",
    )
    op.drop_index(
        op.f(f"ix_{table_prefix}user_webauthn_credentials_credential_id"),
        table_name=f"{table_prefix}user_webauthn_credentials",
    )
    op.drop_table(f"{table_prefix}user_webauthn_credentials")
