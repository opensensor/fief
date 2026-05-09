"""Add fief_clients.branding_signing_key for signed branding_origin verification

Revision ID: 7c92e1a4d8b1
Revises: b400430e70fc
Create Date: 2026-05-09 15:00:00.000000

Covers fief-app-plan T46:
- New nullable column ``branding_signing_key`` on ``fief_clients`` that holds
  the per-OIDC-client HMAC-SHA256 secret used to verify signed
  ``branding_origin`` query parameters supplied to ``GET /authorize``.
- 128 chars leaves headroom for future key formats. Saleor app's T15 / T17
  populates the key at OIDC-client provisioning time via the admin API.
- Nullable so existing first-party / dashboard / SDK clients (which do not
  use signed branding) keep working unchanged: a NULL key means
  "branding_origin disabled for this client" and any param is silently
  ignored. See ``fief/services/branding/origin_verifier.py``.

No data backfill — existing rows default to NULL, which is the correct
"branding-origin disabled" sentinel.

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "7c92e1a4d8b1"
down_revision = "b400430e70fc"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.add_column(
        f"{table_prefix}clients",
        sa.Column(
            "branding_signing_key",
            sa.String(length=128),
            nullable=True,
        ),
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.drop_column(f"{table_prefix}clients", "branding_signing_key")
