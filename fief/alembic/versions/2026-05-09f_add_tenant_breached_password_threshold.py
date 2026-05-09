"""Add fief_tenants.breached_password_threshold for SEC-2 HIBP override

Revision ID: 2efcfe2289f4
Revises: 4f8d1c5e2a9b
Create Date: 2026-05-09 16:00:00.000000

Covers SEC-2 plan T4:
- New nullable column ``breached_password_threshold`` on ``fief_tenants`` that
  holds a per-tenant override for the HaveIBeenPwned breach-count threshold
  used by ``BreachedPasswordChecker``.
- NULL means "use ``settings.breached_password_default_threshold``" (which
  defaults to ``1`` -> reject any sighting in the HIBP corpus). A tenant that
  wants leniency for legacy users sets a higher value (e.g. ``100``).
- No default needed at the DB level; existing rows stay NULL and the service
  falls back to the global setting.

No data backfill required.

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "2efcfe2289f4"
down_revision = "4f8d1c5e2a9b"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.add_column(
        f"{table_prefix}tenants",
        sa.Column(
            "breached_password_threshold",
            sa.Integer(),
            nullable=True,
        ),
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.drop_column(f"{table_prefix}tenants", "breached_password_threshold")
