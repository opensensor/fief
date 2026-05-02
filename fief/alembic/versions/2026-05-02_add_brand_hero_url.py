"""Add Brand.hero_url for per-brand background hero asset

Revision ID: c4e9f1b2d3a7
Revises: b3d8a2f47c1e
Create Date: 2026-05-02 12:25:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "c4e9f1b2d3a7"
down_revision = "b3d8a2f47c1e"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.add_column(
        f"{table_prefix}brands",
        sa.Column("hero_url", sa.String(length=512), nullable=True),
    )

    # Set the LightNVR brand's hero asset (skip silently if the row isn't
    # present, so fresh dev/test environments don't fail).
    op.execute(
        sa.text(
            f"UPDATE {table_prefix}brands "
            "SET hero_url = '/static/brands/lightnvr_members_logo.png' "
            "WHERE host = 'members.lightnvr.com'"
        )
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.drop_column(f"{table_prefix}brands", "hero_url")
