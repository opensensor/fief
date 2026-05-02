"""Set OwlBooks brand logo_url

Revision ID: d5a8f2c1e4b9
Revises: c4e9f1b2d3a7
Create Date: 2026-05-02 12:50:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d5a8f2c1e4b9"
down_revision = "c4e9f1b2d3a7"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.execute(
        sa.text(
            f"UPDATE {table_prefix}brands "
            "SET logo_url = '/static/brands/owlbooks-logo.png' "
            "WHERE host = 'members.owlbooks.ai'"
        )
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.execute(
        sa.text(
            f"UPDATE {table_prefix}brands "
            "SET logo_url = NULL "
            "WHERE host = 'members.owlbooks.ai'"
        )
    )
