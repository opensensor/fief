"""Set per-brand email_from_email / email_from_name for LightNVR and OwlBooks

Revision ID: e9a1c3b7d2f4
Revises: d5a8f2c1e4b9
Create Date: 2026-05-02 13:30:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "e9a1c3b7d2f4"
down_revision = "d5a8f2c1e4b9"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.execute(
        sa.text(
            f"UPDATE {table_prefix}brands "
            "SET email_from_email = 'support@lightnvr.com', "
            "    email_from_name = 'LightNVR' "
            "WHERE host = 'members.lightnvr.com'"
        )
    )
    op.execute(
        sa.text(
            f"UPDATE {table_prefix}brands "
            "SET email_from_email = 'support@owlbooks.ai', "
            "    email_from_name = 'OwlBooks' "
            "WHERE host = 'members.owlbooks.ai'"
        )
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.execute(
        sa.text(
            f"UPDATE {table_prefix}brands "
            "SET email_from_email = NULL, email_from_name = NULL "
            "WHERE host IN ('members.lightnvr.com', 'members.owlbooks.ai')"
        )
    )
