"""Brandify transactional email templates (subjects + masthead + body)

Revision ID: f3b1c2d4a5e6
Revises: e9a1c3b7d2f4
Create Date: 2026-05-02 14:00:00.000000

Refreshes the four seeded email_templates rows in place so they read brand
from the render context with a tenant.name fallback. The render path now
populates `brand` whenever a transactional email is triggered through a
Brand's host. Without this update, production keeps the original Fief seed
(masthead links to https://example.com, subjects say "OpenSensor.io")
because EmailTemplateInitializer only seeds rows when missing.

NOTE: this overwrites any customization made via the admin UI for these
four template types. Current DB content matches the unmodified Fief seed,
so this is safe at the time of writing.

"""

from pathlib import Path

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f3b1c2d4a5e6"
down_revision = "e9a1c3b7d2f4"
branch_labels = None
depends_on = None


# Templates dir relative to this migration: fief/alembic/versions/X.py
# parents[2] resolves to the `fief` package root.
_TEMPLATES_DIR = (
    Path(__file__).resolve().parents[2] / "services" / "email_template" / "templates"
)


_NEW_SUBJECTS = {
    "WELCOME": "Welcome to {{ brand.name if brand else tenant.name }}",
    "VERIFY_EMAIL": (
        "Verify your email for your {{ brand.name if brand else tenant.name }} account"
    ),
    "FORGOT_PASSWORD": "Reset your {{ brand.name if brand else tenant.name }} password",
}

_PRIOR_SUBJECTS = {
    "WELCOME": "Welcome to {{ tenant.name }}",
    "VERIFY_EMAIL": "Verify your email for your {{ tenant.name }}'s account",
    "FORGOT_PASSWORD": "Reset your {{ tenant.name }}'s password",
}


def _read_template(filename: str) -> str:
    return (_TEMPLATES_DIR / filename).read_text()


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    table = f"{table_prefix}email_templates"

    op.execute(
        sa.text(f"UPDATE {table} SET content = :c WHERE type = 'BASE'").bindparams(
            c=_read_template("base.html")
        )
    )
    op.execute(
        sa.text(
            f"UPDATE {table} SET subject = :s, content = :c WHERE type = 'WELCOME'"
        ).bindparams(s=_NEW_SUBJECTS["WELCOME"], c=_read_template("welcome.html"))
    )
    op.execute(
        sa.text(
            f"UPDATE {table} SET subject = :s, content = :c WHERE type = 'VERIFY_EMAIL'"
        ).bindparams(
            s=_NEW_SUBJECTS["VERIFY_EMAIL"], c=_read_template("verify_email.html")
        )
    )
    op.execute(
        sa.text(
            f"UPDATE {table} "
            "SET subject = :s, content = :c WHERE type = 'FORGOT_PASSWORD'"
        ).bindparams(
            s=_NEW_SUBJECTS["FORGOT_PASSWORD"],
            c=_read_template("forgot_password.html"),
        )
    )


def downgrade():
    # Best-effort downgrade: restore the prior subject lines. We cannot
    # restore the prior content bodies precisely without bundling them here,
    # so a roll-back leaves the brand-aware content in place — harmless
    # because a None brand falls back to tenant.name.
    table_prefix = op.get_context().opts["table_prefix"]
    table = f"{table_prefix}email_templates"
    for type_, subject in _PRIOR_SUBJECTS.items():
        op.execute(
            sa.text(f"UPDATE {table} SET subject = :s WHERE type = :t").bindparams(
                s=subject, t=type_
            )
        )
