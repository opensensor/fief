"""Seed MFA_ENABLED and MFA_DISABLED email templates (T22)

Revision ID: a1b2c3d4e5f6
Revises: 331683efd325
Create Date: 2026-05-09 13:00:00.000000

Covers MFA-1 plan T22: insert two new brand-aware transactional email
templates that are sent when a user enables or disables TOTP-based
two-factor authentication. Loads the seed content from the on-disk
templates so the migration matches the EmailTemplateInitializer seed
exactly. Uses a pre-check on the row's `type` so re-running on a
database where the initializer (or this migration) has already populated
the rows is a no-op. UUIDs are generated Python-side to keep the
migration cross-dialect (the GUID column accepts CHAR(36) on non-PG).

"""

import uuid
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "331683efd325"
branch_labels = None
depends_on = None


# Templates dir relative to this migration: fief/alembic/versions/X.py
# parents[2] resolves to the `fief` package root.
_TEMPLATES_DIR = (
    Path(__file__).resolve().parents[2] / "services" / "email_template" / "templates"
)


_SUBJECTS = {
    "MFA_ENABLED": (
        "Two-factor authentication enabled on your "
        "{{ brand.name if brand else tenant.name }} account"
    ),
    "MFA_DISABLED": (
        "Two-factor authentication disabled on your "
        "{{ brand.name if brand else tenant.name }} account"
    ),
}

_FILES = {
    "MFA_ENABLED": "mfa_enabled.html",
    "MFA_DISABLED": "mfa_disabled.html",
}


def _read_template(filename: str) -> str:
    return (_TEMPLATES_DIR / filename).read_text()


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    table = f"{table_prefix}email_templates"

    bind = op.get_bind()
    now = datetime.now(timezone.utc)

    for type_, subject in _SUBJECTS.items():
        existing = bind.execute(
            sa.text(f"SELECT 1 FROM {table} WHERE type = :t").bindparams(t=type_)
        ).first()
        if existing is not None:
            continue
        bind.execute(
            sa.text(
                f"INSERT INTO {table} "
                "(id, created_at, updated_at, type, subject, content) "
                "VALUES (:id, :created_at, :updated_at, :t, :s, :c)"
            ).bindparams(
                id=str(uuid.uuid4()),
                created_at=now,
                updated_at=now,
                t=type_,
                s=subject,
                c=_read_template(_FILES[type_]),
            )
        )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    table = f"{table_prefix}email_templates"

    bind = op.get_bind()
    for type_ in _SUBJECTS:
        bind.execute(
            sa.text(f"DELETE FROM {table} WHERE type = :t").bindparams(t=type_)
        )
