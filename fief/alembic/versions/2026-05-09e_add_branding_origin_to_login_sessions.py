"""Add fief_login_sessions.branding_origin for signed branding_origin persistence

Revision ID: 4f8d1c5e2a9b
Revises: 7c92e1a4d8b1
Create Date: 2026-05-09 15:05:00.000000

Covers fief-app-plan T46 (Option A from the audit § 4.2):
- New nullable column ``branding_origin`` on ``fief_login_sessions`` that
  stores the verified storefront origin (e.g. ``https://shop-a.example.com``)
  produced by the HMAC verifier at ``GET /authorize`` time.
- Persisted on the login session so the verified origin survives the
  ``/authorize`` -> ``/login`` -> ``/consent`` (and any MFA challenge
  redirects in between) chain. Without this, the brand resolver on
  subsequent steps would re-fall back to ``request.url.hostname``, which
  is always Fief's host for Saleor-driven logins.
- 2048 mirrors the existing ``redirect_uri`` column width since both share
  the URL-length domain. NULL means "no signed branding_origin verified
  on this login" -> brand resolver falls back to host-based lookup.

No data backfill required — existing rows default to NULL.

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "4f8d1c5e2a9b"
down_revision = "7c92e1a4d8b1"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.add_column(
        f"{table_prefix}login_sessions",
        sa.Column(
            "branding_origin",
            sa.String(length=2048),
            nullable=True,
        ),
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.drop_column(f"{table_prefix}login_sessions", "branding_origin")
