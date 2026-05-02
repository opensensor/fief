"""Add Brand model for host-based whitelabel routing

Revision ID: b3d8a2f47c1e
Revises: a736fe95ec4f
Create Date: 2026-05-02 11:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

import fief

# revision identifiers, used by Alembic.
revision = "b3d8a2f47c1e"
down_revision = "a736fe95ec4f"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.create_table(
        f"{table_prefix}brands",
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("application_url", sa.String(length=512), nullable=False),
        sa.Column("logo_url", sa.String(length=512), nullable=True),
        sa.Column(
            "is_default", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("tenant_id", fief.models.generics.GUID(), nullable=False),
        sa.Column("theme_id", fief.models.generics.GUID(), nullable=True),
        sa.Column("email_from_email", sa.String(length=255), nullable=True),
        sa.Column("email_from_name", sa.String(length=255), nullable=True),
        sa.Column("email_domain_id", fief.models.generics.GUID(), nullable=True),
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
            ["tenant_id"],
            [f"{table_prefix}tenants.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["theme_id"],
            [f"{table_prefix}themes.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["email_domain_id"],
            [f"{table_prefix}email_domains.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("host"),
    )
    op.create_index(
        op.f(f"ix_{table_prefix}brands_host"),
        f"{table_prefix}brands",
        ["host"],
        unique=True,
    )
    op.create_index(
        op.f(f"ix_{table_prefix}brands_created_at"),
        f"{table_prefix}brands",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f(f"ix_{table_prefix}brands_updated_at"),
        f"{table_prefix}brands",
        ["updated_at"],
        unique=False,
    )

    # Seed brand rows mapped to the default tenant. Skip silently if no default
    # tenant exists (fresh dev/test environments) — get_current_brand returns
    # None and templates fall back to the OpenSensor defaults.
    import uuid
    from datetime import UTC, datetime

    connection = op.get_bind()
    default_tenant_id = connection.execute(
        sa.text(f'SELECT id FROM {table_prefix}tenants WHERE "default" = true LIMIT 1')
    ).scalar()

    if default_tenant_id is not None:
        now = datetime.now(UTC)
        brands_table = sa.table(
            f"{table_prefix}brands",
            sa.column("id", fief.models.generics.GUID()),
            sa.column("host", sa.String),
            sa.column("name", sa.String),
            sa.column("application_url", sa.String),
            sa.column("logo_url", sa.String),
            sa.column("is_default", sa.Boolean),
            sa.column("tenant_id", fief.models.generics.GUID()),
            sa.column("created_at", fief.models.generics.TIMESTAMPAware(timezone=True)),
            sa.column("updated_at", fief.models.generics.TIMESTAMPAware(timezone=True)),
        )
        op.bulk_insert(
            brands_table,
            [
                {
                    "id": uuid.uuid4(),
                    "host": "members.opensensor.io",
                    "name": "OpenSensor",
                    "application_url": "https://opensensor.io",
                    "logo_url": None,
                    "is_default": True,
                    "tenant_id": default_tenant_id,
                    "created_at": now,
                    "updated_at": now,
                },
                {
                    "id": uuid.uuid4(),
                    "host": "members.lightnvr.com",
                    "name": "LightNVR",
                    "application_url": "https://lightnvr.com",
                    "logo_url": None,
                    "is_default": False,
                    "tenant_id": default_tenant_id,
                    "created_at": now,
                    "updated_at": now,
                },
                {
                    "id": uuid.uuid4(),
                    "host": "members.owlbooks.ai",
                    "name": "OwlBooks",
                    "application_url": "https://owlbooks.ai",
                    "logo_url": None,
                    "is_default": False,
                    "tenant_id": default_tenant_id,
                    "created_at": now,
                    "updated_at": now,
                },
            ],
        )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]

    op.drop_index(
        op.f(f"ix_{table_prefix}brands_updated_at"),
        table_name=f"{table_prefix}brands",
    )
    op.drop_index(
        op.f(f"ix_{table_prefix}brands_created_at"),
        table_name=f"{table_prefix}brands",
    )
    op.drop_index(
        op.f(f"ix_{table_prefix}brands_host"),
        table_name=f"{table_prefix}brands",
    )
    op.drop_table(f"{table_prefix}brands")
