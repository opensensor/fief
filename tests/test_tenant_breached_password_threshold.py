# Import Tenant directly (not via fief.models.__init__) so we don't
# eagerly register sibling models whose back_populates targets land in
# other tasks. T5 is independent of those.
from fief.models.tenant import Tenant
from fief.schemas.tenant import (
    BaseTenant,
    TenantCreate,
    TenantUpdate,
)


def _make_tenant(**overrides) -> Tenant:
    kwargs = dict(
        name="Default",
        slug="default",
        default=True,
        oauth_providers=[],
    )
    kwargs.update(overrides)
    return Tenant(**kwargs)


class TestTenantModelBreachedPasswordThreshold:
    def test_tenant_model_exposes_breached_password_threshold_attribute(self):
        # Column-level default (None) is applied at INSERT time by SQLAlchemy,
        # so on an in-memory instance we just verify the attribute is wired.
        tenant = _make_tenant(breached_password_threshold=None)
        assert tenant.breached_password_threshold is None

    def test_tenant_breached_password_threshold_can_be_set_to_int(self):
        tenant = _make_tenant(breached_password_threshold=100)
        assert tenant.breached_password_threshold == 100

    def test_tenant_model_column_default_is_none_and_nullable(self):
        column = Tenant.__table__.c.breached_password_threshold
        # Column-level default should be None (applied on insert).
        assert column.default is None or column.default.arg is None
        assert column.nullable is True


class TestTenantSchemaBreachedPasswordThreshold:
    def test_read_schema_includes_breached_password_threshold(self):
        # BaseTenant uses from_attributes=True (see schemas.generics.BaseModel)
        # so we can build it from a model-like instance.
        from datetime import datetime, timezone
        from uuid import uuid4

        tenant = _make_tenant(
            registration_allowed=True,
            mfa_required=False,
            breached_password_threshold=50,
        )
        tenant.id = uuid4()
        tenant.created_at = datetime.now(tz=timezone.utc)
        tenant.updated_at = datetime.now(tz=timezone.utc)

        schema = BaseTenant.model_validate(tenant)
        dumped = schema.model_dump()

        assert "breached_password_threshold" in dumped
        assert dumped["breached_password_threshold"] == 50

    def test_read_schema_breached_password_threshold_can_be_none(self):
        from datetime import datetime, timezone
        from uuid import uuid4

        tenant = _make_tenant(
            registration_allowed=True,
            mfa_required=False,
            breached_password_threshold=None,
        )
        tenant.id = uuid4()
        tenant.created_at = datetime.now(tz=timezone.utc)
        tenant.updated_at = datetime.now(tz=timezone.utc)

        schema = BaseTenant.model_validate(tenant)
        dumped = schema.model_dump()

        assert "breached_password_threshold" in dumped
        assert dumped["breached_password_threshold"] is None

    def test_create_schema_accepts_breached_password_threshold(self):
        payload = TenantCreate(name="Acme", breached_password_threshold=42)
        assert payload.breached_password_threshold == 42

    def test_create_schema_defaults_breached_password_threshold_none(self):
        payload = TenantCreate(name="Acme")
        assert payload.breached_password_threshold is None

    def test_update_schema_accepts_breached_password_threshold(self):
        payload = TenantUpdate(breached_password_threshold=200)
        assert payload.breached_password_threshold == 200

    def test_update_schema_defaults_breached_password_threshold_none(self):
        payload = TenantUpdate()
        assert payload.breached_password_threshold is None
