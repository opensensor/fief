# Import Tenant directly (not via fief.models.__init__) so we don't
# eagerly register sibling MFA models whose back_populates targets land
# in T8. T7 is independent of T8 per the plan.
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


class TestTenantModelMfaRequired:
    def test_tenant_model_exposes_mfa_required_attribute(self):
        # Column-level default (False) is applied at INSERT time by SQLAlchemy,
        # so on an in-memory instance we just verify the attribute is wired.
        tenant = _make_tenant(mfa_required=False)
        assert tenant.mfa_required is False

    def test_tenant_mfa_required_can_be_set_true(self):
        tenant = _make_tenant(mfa_required=True)
        assert tenant.mfa_required is True

    def test_tenant_model_column_default_is_false(self):
        # Verify the SQLAlchemy column-level default is False (applied on insert).
        column = Tenant.__table__.c.mfa_required
        assert column.default.arg is False
        assert column.nullable is False


class TestTenantSchemaMfaRequired:
    def test_read_schema_includes_mfa_required(self):
        # BaseTenant uses from_attributes=True (see schemas.generics.BaseModel)
        # so we can build it from a model-like instance.
        from datetime import datetime, timezone
        from uuid import uuid4

        tenant = _make_tenant(registration_allowed=True, mfa_required=True)
        tenant.id = uuid4()
        tenant.created_at = datetime.now(tz=timezone.utc)
        tenant.updated_at = datetime.now(tz=timezone.utc)

        schema = BaseTenant.model_validate(tenant)
        dumped = schema.model_dump()

        assert "mfa_required" in dumped
        assert dumped["mfa_required"] is True

    def test_create_schema_accepts_mfa_required(self):
        payload = TenantCreate(name="Acme", mfa_required=True)
        assert payload.mfa_required is True

    def test_create_schema_defaults_mfa_required_false(self):
        payload = TenantCreate(name="Acme")
        assert payload.mfa_required is False

    def test_update_schema_accepts_mfa_required(self):
        payload = TenantUpdate(mfa_required=True)
        assert payload.mfa_required is True

    def test_update_schema_defaults_mfa_required_none(self):
        payload = TenantUpdate()
        assert payload.mfa_required is None
