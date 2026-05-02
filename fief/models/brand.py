from pydantic import UUID4
from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fief.models.base import Base
from fief.models.email_domain import EmailDomain
from fief.models.generics import GUID, CreatedUpdatedAt, PydanticUrlString, UUIDModel
from fief.models.tenant import Tenant
from fief.models.theme import Theme
from fief.settings import settings


class Brand(UUIDModel, CreatedUpdatedAt, Base):
    __tablename__ = "brands"

    host: Mapped[str] = mapped_column(
        String(length=255), nullable=False, unique=True, index=True
    )
    name: Mapped[str] = mapped_column(String(length=255), nullable=False)
    application_url: Mapped[str] = mapped_column(
        PydanticUrlString(String)(length=512), nullable=False
    )
    logo_url: Mapped[str | None] = mapped_column(
        PydanticUrlString(String)(length=512), default=None, nullable=True
    )
    hero_url: Mapped[str | None] = mapped_column(
        PydanticUrlString(String)(length=512), default=None, nullable=True
    )
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    tenant_id: Mapped[UUID4] = mapped_column(
        GUID, ForeignKey(Tenant.id, ondelete="CASCADE"), nullable=False
    )
    tenant: Mapped[Tenant] = relationship("Tenant")

    theme_id: Mapped[UUID4 | None] = mapped_column(
        GUID, ForeignKey(Theme.id, ondelete="SET NULL"), nullable=True
    )
    theme: Mapped[Theme | None] = relationship("Theme")

    email_from_email: Mapped[str | None] = mapped_column(
        String(length=255), nullable=True
    )
    email_from_name: Mapped[str | None] = mapped_column(
        String(length=255), nullable=True
    )
    email_domain_id: Mapped[UUID4 | None] = mapped_column(
        GUID, ForeignKey(EmailDomain.id, ondelete="SET NULL"), nullable=True
    )
    email_domain: Mapped[EmailDomain | None] = relationship("EmailDomain")

    def get_email_sender(
        self, *, fallback_tenant: Tenant | None = None
    ) -> tuple[str, str | None]:
        fallback_email, fallback_name = (
            fallback_tenant.get_email_sender()
            if fallback_tenant is not None
            else (settings.default_from_email, settings.default_from_name)
        )

        valid_email_domain = (
            self.email_domain is None or self.email_domain.is_verified()
        )

        from_email = (
            self.email_from_email
            if self.email_from_email is not None and valid_email_domain
            else fallback_email
        )
        from_name = (
            self.email_from_name if self.email_from_name is not None else fallback_name
        )

        return (from_email, from_name)
