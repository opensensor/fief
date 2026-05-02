from pydantic import UUID4
from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fief.models.base import Base
from fief.models.email_domain import EmailDomain
from fief.models.generics import GUID, CreatedUpdatedAt, PydanticUrlString, UUIDModel
from fief.models.tenant import Tenant
from fief.models.theme import Theme


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
