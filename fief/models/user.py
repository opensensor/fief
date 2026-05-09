from typing import TYPE_CHECKING, Any, Optional, Self

from pydantic import UUID4
from sqlalchemy import Boolean, ForeignKey, String, event
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql.schema import UniqueConstraint

from fief.models.base import Base
from fief.models.generics import GUID, CreatedUpdatedAt, UUIDModel
from fief.models.tenant import Tenant
from fief.models.user_field import UserField

if TYPE_CHECKING:
    from fief.models.user_field_value import UserFieldValue
    from fief.models.user_lockout import UserLockout
    from fief.models.user_mfa_recovery_code import UserMfaRecoveryCode
    from fief.models.user_totp_secret import UserTotpSecret
    from fief.models.user_webauthn_credential import UserWebAuthnCredential


class User(UUIDModel, CreatedUpdatedAt, Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", "tenant_id"),)

    email: Mapped[str] = mapped_column(String(length=320), index=True, nullable=False)
    email_lower: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    email_verified: Mapped[bool] = mapped_column(
        Boolean, index=True, default=False, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(String(length=255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    tenant_id: Mapped[UUID4] = mapped_column(
        GUID, ForeignKey(Tenant.id, ondelete="CASCADE"), nullable=False
    )
    tenant: Mapped[Tenant] = relationship("Tenant")

    user_field_values: Mapped[list["UserFieldValue"]] = relationship(
        "UserFieldValue", back_populates="user", cascade="all, delete", lazy="selectin"
    )

    totp_secret: Mapped["UserTotpSecret | None"] = relationship(
        "UserTotpSecret",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    mfa_recovery_codes: Mapped[list["UserMfaRecoveryCode"]] = relationship(
        "UserMfaRecoveryCode",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    lockout: Mapped["UserLockout | None"] = relationship(
        "UserLockout",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    webauthn_credentials: Mapped[list["UserWebAuthnCredential"]] = relationship(
        "UserWebAuthnCredential",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"User(id={self.id}, email={self.email})"

    @property
    def fields(self) -> dict[str, Any]:
        return dict(
            user_field_value.get_slug_and_value()
            for user_field_value in self.user_field_values
        )

    def get_user_field_value(self, user_field: UserField) -> Optional["UserFieldValue"]:
        for user_field_value in self.user_field_values:
            if user_field_value.user_field_id == user_field.id:
                return user_field_value
        return None

    def get_claims(self) -> dict[str, Any]:
        fields = dict(
            user_field_value.get_slug_and_value(json_serializable=True)
            for user_field_value in self.user_field_values
        )
        return {
            "sub": str(self.id),
            "email": self.email,
            "email_verified": self.email_verified,
            "is_active": self.is_active,
            "tenant_id": str(self.tenant_id),
            "fields": fields,
        }

    @classmethod
    def create_sample(cls, tenant: Tenant) -> Self:
        return cls(
            email="anne@bretagne.duchy",
            tenant_id=tenant.id,
        )


@event.listens_for(User.email, "set")
def update_email_lower(target: User, value: str, oldvalue, initiator):
    if value is not None:
        target.email_lower = value.lower()
