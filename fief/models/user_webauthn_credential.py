from datetime import datetime

from pydantic import UUID4
from sqlalchemy import BigInteger, Boolean, ForeignKey, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fief.models.base import Base
from fief.models.generics import GUID, CreatedUpdatedAt, TIMESTAMPAware, UUIDModel
from fief.models.user import User


class UserWebAuthnCredential(UUIDModel, CreatedUpdatedAt, Base):
    """MFA-2 WebAuthn / passkey credential.

    One row per registered authenticator. ``credential_id`` is the
    WebAuthn-side identifier (raw bytes) and is unique-indexed because
    assertion lookup uses it directly.

    ``transports`` is stored as comma-separated text rather than a
    Postgres ``text[]`` array — keeps the column cross-dialect for
    SQLite-backed tests. Service code converts to/from ``list[str]``.
    """

    __tablename__ = "user_webauthn_credentials"

    user_id: Mapped[UUID4] = mapped_column(
        GUID,
        ForeignKey(User.id, ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    credential_id: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False, unique=True, index=True
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    transports: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    aaguid: Mapped[UUID4 | None] = mapped_column(GUID, nullable=True, default=None)
    backup_eligible: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    backup_state: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    label: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    attestation_obj: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True, default=None
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMPAware(timezone=True), nullable=True, default=None
    )

    user: Mapped[User] = relationship("User", back_populates="webauthn_credentials")

    @property
    def transports_list(self) -> list[str]:
        if not self.transports:
            return []
        return [t.strip() for t in self.transports.split(",") if t.strip()]
