from datetime import datetime

from pydantic import UUID4
from sqlalchemy import BigInteger, ForeignKey, LargeBinary, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fief.models.base import Base
from fief.models.generics import GUID, CreatedUpdatedAt, TIMESTAMPAware, UUIDModel
from fief.models.user import User


class UserTotpSecret(UUIDModel, CreatedUpdatedAt, Base):
    __tablename__ = "user_totp_secrets"
    __table_args__ = (UniqueConstraint("user_id"),)

    secret_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    confirmed_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMPAware(timezone=True), nullable=True, default=None
    )
    last_used_step: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True, default=None
    )

    user_id: Mapped[UUID4] = mapped_column(
        GUID, ForeignKey(User.id, ondelete="CASCADE"), nullable=False
    )
    user: Mapped[User] = relationship("User", back_populates="totp_secret")
