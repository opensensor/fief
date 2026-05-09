from datetime import datetime

from pydantic import UUID4
from sqlalchemy import ForeignKey, Index, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fief.models.base import Base
from fief.models.generics import GUID, CreatedUpdatedAt, TIMESTAMPAware, UUIDModel
from fief.models.user import User


class UserMfaRecoveryCode(UUIDModel, CreatedUpdatedAt, Base):
    __tablename__ = "user_mfa_recovery_codes"
    __table_args__ = (
        Index(
            "ix_user_mfa_recovery_codes_user_id_used_at",
            "user_id",
            "used_at",
        ),
    )

    code_hash: Mapped[str] = mapped_column(Text, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMPAware(timezone=True), nullable=True, default=None
    )

    user_id: Mapped[UUID4] = mapped_column(
        GUID, ForeignKey(User.id, ondelete="CASCADE"), nullable=False
    )
    user: Mapped[User] = relationship("User", back_populates="mfa_recovery_codes")
