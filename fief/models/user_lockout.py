from datetime import datetime

from pydantic import UUID4
from sqlalchemy import ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fief.models.base import Base
from fief.models.generics import GUID, CreatedUpdatedAt, TIMESTAMPAware
from fief.models.user import User


class UserLockout(CreatedUpdatedAt, Base):
    """SEC-1 per-account lockout state.

    One row per user (``user_id`` is the primary key — there is no
    synthetic ``id`` column). The row is created lazily on the first
    failed login attempt and updated by ``AccountLockoutService`` as
    the failure ladder progresses.
    """

    __tablename__ = "user_lockouts"

    user_id: Mapped[UUID4] = mapped_column(
        GUID,
        ForeignKey(User.id, ondelete="CASCADE"),
        primary_key=True,
    )
    failed_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        TIMESTAMPAware(timezone=True), nullable=True, default=None, index=True
    )

    user: Mapped[User] = relationship("User", back_populates="lockout")
