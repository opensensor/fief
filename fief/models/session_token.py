from datetime import datetime

from pydantic import UUID4
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fief.models.base import Base
from fief.models.generics import (
    GUID,
    CreatedUpdatedAt,
    ExpiresAt,
    TIMESTAMPAware,
    UUIDModel,
)
from fief.models.user import User
from fief.settings import settings


class SessionToken(UUIDModel, CreatedUpdatedAt, ExpiresAt, Base):
    __tablename__ = "session_tokens"
    __lifetime_seconds__ = settings.session_lifetime_seconds

    token: Mapped[str] = mapped_column(
        String(length=255),
        nullable=False,
        index=True,
        unique=True,
    )

    user_id: Mapped[UUID4] = mapped_column(
        GUID,
        ForeignKey(User.id, ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user: Mapped[User] = relationship("User", lazy="joined")

    created_ip: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    created_user_agent: Mapped[str | None] = mapped_column(
        Text, nullable=True, default=None
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMPAware(timezone=True), nullable=True, default=None
    )
    last_seen_ip: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
