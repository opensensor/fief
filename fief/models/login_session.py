import secrets
import uuid
from datetime import datetime
from typing import cast

from fastapi import Request
from fastapi.datastructures import URL
from pydantic import UUID4
from sqlalchemy import Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql.sqltypes import JSON, String

from fief.models.base import TABLE_PREFIX, Base
from fief.models.client import Client
from fief.models.generics import (
    GUID,
    CreatedUpdatedAt,
    ExpiresAt,
    TIMESTAMPAware,
    UUIDModel,
)
from fief.models.user import User
from fief.services.acr import ACR
from fief.settings import settings


class LoginSession(UUIDModel, CreatedUpdatedAt, ExpiresAt, Base):
    __tablename__ = "login_sessions"
    __lifetime_seconds__ = settings.login_session_lifetime_seconds

    token: Mapped[str] = mapped_column(
        String(length=255),
        default=secrets.token_urlsafe,
        nullable=False,
        index=True,
        unique=True,
    )
    response_type: Mapped[str] = mapped_column(String(length=255), nullable=False)
    response_mode: Mapped[str] = mapped_column(String(length=255), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(length=2048), nullable=False)
    scope: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    prompt: Mapped[str | None] = mapped_column(String(length=255), nullable=True)
    state: Mapped[str | None] = mapped_column(String(length=2048), nullable=True)
    nonce: Mapped[str | None] = mapped_column(String(length=255), nullable=True)
    acr: Mapped[ACR] = mapped_column(
        Enum(
            ACR,
            name=f"{TABLE_PREFIX}acr",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=ACR.LEVEL_ZERO,
    )
    code_challenge: Mapped[str | None] = mapped_column(
        String(length=255), nullable=True
    )
    code_challenge_method: Mapped[str | None] = mapped_column(
        String(length=255), nullable=True
    )

    client_id: Mapped[UUID4] = mapped_column(
        GUID, ForeignKey(Client.id, ondelete="CASCADE"), nullable=False
    )
    client: Mapped[Client] = relationship("Client", lazy="joined")

    # Verified storefront origin (e.g. ``https://shop-a.example.com``) carried
    # over from the signed ``branding_origin`` query param on ``GET /authorize``
    # (T46). Persisted here so the verified value survives the
    # ``/login`` -> ``/consent`` (and any MFA challenge) redirect chain — the
    # 5-minute expiry on the signed token only gates the initial ``/authorize``
    # hit, after which the brand resolver re-reads the value off the login
    # session for the rest of the flow. NULL means no signed branding_origin
    # was verified (or the client has no signing key set), in which case the
    # brand resolver falls back to the host-based lookup.
    branding_origin: Mapped[str | None] = mapped_column(
        String(length=2048), nullable=True, default=None
    )

    mfa_pending_user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID,
        ForeignKey(User.id, ondelete="SET NULL"),
        nullable=True,
        default=None,
    )
    mfa_attempts_count: Mapped[int] = mapped_column(default=0, nullable=False)
    mfa_locked_until: Mapped[datetime | None] = mapped_column(
        TIMESTAMPAware(timezone=True), nullable=True, default=None
    )

    def get_code_challenge_tuple(self) -> tuple[str, str] | None:
        if self.code_challenge is not None:
            return (self.code_challenge, cast(str, self.code_challenge_method))
        return None

    def regenerate_authorization_url(self, request: Request) -> URL:
        tenant = self.client.tenant
        query_params = {
            "response_type": self.response_type,
            "client_id": self.client.client_id,
            "redirect_uri": self.redirect_uri,
            "response_mode": self.response_mode,
            "scope": " ".join(self.scope),
            "prompt": self.prompt,
            "code_challenge_method": self.code_challenge_method,
            "code_challenge": self.code_challenge,
            "nonce": self.nonce,
            "state": self.state,
            "acr_values": self.acr.value,
        }
        return tenant.url_for(request, "auth:authorize").include_query_params(
            **{k: v for k, v in query_params.items() if v is not None}
        )
