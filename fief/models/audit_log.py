from datetime import datetime
from enum import StrEnum

from pydantic import UUID4
from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fief.models.base import Base
from fief.models.generics import GUID, TIMESTAMPAware, UUIDModel
from fief.models.user import User


class AuditLogMessage(StrEnum):
    OBJECT_CREATED = "OBJECT_CREATED"
    OBJECT_UPDATED = "OBJECT_UPDATED"
    OBJECT_DELETED = "OBJECT_DELETED"
    USER_REGISTERED = "USER_REGISTERED"
    USER_UPDATED = "USER_UPDATED"
    USER_EMAIL_VERIFY_REQUESTED = "USER_EMAIL_VERIFY_REQUESTED"
    USER_FORGOT_PASSWORD_REQUESTED = "USER_FORGOT_PASSWORD_REQUESTED"
    USER_PASSWORD_RESET = "USER_PASSWORD_RESET"
    USER_TOKEN_GENERATED = "USER_TOKEN_GENERATED"
    USER_TOKEN_GENERATED_BY_ADMIN = "USER_TOKEN_GENERATED_BY_ADMIN"
    USER_MFA_ENROLLED = "USER_MFA_ENROLLED"
    USER_MFA_DISABLED = "USER_MFA_DISABLED"
    USER_MFA_VERIFIED = "USER_MFA_VERIFIED"
    USER_MFA_VERIFY_FAILED = "USER_MFA_VERIFY_FAILED"
    USER_MFA_RECOVERY_CODE_USED = "USER_MFA_RECOVERY_CODE_USED"
    USER_MFA_RECOVERY_CODES_REGENERATED = "USER_MFA_RECOVERY_CODES_REGENERATED"
    USER_MFA_FORCE_REENROLLED = "USER_MFA_FORCE_REENROLLED"
    USER_MFA_STATE_INCONSISTENT = "USER_MFA_STATE_INCONSISTENT"
    USER_LOGIN_FAILED = "USER_LOGIN_FAILED"
    USER_RATE_LIMIT_EXCEEDED = "USER_RATE_LIMIT_EXCEEDED"
    USER_ACCOUNT_LOCKED = "USER_ACCOUNT_LOCKED"
    USER_ACCOUNT_AUTO_UNLOCKED = "USER_ACCOUNT_AUTO_UNLOCKED"
    USER_ACCOUNT_ADMIN_UNLOCKED = "USER_ACCOUNT_ADMIN_UNLOCKED"
    USER_PASSWORD_BREACHED_REJECTED = "USER_PASSWORD_BREACHED_REJECTED"
    USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN = "USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN"
    # UX-1 session revocation events.
    # Standard `extra` schema (informational — not enforced in code):
    #   - revoked_session_count: int   (count of fief_session_tokens deleted)
    #   - revoked_refresh_count: int   (count of fief_refresh_tokens deleted)
    #   - trigger_reason: str          (USER_SESSIONS_AUTO_REVOKED only;
    #                                    one of "password_change", "mfa_enrolled",
    #                                    "mfa_disabled", "recovery_code_used")
    #   - device_label: str | None     (USER_SESSION_REVOKED only;
    #                                    e.g. "Safari on Mac OS X")
    USER_SESSION_REVOKED = "USER_SESSION_REVOKED"
    USER_SESSIONS_SIGNED_OUT_OTHERS = "USER_SESSIONS_SIGNED_OUT_OTHERS"
    USER_SESSIONS_AUTO_REVOKED = "USER_SESSIONS_AUTO_REVOKED"
    # MFA-2 passkey / WebAuthn lifecycle events.
    # `USER_PASSKEY_VERIFY_FAILED.extra`:
    #   - reason: "invalid_signature" | "credential_not_found" | "challenge_expired"
    # `USER_PASSKEY_SIGN_COUNT_ROLLBACK.extra`:
    #   - credential_id_hex: str, stored: int, received: int
    #   (assertion's sign_count <= stored — possible cloned authenticator)
    USER_PASSKEY_REGISTERED = "USER_PASSKEY_REGISTERED"
    USER_PASSKEY_DELETED = "USER_PASSKEY_DELETED"
    USER_PASSKEY_VERIFIED = "USER_PASSKEY_VERIFIED"
    USER_PASSKEY_VERIFY_FAILED = "USER_PASSKEY_VERIFY_FAILED"
    USER_PASSKEY_SIGN_COUNT_ROLLBACK = "USER_PASSKEY_SIGN_COUNT_ROLLBACK"
    OAUTH_PROVIDER_USER_ACCESS_TOKEN_GET = "OAUTH_PROVIDER_USER_ACCESS_TOKEN_GET"


class AuditLog(UUIDModel, Base):
    __tablename__ = "audit_logs"

    timestamp: Mapped[datetime] = mapped_column(
        TIMESTAMPAware(timezone=True), nullable=False, index=True
    )
    level: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    extra: Mapped[dict] = mapped_column(JSON, nullable=True)

    subject_user_id: Mapped[UUID4 | None] = mapped_column(
        GUID, nullable=True, index=True
    )

    object_id: Mapped[UUID4 | None] = mapped_column(GUID, nullable=True, index=True)
    object_class: Mapped[str | None] = mapped_column(
        String(length=255), nullable=True, index=True
    )

    admin_user_id: Mapped[UUID4 | None] = mapped_column(GUID, nullable=True, index=True)
    admin_api_key_id: Mapped[UUID4 | None] = mapped_column(
        GUID, nullable=True, index=True
    )

    subject_user: Mapped[User | None] = relationship(
        "User",
        # Define a relationship, but without a foreign key constraint
        foreign_keys="AuditLog.subject_user_id",
        primaryjoin="AuditLog.subject_user_id == User.id",
    )
