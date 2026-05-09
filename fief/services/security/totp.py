"""TOTP enrollment, verification, and teardown for the MFA-1 epic.

This service is the single chokepoint for everything related to
time-based one-time passwords. Routes (and any other caller) should never
import :mod:`pyotp` or :mod:`segno` directly — they should call into the
methods exposed here so that:

- secret material lives in memory for as short as possible (only the
  ``begin_enrollment`` return value carries the plaintext base32 secret —
  callers must not persist it),
- replay protection (``last_used_step``) is enforced on every successful
  verify, and
- decryption failures or orphaned ``users.mfa_enabled`` flags are folded
  into a single :class:`VerifyResult.INCONSISTENT_STATE` outcome that
  routes can self-heal from.

Audit logging mirrors the pattern in :class:`fief.services.user_manager`:
the :class:`fief.logger.AuditLogger` instance is invoked positionally with
the :class:`AuditLogMessage` and ``subject_user_id`` (plus an ``extra``
dict for state-inconsistency reasons so downstream log analysis can tell
the missing-row case apart from the decryption-failure case).
"""

from __future__ import annotations

import base64
import io
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum

import pyotp
import segno

from fief.logger import AuditLogger, logger
from fief.models import AuditLogMessage, UserTotpSecret
from fief.models.user import User
from fief.repositories.user import UserRepository
from fief.repositories.user_mfa_recovery_code import UserMfaRecoveryCodeRepository
from fief.repositories.user_totp_secret import UserTotpSecretRepository
from fief.services.security.encryption import (
    MfaSecretDecryptionError,
    decrypt,
    encrypt,
)
from fief.tasks.base import SendTask
from fief.tasks.mfa import on_mfa_state_changed

__all__ = [
    "EnrollmentBundle",
    "MfaAlreadyEnrolledError",
    "TotpService",
    "VerifyResult",
]


# Default pyotp/Google Authenticator step is 30 seconds. Recomputing the
# step from ``time.time()`` (rather than reaching into ``pyotp.utils``)
# keeps the dependency surface narrow and makes the replay test
# deterministic — same expression appears in the test suite.
_TOTP_STEP_SECONDS = 30


@dataclass
class EnrollmentBundle:
    """Payload returned to the caller starting an enrollment.

    ``secret_b32`` is the freshly generated plaintext secret. It is *only*
    returned on enroll-begin so the caller can render a manual-entry
    fallback alongside the QR code; it must never be persisted by the
    caller — the only at-rest copy lives in
    :class:`UserTotpSecret.secret_encrypted` (Fernet ciphertext).
    """

    secret_b32: str
    otpauth_uri: str
    qr_png_data_uri: str


class VerifyResult(StrEnum):
    """Outcome of :meth:`TotpService.verify`.

    Routes branch on this enum directly so the failure taxonomy is
    explicit at every call site (no boolean / exception duality).
    """

    SUCCESS = "SUCCESS"
    INVALID = "INVALID"
    REPLAY = "REPLAY"
    INCONSISTENT_STATE = "INCONSISTENT_STATE"


class MfaAlreadyEnrolledError(Exception):
    """Raised by :meth:`TotpService.begin_enrollment` if a confirmed row
    already exists for the user.

    The caller (typically the dashboard disable flow) is responsible for
    calling :meth:`TotpService.disable` first; we refuse to silently
    overwrite a working second factor because that would be a privilege
    escalation if the disable confirmation step were ever skipped.
    """


def _current_step() -> int:
    """Return the integer TOTP step for the current wall-clock time.

    Matches pyotp's default 30-second step. Used for the per-user
    replay-protection counter stored in ``last_used_step``.
    """

    return int(time.time() / _TOTP_STEP_SECONDS)


def _build_qr_data_uri(otpauth_uri: str) -> str:
    """Render ``otpauth_uri`` as an inline ``data:image/png;base64,...`` URI."""

    img = segno.make(otpauth_uri)
    buf = io.BytesIO()
    img.save(buf, kind="png", scale=4)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


class TotpService:
    def __init__(
        self,
        totp_repo: UserTotpSecretRepository,
        recovery_repo: UserMfaRecoveryCodeRepository,
        user_repo: UserRepository,
        audit_logger: AuditLogger,
    ) -> None:
        self.totp_repo = totp_repo
        self.recovery_repo = recovery_repo
        self.user_repo = user_repo
        self.audit_logger = audit_logger

    async def begin_enrollment(self, user: User, label: str) -> EnrollmentBundle:
        """Start (or restart) TOTP enrollment for ``user``.

        Replaces any existing *unconfirmed* row. Refuses to clobber a
        confirmed row by raising :class:`MfaAlreadyEnrolledError` — the
        caller must walk the user through ``disable`` first.
        """

        existing = await self.totp_repo.get_by_user_id(user.id)
        if existing is not None:
            if existing.confirmed_at is not None:
                raise MfaAlreadyEnrolledError(
                    "User already has a confirmed TOTP secret"
                )
            await self.totp_repo.delete_by_user_id(user.id)

        secret_b32 = pyotp.random_base32()
        otpauth_uri = pyotp.TOTP(secret_b32).provisioning_uri(
            name=user.email, issuer_name=label
        )
        qr_png_data_uri = _build_qr_data_uri(otpauth_uri)

        row = UserTotpSecret(
            user_id=user.id,
            secret_encrypted=encrypt(secret_b32),
            confirmed_at=None,
            last_used_step=None,
        )
        await self.totp_repo.create(row)

        return EnrollmentBundle(
            secret_b32=secret_b32,
            otpauth_uri=otpauth_uri,
            qr_png_data_uri=qr_png_data_uri,
        )

    async def confirm_enrollment(
        self,
        user: User,
        code: str,
        *,
        send_task: SendTask | None = None,
        brand_id: str | None = None,
    ) -> bool:
        """Validate the first OTP and flip the user's MFA on.

        Returns ``False`` (without deleting the unconfirmed row) on a bad
        code so the caller can re-prompt without restarting the QR
        ceremony.

        If ``send_task`` is provided, a brand-aware "MFA enabled"
        notification email is enqueued on success. ``brand_id`` is the
        UUID string of the brand the request originated from (None for
        admin / non-branded contexts; the email then renders against the
        tenant fallback).
        """

        row = await self.totp_repo.get_by_user_id(user.id)
        if row is None or row.confirmed_at is not None:
            # Either no enrollment in progress or it's already confirmed.
            return False

        try:
            secret_b32 = decrypt(row.secret_encrypted)
        except MfaSecretDecryptionError:
            # Should never happen during enrollment (we just wrote this
            # row a moment ago), but if it does, surface as failure rather
            # than crashing.
            logger.warning(
                "TOTP confirm_enrollment: decryption failed",
                user_id=str(user.id),
            )
            return False

        if not pyotp.TOTP(secret_b32).verify(code, valid_window=1):
            return False

        row.confirmed_at = datetime.now(timezone.utc)
        row.last_used_step = _current_step()
        await self.totp_repo.update(row)

        user.mfa_enabled = True
        await self.user_repo.update(user)

        self.audit_logger(
            AuditLogMessage.USER_MFA_ENROLLED, subject_user_id=user.id
        )

        if send_task is not None:
            send_task(
                on_mfa_state_changed,
                str(user.id),
                "enabled",
                brand_id,
            )
        return True

    async def verify(self, user: User, code: str) -> VerifyResult:
        """Verify ``code`` against the user's confirmed TOTP secret.

        Returns one of :class:`VerifyResult`. ``INCONSISTENT_STATE`` is
        emitted when either the ``users.mfa_enabled`` flag is set with
        no confirmed row, OR the stored ciphertext can't be decrypted.
        Both branches also fire :data:`AuditLogMessage.USER_MFA_STATE_INCONSISTENT`
        with a distinguishing ``extra={"reason": ...}``.
        """

        row = await self.totp_repo.get_confirmed_by_user_id(user.id)
        if row is None:
            if user.mfa_enabled:
                logger.warning(
                    "TOTP verify: users.mfa_enabled set but no confirmed secret",
                    user_id=str(user.id),
                )
                self.audit_logger(
                    AuditLogMessage.USER_MFA_STATE_INCONSISTENT,
                    subject_user_id=user.id,
                    extra={"reason": "missing_confirmed_secret"},
                )
                return VerifyResult.INCONSISTENT_STATE
            return VerifyResult.INVALID

        try:
            secret_b32 = decrypt(row.secret_encrypted)
        except MfaSecretDecryptionError as exc:
            logger.warning(
                "TOTP verify: ciphertext could not be decrypted",
                user_id=str(user.id),
                error=str(exc),
            )
            self.audit_logger(
                AuditLogMessage.USER_MFA_STATE_INCONSISTENT,
                subject_user_id=user.id,
                extra={"reason": "decryption_failed"},
            )
            return VerifyResult.INCONSISTENT_STATE

        proposed_step = _current_step()
        if (
            row.last_used_step is not None
            and proposed_step <= row.last_used_step
        ):
            return VerifyResult.REPLAY

        if not pyotp.TOTP(secret_b32).verify(code, valid_window=1):
            return VerifyResult.INVALID

        row.last_used_step = proposed_step
        await self.totp_repo.update(row)
        return VerifyResult.SUCCESS

    async def disable(
        self,
        user: User,
        *,
        send_task: SendTask | None = None,
        brand_id: str | None = None,
        notify: bool = True,
    ) -> None:
        """Tear down all MFA state for ``user`` and audit the event.

        This is best-effort idempotent — it's safe to call when no row
        exists (e.g. self-heal from an orphaned ``users.mfa_enabled=true``).

        If ``send_task`` is provided and ``notify`` is true, a brand-aware
        "MFA disabled" notification email is enqueued. Self-heal /
        inconsistent-state callers can pass ``notify=False`` to skip the
        email when the tear-down is reconciling state rather than
        responding to a user-initiated disable.
        """

        # Capture whether the user actually had MFA on before we mutate
        # state, so the notification path can short-circuit on idempotent
        # no-op calls (e.g. orphan self-heal where mfa_enabled is already
        # false).
        was_enabled = bool(user.mfa_enabled)

        await self.totp_repo.delete_by_user_id(user.id)
        await self.recovery_repo.delete_by_user_id(user.id)

        user.mfa_enabled = False
        await self.user_repo.update(user)

        self.audit_logger(
            AuditLogMessage.USER_MFA_DISABLED, subject_user_id=user.id
        )

        if notify and was_enabled and send_task is not None:
            send_task(
                on_mfa_state_changed,
                str(user.id),
                "disabled",
                brand_id,
            )
