"""Unit tests for :class:`TotpService` (T11).

These tests stub out the repositories, audit logger, and Fernet encryption
helper so they don't require a database. The TOTP arithmetic (``pyotp``) and
QR rendering (``segno``) are exercised for real because they're pure-Python
and load-bearing for the public contract this service exposes.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pyotp
import pytest

from fief.models import AuditLogMessage, UserTotpSecret
from fief.services.security import totp as totp_module
from fief.services.security.encryption import MfaSecretDecryptionError
from fief.services.security.totp import (
    EnrollmentBundle,
    MfaAlreadyEnrolledError,
    TotpService,
    VerifyResult,
)


class _FakeUser:
    def __init__(self, email: str = "user@example.com") -> None:
        self.id = uuid.uuid4()
        self.email = email
        self.mfa_enabled = False


class _FakeTotpRepo:
    def __init__(self) -> None:
        self.rows: dict[uuid.UUID, UserTotpSecret] = {}
        self.calls: list[tuple[str, Any]] = []

    async def get_by_user_id(
        self, user_id: uuid.UUID
    ) -> UserTotpSecret | None:
        self.calls.append(("get_by_user_id", user_id))
        return self.rows.get(user_id)

    async def get_confirmed_by_user_id(
        self, user_id: uuid.UUID
    ) -> UserTotpSecret | None:
        self.calls.append(("get_confirmed_by_user_id", user_id))
        row = self.rows.get(user_id)
        if row is None or row.confirmed_at is None:
            return None
        return row

    async def delete_by_user_id(self, user_id: uuid.UUID) -> None:
        self.calls.append(("delete_by_user_id", user_id))
        self.rows.pop(user_id, None)

    async def create(self, row: UserTotpSecret) -> UserTotpSecret:
        self.calls.append(("create", row))
        self.rows[row.user_id] = row
        return row

    async def update(self, row: UserTotpSecret) -> None:
        self.calls.append(("update", row))
        self.rows[row.user_id] = row

    async def delete(self, row: UserTotpSecret) -> None:
        self.calls.append(("delete", row))
        self.rows.pop(row.user_id, None)


class _FakeRecoveryRepo:
    def __init__(self) -> None:
        self.deleted: list[uuid.UUID] = []

    async def delete_by_user_id(self, user_id: uuid.UUID) -> None:
        self.deleted.append(user_id)


class _FakeUserRepo:
    def __init__(self) -> None:
        self.updated: list[Any] = []

    async def update(self, user: Any) -> None:
        self.updated.append(user)


class _FakeWebauthnRepo:
    """Stand-in for :class:`UserWebAuthnCredentialRepository`.

    The TOTP service only consults ``count_for_user`` (via the shared
    :func:`recompute_mfa_enabled` helper) on the disable path. Default
    is "no passkeys" so disable still flips ``mfa_enabled=False`` for
    these single-factor TOTP tests.
    """

    def __init__(self, *, passkey_count: int = 0) -> None:
        self.passkey_count = passkey_count

    async def count_for_user(self, user_id: uuid.UUID) -> int:
        return self.passkey_count


@pytest.fixture
def totp_repo() -> _FakeTotpRepo:
    return _FakeTotpRepo()


@pytest.fixture
def recovery_repo() -> _FakeRecoveryRepo:
    return _FakeRecoveryRepo()


@pytest.fixture
def webauthn_repo() -> _FakeWebauthnRepo:
    return _FakeWebauthnRepo()


@pytest.fixture
def user_repo() -> _FakeUserRepo:
    return _FakeUserRepo()


@pytest.fixture
def audit_logger() -> MagicMock:
    return MagicMock()


@pytest.fixture(autouse=True)
def stub_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Fernet encrypt/decrypt with a trivial reversible codec.

    The real Fernet helper requires settings configuration; we don't care
    about cryptographic strength here — only that the round-trip works and
    that we can drive a tampered/unknown ciphertext failure mode in one of
    the verify tests.
    """

    def _encrypt(plaintext: str) -> bytes:
        return ("ENC::" + plaintext).encode("utf-8")

    def _decrypt(blob: bytes) -> str:
        text = blob.decode("utf-8")
        if not text.startswith("ENC::"):
            raise MfaSecretDecryptionError("not a stub-encrypted token")
        return text[len("ENC::") :]

    monkeypatch.setattr(totp_module, "encrypt", _encrypt)
    monkeypatch.setattr(totp_module, "decrypt", _decrypt)


@pytest.fixture
def service(
    totp_repo: _FakeTotpRepo,
    recovery_repo: _FakeRecoveryRepo,
    user_repo: _FakeUserRepo,
    audit_logger: MagicMock,
    webauthn_repo: _FakeWebauthnRepo,
) -> TotpService:
    return TotpService(
        totp_repo,
        recovery_repo,
        user_repo,
        audit_logger,
        webauthn_repo,
    )


@pytest.fixture
def user() -> _FakeUser:
    return _FakeUser()


# ---------------------------------------------------------------------------
# begin_enrollment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_begin_enrollment_returns_bundle_with_uri_qr_and_secret(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
) -> None:
    bundle = await service.begin_enrollment(user, "Acme")

    assert isinstance(bundle, EnrollmentBundle)
    # base32 secret: pyotp generates a 32-char base32 string by default.
    assert bundle.secret_b32.isalnum()
    assert len(bundle.secret_b32) >= 16
    # otpauth URI carries the user email (URL-encoded) and the issuer label.
    assert bundle.otpauth_uri.startswith("otpauth://totp/")
    assert "user%40example.com" in bundle.otpauth_uri
    assert "issuer=Acme" in bundle.otpauth_uri
    assert "Acme" in bundle.otpauth_uri  # appears as label prefix too
    # QR is an inline base64 PNG data URI.
    assert bundle.qr_png_data_uri.startswith("data:image/png;base64,")
    # A row was persisted with confirmed_at=null.
    assert user.id in totp_repo.rows
    persisted = totp_repo.rows[user.id]
    assert persisted.confirmed_at is None


@pytest.mark.asyncio
async def test_begin_enrollment_replaces_existing_unconfirmed_row(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
) -> None:
    first = await service.begin_enrollment(user, "Acme")
    first_row = totp_repo.rows[user.id]

    second = await service.begin_enrollment(user, "Acme")

    # The persisted row was replaced (different ciphertext / different
    # underlying object) — not stacked.
    assert second.secret_b32 != first.secret_b32
    assert totp_repo.rows[user.id] is not first_row
    op_names = [c[0] for c in totp_repo.calls]
    # The replace path must invoke a delete (either delete_by_user_id or
    # the typed delete(row)) before the second create.
    second_create_idx = [
        i for i, n in enumerate(op_names) if n == "create"
    ][1]
    assert any(
        n in ("delete_by_user_id", "delete")
        for n in op_names[:second_create_idx]
    )


@pytest.mark.asyncio
async def test_begin_enrollment_raises_when_already_confirmed(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
) -> None:
    # Seed a confirmed row.
    secret = pyotp.random_base32()
    confirmed = UserTotpSecret(
        user_id=user.id,
        secret_encrypted=b"ENC::" + secret.encode(),
        confirmed_at=datetime.now(timezone.utc),
        last_used_step=None,
    )
    totp_repo.rows[user.id] = confirmed

    with pytest.raises(MfaAlreadyEnrolledError):
        await service.begin_enrollment(user, "Acme")


# ---------------------------------------------------------------------------
# confirm_enrollment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirm_enrollment_happy_path_flips_state_and_audits(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
    user_repo: _FakeUserRepo,
    audit_logger: MagicMock,
) -> None:
    bundle = await service.begin_enrollment(user, "Acme")
    code = pyotp.TOTP(bundle.secret_b32).now()

    assert await service.confirm_enrollment(user, code) is True

    persisted = totp_repo.rows[user.id]
    assert persisted.confirmed_at is not None
    assert persisted.last_used_step is not None
    assert persisted.last_used_step == int(time.time() / 30)
    assert user.mfa_enabled is True
    assert user in user_repo.updated
    audit_logger.assert_any_call(
        AuditLogMessage.USER_MFA_ENROLLED, subject_user_id=user.id
    )


@pytest.mark.asyncio
async def test_confirm_enrollment_invalid_code_keeps_unconfirmed(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
) -> None:
    await service.begin_enrollment(user, "Acme")

    assert await service.confirm_enrollment(user, "000000") is False
    assert user.mfa_enabled is False
    persisted = totp_repo.rows[user.id]
    assert persisted.confirmed_at is None


@pytest.mark.asyncio
async def test_confirm_enrollment_returns_false_when_no_unconfirmed_row(
    service: TotpService, user: _FakeUser
) -> None:
    assert await service.confirm_enrollment(user, "123456") is False


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_happy_path_returns_success_and_advances_step(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
) -> None:
    bundle = await service.begin_enrollment(user, "Acme")
    enrolled_step = int(time.time() / 30)
    # Confirm enrollment so user.mfa_enabled = True and last_used_step is
    # set; we'll then bump the step backwards on the row to allow a fresh
    # verify in the same 30-second window.
    confirm_code = pyotp.TOTP(bundle.secret_b32).now()
    assert await service.confirm_enrollment(user, confirm_code) is True

    # Reset last_used_step to one before the current step so verify is
    # accepted (the typical real-world case is verify some seconds-to-minutes
    # after enrollment).
    totp_repo.rows[user.id].last_used_step = enrolled_step - 1

    code = pyotp.TOTP(bundle.secret_b32).now()
    result = await service.verify(user, code)

    assert result is VerifyResult.SUCCESS
    assert totp_repo.rows[user.id].last_used_step == int(time.time() / 30)


@pytest.mark.asyncio
async def test_verify_replay_returns_replay_on_second_attempt(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
) -> None:
    bundle = await service.begin_enrollment(user, "Acme")
    confirm_code = pyotp.TOTP(bundle.secret_b32).now()
    assert await service.confirm_enrollment(user, confirm_code) is True
    # Step it back so the first verify can succeed.
    totp_repo.rows[user.id].last_used_step = int(time.time() / 30) - 1

    code = pyotp.TOTP(bundle.secret_b32).now()
    first = await service.verify(user, code)
    second = await service.verify(user, code)

    assert first is VerifyResult.SUCCESS
    assert second is VerifyResult.REPLAY


@pytest.mark.asyncio
async def test_verify_invalid_code_returns_invalid(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
) -> None:
    bundle = await service.begin_enrollment(user, "Acme")
    confirm_code = pyotp.TOTP(bundle.secret_b32).now()
    assert await service.confirm_enrollment(user, confirm_code) is True
    totp_repo.rows[user.id].last_used_step = int(time.time() / 30) - 1

    result = await service.verify(user, "000000")

    assert result is VerifyResult.INVALID


@pytest.mark.asyncio
async def test_verify_inconsistent_state_when_decrypt_fails(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
    audit_logger: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await service.begin_enrollment(user, "Acme")
    confirm_code = pyotp.TOTP(bundle.secret_b32).now()
    assert await service.confirm_enrollment(user, confirm_code) is True
    totp_repo.rows[user.id].last_used_step = int(time.time() / 30) - 1

    def _decrypt_fail(_blob: bytes) -> str:
        raise MfaSecretDecryptionError("simulated tampering")

    monkeypatch.setattr(totp_module, "decrypt", _decrypt_fail)

    result = await service.verify(user, "123456")

    assert result is VerifyResult.INCONSISTENT_STATE
    audit_logger.assert_any_call(
        AuditLogMessage.USER_MFA_STATE_INCONSISTENT,
        subject_user_id=user.id,
        extra={"reason": "decryption_failed"},
    )


@pytest.mark.asyncio
async def test_verify_inconsistent_state_when_no_confirmed_row_but_flag_set(
    service: TotpService,
    user: _FakeUser,
    audit_logger: MagicMock,
) -> None:
    user.mfa_enabled = True  # orphan flag, no row.

    result = await service.verify(user, "123456")

    assert result is VerifyResult.INCONSISTENT_STATE
    audit_logger.assert_any_call(
        AuditLogMessage.USER_MFA_STATE_INCONSISTENT,
        subject_user_id=user.id,
        extra={"reason": "missing_confirmed_secret"},
    )


@pytest.mark.asyncio
async def test_verify_returns_invalid_when_no_row_and_flag_unset(
    service: TotpService, user: _FakeUser
) -> None:
    # No flag, no row — caller shouldn't be calling verify, but if they do
    # we should reject without flagging an inconsistent state.
    result = await service.verify(user, "123456")
    assert result is VerifyResult.INVALID


# ---------------------------------------------------------------------------
# disable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_clears_state_and_audits(
    service: TotpService,
    user: _FakeUser,
    totp_repo: _FakeTotpRepo,
    recovery_repo: _FakeRecoveryRepo,
    user_repo: _FakeUserRepo,
    audit_logger: MagicMock,
) -> None:
    # Confirm enrollment first so disable has something to clear.
    bundle = await service.begin_enrollment(user, "Acme")
    confirm_code = pyotp.TOTP(bundle.secret_b32).now()
    assert await service.confirm_enrollment(user, confirm_code) is True
    assert user.mfa_enabled is True

    await service.disable(user)

    assert user.id not in totp_repo.rows
    assert user.id in recovery_repo.deleted
    assert user.mfa_enabled is False
    assert user in user_repo.updated
    audit_logger.assert_any_call(
        AuditLogMessage.USER_MFA_DISABLED, subject_user_id=user.id
    )
