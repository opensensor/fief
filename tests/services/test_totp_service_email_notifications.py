"""Tests for the brand-aware MFA enable/disable notification email
enqueue path on :class:`TotpService` (T22).

We don't exercise the dramatiq broker here — only that
:meth:`TotpService.confirm_enrollment` and :meth:`TotpService.disable`
call the supplied ``send_task`` callable with the right actor + args.
The actor is imported directly from ``fief.tasks.mfa`` to make the
identity assertion meaningful.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pyotp
import pytest

from fief.models import UserTotpSecret
from fief.services.security import totp as totp_module
from fief.services.security.encryption import MfaSecretDecryptionError
from fief.services.security.totp import TotpService
from fief.tasks.mfa import on_mfa_state_changed


class _FakeUser:
    def __init__(self, email: str = "user@example.com") -> None:
        self.id = uuid.uuid4()
        self.email = email
        self.mfa_enabled = False


class _FakeTotpRepo:
    def __init__(self) -> None:
        self.rows: dict[uuid.UUID, UserTotpSecret] = {}

    async def get_by_user_id(self, user_id: uuid.UUID) -> UserTotpSecret | None:
        return self.rows.get(user_id)

    async def get_confirmed_by_user_id(
        self, user_id: uuid.UUID
    ) -> UserTotpSecret | None:
        row = self.rows.get(user_id)
        if row is None or row.confirmed_at is None:
            return None
        return row

    async def delete_by_user_id(self, user_id: uuid.UUID) -> None:
        self.rows.pop(user_id, None)

    async def create(self, row: UserTotpSecret) -> UserTotpSecret:
        self.rows[row.user_id] = row
        return row

    async def update(self, row: UserTotpSecret) -> None:
        self.rows[row.user_id] = row

    async def delete(self, row: UserTotpSecret) -> None:
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


@pytest.fixture
def totp_repo() -> _FakeTotpRepo:
    return _FakeTotpRepo()


@pytest.fixture
def recovery_repo() -> _FakeRecoveryRepo:
    return _FakeRecoveryRepo()


@pytest.fixture
def user_repo() -> _FakeUserRepo:
    return _FakeUserRepo()


@pytest.fixture
def audit_logger() -> MagicMock:
    return MagicMock()


@pytest.fixture(autouse=True)
def stub_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    """Trivial reversible encrypt/decrypt — same pattern as test_totp_service."""

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
) -> TotpService:
    return TotpService(totp_repo, recovery_repo, user_repo, audit_logger)


@pytest.fixture
def user() -> _FakeUser:
    return _FakeUser()


# ---------------------------------------------------------------------------
# confirm_enrollment notification path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirm_enrollment_enqueues_enabled_notification_with_brand(
    service: TotpService, user: _FakeUser
) -> None:
    bundle = await service.begin_enrollment(user, "Acme")
    code = pyotp.TOTP(bundle.secret_b32).now()

    send_task = MagicMock()
    brand_id = str(uuid.uuid4())

    confirmed = await service.confirm_enrollment(
        user, code, send_task=send_task, brand_id=brand_id
    )

    assert confirmed is True
    send_task.assert_called_once_with(
        on_mfa_state_changed, str(user.id), "enabled", brand_id
    )


@pytest.mark.asyncio
async def test_confirm_enrollment_enqueues_with_none_brand_when_unbranded(
    service: TotpService, user: _FakeUser
) -> None:
    bundle = await service.begin_enrollment(user, "Acme")
    code = pyotp.TOTP(bundle.secret_b32).now()

    send_task = MagicMock()

    confirmed = await service.confirm_enrollment(
        user, code, send_task=send_task, brand_id=None
    )

    assert confirmed is True
    send_task.assert_called_once_with(
        on_mfa_state_changed, str(user.id), "enabled", None
    )


@pytest.mark.asyncio
async def test_confirm_enrollment_does_not_enqueue_on_invalid_code(
    service: TotpService, user: _FakeUser
) -> None:
    await service.begin_enrollment(user, "Acme")
    send_task = MagicMock()

    confirmed = await service.confirm_enrollment(
        user, "000000", send_task=send_task, brand_id=None
    )

    assert confirmed is False
    send_task.assert_not_called()


@pytest.mark.asyncio
async def test_confirm_enrollment_skips_enqueue_when_no_send_task(
    service: TotpService, user: _FakeUser
) -> None:
    """Backwards-compat: callers (e.g. tests) that don't supply send_task
    must not crash, just silently skip the enqueue."""

    bundle = await service.begin_enrollment(user, "Acme")
    code = pyotp.TOTP(bundle.secret_b32).now()

    # Should not raise.
    confirmed = await service.confirm_enrollment(user, code)
    assert confirmed is True


# ---------------------------------------------------------------------------
# disable notification path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_enqueues_disabled_notification_with_brand(
    service: TotpService, user: _FakeUser, totp_repo: _FakeTotpRepo
) -> None:
    # Seed a confirmed row so was_enabled=True path fires.
    user.mfa_enabled = True
    totp_repo.rows[user.id] = UserTotpSecret(
        user_id=user.id,
        secret_encrypted=b"ENC::ABC",
        confirmed_at=datetime.now(timezone.utc),
        last_used_step=0,
    )
    send_task = MagicMock()
    brand_id = str(uuid.uuid4())

    await service.disable(user, send_task=send_task, brand_id=brand_id)

    send_task.assert_called_once_with(
        on_mfa_state_changed, str(user.id), "disabled", brand_id
    )
    assert user.mfa_enabled is False


@pytest.mark.asyncio
async def test_disable_does_not_enqueue_when_user_was_not_enabled(
    service: TotpService, user: _FakeUser
) -> None:
    """Self-heal idempotent disable: user.mfa_enabled was already false,
    so this is a no-op clean-up — no spurious "MFA disabled" email."""

    assert user.mfa_enabled is False  # sanity
    send_task = MagicMock()

    await service.disable(user, send_task=send_task, brand_id=None)

    send_task.assert_not_called()


@pytest.mark.asyncio
async def test_disable_respects_notify_false_flag(
    service: TotpService, user: _FakeUser, totp_repo: _FakeTotpRepo
) -> None:
    """Inconsistent-state self-heal callers can opt out of the email."""

    user.mfa_enabled = True
    totp_repo.rows[user.id] = UserTotpSecret(
        user_id=user.id,
        secret_encrypted=b"ENC::ABC",
        confirmed_at=datetime.now(timezone.utc),
        last_used_step=0,
    )
    send_task = MagicMock()

    await service.disable(
        user, send_task=send_task, brand_id=None, notify=False
    )

    send_task.assert_not_called()


@pytest.mark.asyncio
async def test_disable_skips_enqueue_when_no_send_task(
    service: TotpService, user: _FakeUser, totp_repo: _FakeTotpRepo
) -> None:
    """Backwards-compat: callers that don't supply send_task must not
    crash. The auth.py recovery / self-heal paths rely on this."""

    user.mfa_enabled = True
    totp_repo.rows[user.id] = UserTotpSecret(
        user_id=user.id,
        secret_encrypted=b"ENC::ABC",
        confirmed_at=datetime.now(timezone.utc),
        last_used_step=0,
    )

    # Should not raise.
    await service.disable(user)
    assert user.mfa_enabled is False
