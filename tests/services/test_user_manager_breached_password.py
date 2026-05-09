"""Tests for SEC-2 T7: HIBP wiring inside :meth:`UserManager.validate_password`.

These tests exercise the four pieces of T7 in isolation, without exercising
HTTP (the :class:`BreachedPasswordChecker` is replaced with a stub):

1. ``BreachedPasswordError`` is a subclass of ``InvalidPasswordError`` so
   existing ``except InvalidPasswordError`` catch sites still match.
2. ``UserManager.validate_password`` calls
   ``BreachedPasswordChecker.is_breached`` and raises
   ``BreachedPasswordError`` (with an audit emit) when it returns True.
3. ``validate_password`` does NOT raise when ``is_breached`` returns False.
4. ``set_user_attributes(user, password=..., tenant=tenant)`` propagates
   the tenant arg through to the breached-password checker.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fief.models.audit_log import AuditLogMessage
from fief.services.user_manager import (
    BreachedPasswordError,
    InvalidPasswordError,
    UserManager,
)


# ---------------------------------------------------------------------------
# Lightweight fakes — enough surface for ``validate_password`` /
# ``set_user_attributes`` to run without touching the DB.
# ---------------------------------------------------------------------------


class _FakeUser:
    def __init__(self, *, tenant_id: uuid.UUID | None = None) -> None:
        self.id = uuid.uuid4()
        self.email = "user@example.com"
        self.tenant_id = tenant_id or uuid.uuid4()
        self.hashed_password = "old-hash"


class _FakeTenant:
    def __init__(self, *, breached_password_threshold: int | None = None) -> None:
        self.id = uuid.uuid4()
        self.breached_password_threshold = breached_password_threshold


def _build_user_manager(
    *,
    breached_password_checker: Any,
    audit_logger: Any | None = None,
) -> UserManager:
    """Build a :class:`UserManager` with everything mocked.

    ``validate_password`` only touches ``self.audit_logger`` and
    ``self.breached_password_checker``; ``set_user_attributes`` also needs
    ``self.password_helper``. All other deps are MagicMocks.
    """

    mock_password_helper = MagicMock()
    mock_password_helper.hash.return_value = "new-hash"

    return UserManager(
        password_helper=mock_password_helper,
        user_repository=MagicMock(),
        email_verification_repository=MagicMock(),
        user_fields=[],
        send_task=MagicMock(),
        audit_logger=audit_logger or MagicMock(),
        trigger_webhooks=MagicMock(),
        user_roles=MagicMock(),
        breached_password_checker=breached_password_checker,
    )


# ---------------------------------------------------------------------------
# Subclass relationship
# ---------------------------------------------------------------------------


def test_breached_password_error_is_invalid_password_error() -> None:
    """Existing ``except InvalidPasswordError`` sites must keep catching
    breached-password rejections without code changes."""

    err = BreachedPasswordError(["some message"])
    assert isinstance(err, InvalidPasswordError)
    assert err.messages == ["some message"]


# ---------------------------------------------------------------------------
# validate_password — HIBP integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_password_raises_breached_when_is_breached_true() -> None:
    checker = MagicMock()
    checker.is_breached = AsyncMock(return_value=True)
    audit_logger = MagicMock()

    manager = _build_user_manager(
        breached_password_checker=checker,
        audit_logger=audit_logger,
    )
    user = _FakeUser()
    tenant = _FakeTenant()

    # The password must pass zxcvbn first or we'd hit the existing
    # ``InvalidPasswordError`` branch instead of HIBP. ``correct horse
    # battery staple`` clears the default min_score=3 trivially.
    strong_breached_password = "correct horse battery staple"

    with pytest.raises(BreachedPasswordError):
        await manager.validate_password(
            strong_breached_password, user, tenant=tenant
        )

    # Audit emitted with the right enum + subject + tenant_id extra.
    breached_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_PASSWORD_BREACHED_REJECTED
    ]
    assert len(breached_calls) == 1
    call = breached_calls[0]
    assert call.kwargs["subject_user_id"] == user.id
    assert call.kwargs["extra"] == {"tenant_id": str(tenant.id)}

    # And ``is_breached`` was called with the right arguments.
    checker.is_breached.assert_awaited_once_with(strong_breached_password, tenant)


@pytest.mark.asyncio
async def test_validate_password_passes_when_is_breached_false() -> None:
    checker = MagicMock()
    checker.is_breached = AsyncMock(return_value=False)

    manager = _build_user_manager(breached_password_checker=checker)
    user = _FakeUser()
    tenant = _FakeTenant()

    # Should NOT raise.
    await manager.validate_password(
        "correct horse battery staple", user, tenant=tenant
    )

    checker.is_breached.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_password_short_circuits_on_zxcvbn_before_hibp() -> None:
    """A weak password should be rejected by zxcvbn BEFORE we waste a
    network round-trip checking HIBP. This guards an important
    optimization: HIBP traffic is bounded by the count of zxcvbn-passing
    attempts only."""

    checker = MagicMock()
    checker.is_breached = AsyncMock(return_value=True)

    manager = _build_user_manager(breached_password_checker=checker)
    user = _FakeUser()
    tenant = _FakeTenant()

    # Trivially weak password — zxcvbn will reject this with the
    # existing ``InvalidPasswordError`` (NOT BreachedPasswordError).
    with pytest.raises(InvalidPasswordError) as exc_info:
        await manager.validate_password("a", user, tenant=tenant)

    # Specifically NOT a BreachedPasswordError — the zxcvbn branch fires
    # first.
    assert not isinstance(exc_info.value, BreachedPasswordError)

    # And HIBP was never consulted.
    checker.is_breached.assert_not_awaited()


@pytest.mark.asyncio
async def test_validate_password_default_tenant_is_none() -> None:
    """Calling ``validate_password`` without a ``tenant`` kwarg (the
    legacy signature) must keep working — it just passes ``tenant=None``
    through to the checker."""

    checker = MagicMock()
    checker.is_breached = AsyncMock(return_value=False)

    manager = _build_user_manager(breached_password_checker=checker)
    user = _FakeUser()

    await manager.validate_password("correct horse battery staple", user)

    checker.is_breached.assert_awaited_once_with(
        "correct horse battery staple", None
    )


# ---------------------------------------------------------------------------
# set_user_attributes — tenant threading
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_user_attributes_propagates_tenant_to_validate_password() -> None:
    """When a caller passes ``tenant=tenant`` into ``set_user_attributes``
    alongside a ``password=...`` change, that same tenant must reach the
    HIBP checker so per-tenant thresholds apply."""

    checker = MagicMock()
    checker.is_breached = AsyncMock(return_value=False)

    manager = _build_user_manager(breached_password_checker=checker)
    user = _FakeUser()
    tenant = _FakeTenant(breached_password_threshold=100)

    await manager.set_user_attributes(
        user,
        password="correct horse battery staple",
        tenant=tenant,
    )

    checker.is_breached.assert_awaited_once_with(
        "correct horse battery staple", tenant
    )


@pytest.mark.asyncio
async def test_set_user_attributes_without_tenant_passes_none() -> None:
    """Back-compat: callers that don't pass tenant get None propagated
    (which means the global default threshold applies)."""

    checker = MagicMock()
    checker.is_breached = AsyncMock(return_value=False)

    manager = _build_user_manager(breached_password_checker=checker)
    user = _FakeUser()

    await manager.set_user_attributes(
        user, password="correct horse battery staple"
    )

    checker.is_breached.assert_awaited_once_with(
        "correct horse battery staple", None
    )


@pytest.mark.asyncio
async def test_set_user_attributes_breached_raises_breached_error() -> None:
    """End-to-end: ``set_user_attributes`` with a breached password
    surfaces as ``BreachedPasswordError`` — and existing code that only
    catches ``InvalidPasswordError`` still handles it."""

    checker = MagicMock()
    checker.is_breached = AsyncMock(return_value=True)

    manager = _build_user_manager(breached_password_checker=checker)
    user = _FakeUser()
    tenant = _FakeTenant()

    with pytest.raises(InvalidPasswordError) as exc_info:
        await manager.set_user_attributes(
            user,
            password="correct horse battery staple",
            tenant=tenant,
        )
    # And specifically the subclass:
    assert isinstance(exc_info.value, BreachedPasswordError)
