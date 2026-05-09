"""Unit tests for :func:`recompute_mfa_enabled` (MFA-2 T13).

The helper centralizes the "is this user MFA-enrolled?" calculation so that
TOTP teardown and passkey register/delete all converge on the same logic:
``users.mfa_enabled`` is True iff the user has a confirmed TOTP secret OR
at least one WebAuthn credential.

These tests stub out the three repos (totp, webauthn, user) with in-memory
fakes so they don't require a database. The cases cover every transition
listed in T13:

- No factors → stays False.
- TOTP only → True.
- Passkey only → True.
- Both → True.
- Both, then drop one → still True (other factor keeps mfa_enabled True).
- Both, then drop both → flips False.
- None, then add one → flips True.
- Idempotency: calling twice when state matches doesn't re-update.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from fief.services.security.mfa_state import recompute_mfa_enabled


class _FakeUser:
    def __init__(self, *, mfa_enabled: bool = False) -> None:
        self.id = uuid.uuid4()
        self.mfa_enabled = mfa_enabled


class _FakeTotpRepo:
    """Stand-in for :class:`UserTotpSecretRepository`.

    Only ``get_confirmed_by_user_id`` is consulted by the helper; we
    return a sentinel object (truthy) when ``has_totp`` is True.
    """

    def __init__(self, *, has_totp: bool = False) -> None:
        self.has_totp = has_totp
        self.calls: list[uuid.UUID] = []

    async def get_confirmed_by_user_id(self, user_id: uuid.UUID) -> Any:
        self.calls.append(user_id)
        return object() if self.has_totp else None


class _FakeWebauthnRepo:
    """Stand-in for :class:`UserWebAuthnCredentialRepository.count_for_user`."""

    def __init__(self, *, passkey_count: int = 0) -> None:
        self.passkey_count = passkey_count
        self.calls: list[uuid.UUID] = []

    async def count_for_user(self, user_id: uuid.UUID) -> int:
        self.calls.append(user_id)
        return self.passkey_count


class _FakeUserRepo:
    def __init__(self) -> None:
        self.updated: list[Any] = []

    async def update(self, user: Any) -> None:
        self.updated.append(user)


@pytest.mark.asyncio
async def test_no_factors_stays_false() -> None:
    user = _FakeUser(mfa_enabled=False)
    totp_repo = _FakeTotpRepo(has_totp=False)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=0)
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert user.mfa_enabled is False
    # No-op: state already matches desired, no UPDATE issued.
    assert user_repo.updated == []


@pytest.mark.asyncio
async def test_totp_only_flips_true() -> None:
    user = _FakeUser(mfa_enabled=False)
    totp_repo = _FakeTotpRepo(has_totp=True)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=0)
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert user.mfa_enabled is True
    assert user in user_repo.updated


@pytest.mark.asyncio
async def test_passkey_only_flips_true() -> None:
    user = _FakeUser(mfa_enabled=False)
    totp_repo = _FakeTotpRepo(has_totp=False)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=1)
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert user.mfa_enabled is True
    assert user in user_repo.updated


@pytest.mark.asyncio
async def test_both_factors_present_stays_true() -> None:
    user = _FakeUser(mfa_enabled=True)
    totp_repo = _FakeTotpRepo(has_totp=True)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=2)
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert user.mfa_enabled is True
    # Idempotent: state already matches, no UPDATE issued.
    assert user_repo.updated == []


@pytest.mark.asyncio
async def test_both_factors_drop_passkey_stays_true() -> None:
    """User with TOTP + passkey deletes the passkey → mfa_enabled stays
    True because TOTP still enrolled."""
    user = _FakeUser(mfa_enabled=True)
    totp_repo = _FakeTotpRepo(has_totp=True)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=0)  # passkey just deleted
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert user.mfa_enabled is True
    assert user_repo.updated == []


@pytest.mark.asyncio
async def test_both_factors_drop_totp_stays_true() -> None:
    """User with TOTP + passkey disables TOTP → mfa_enabled stays True
    because passkey still registered."""
    user = _FakeUser(mfa_enabled=True)
    totp_repo = _FakeTotpRepo(has_totp=False)  # TOTP just disabled
    webauthn_repo = _FakeWebauthnRepo(passkey_count=1)
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert user.mfa_enabled is True
    assert user_repo.updated == []


@pytest.mark.asyncio
async def test_drop_both_factors_flips_false() -> None:
    """User with no remaining factors → mfa_enabled flips False."""
    user = _FakeUser(mfa_enabled=True)
    totp_repo = _FakeTotpRepo(has_totp=False)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=0)
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert user.mfa_enabled is False
    assert user in user_repo.updated


@pytest.mark.asyncio
async def test_add_first_passkey_flips_true() -> None:
    """User with no factors registers their first passkey → flip True."""
    user = _FakeUser(mfa_enabled=False)
    totp_repo = _FakeTotpRepo(has_totp=False)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=1)
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert user.mfa_enabled is True
    assert user in user_repo.updated


@pytest.mark.asyncio
async def test_idempotent_two_calls_only_updates_once() -> None:
    """Calling twice when the desired state is already set issues exactly
    one UPDATE (the first call), not two. Guards against unnecessary
    SQL writes on every register/delete that doesn't actually transition."""
    user = _FakeUser(mfa_enabled=False)
    totp_repo = _FakeTotpRepo(has_totp=False)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=1)
    user_repo = _FakeUserRepo()

    # First call: False -> True (flip).
    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )
    assert user.mfa_enabled is True
    assert len(user_repo.updated) == 1

    # Second call: True -> True (no flip, no second UPDATE).
    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )
    assert user.mfa_enabled is True
    assert len(user_repo.updated) == 1


@pytest.mark.asyncio
async def test_repos_consulted_with_user_id() -> None:
    """Both repos are queried using the user's id (not, say, the User
    object). Catches a refactor regression where the user_id derivation
    silently changes."""
    user = _FakeUser(mfa_enabled=False)
    totp_repo = _FakeTotpRepo(has_totp=False)
    webauthn_repo = _FakeWebauthnRepo(passkey_count=0)
    user_repo = _FakeUserRepo()

    await recompute_mfa_enabled(
        user,
        totp_repo=totp_repo,
        webauthn_repo=webauthn_repo,
        user_repo=user_repo,
    )

    assert totp_repo.calls == [user.id]
    assert webauthn_repo.calls == [user.id]
