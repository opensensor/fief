"""Unit tests for :class:`AccountLockoutService` (SEC-1 T10).

The service mediates per-account lockouts on top of
:class:`UserLockoutRepository`. These tests use an in-memory fake repo
that mirrors the public method surface (``get_by_user_id``, ``upsert``,
``increment_and_apply_ladder``, ``clear``) and a ``MagicMock`` audit
logger, in the same style as ``tests/services/test_recovery_code_service.py``.

The ladder under test is exactly:
    5  fails -> +1  minute
    10 fails -> +5  minutes
    20 fails -> +15 minutes
    50 fails -> +24 hours
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from fief.models import AuditLogMessage
from fief.services.security.account_lockout import (
    AccountLocked,
    AccountLockoutService,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeUser:
    def __init__(self) -> None:
        self.id = uuid.uuid4()


class _FakeLockoutRow:
    """In-memory analogue of :class:`fief.models.UserLockout`.

    Only the fields the service touches matter: ``user_id``,
    ``failed_count`` and ``locked_until``.
    """

    def __init__(
        self,
        user_id: uuid.UUID,
        *,
        failed_count: int = 0,
        locked_until: datetime | None = None,
    ) -> None:
        self.user_id = user_id
        self.failed_count = failed_count
        self.locked_until = locked_until


# Same ladder thresholds as the real repo's ``_LADDER`` — duplicated here so
# the test file is the source of truth for the ladder under test.
_LADDER: dict[int, timedelta] = {
    5: timedelta(minutes=1),
    10: timedelta(minutes=5),
    20: timedelta(minutes=15),
    50: timedelta(hours=24),
}


class _FakeLockoutRepo:
    """In-memory stand-in for :class:`UserLockoutRepository`.

    Records every call so tests can assert ordering / call shape.
    """

    def __init__(self) -> None:
        self.rows: dict[uuid.UUID, _FakeLockoutRow] = {}
        self.calls: list[tuple[str, Any]] = []

    async def get_by_user_id(
        self, user_id: uuid.UUID
    ) -> _FakeLockoutRow | None:
        self.calls.append(("get_by_user_id", user_id))
        return self.rows.get(user_id)

    async def upsert(
        self,
        user_id: uuid.UUID,
        *,
        failed_count: int,
        locked_until: datetime | None,
    ) -> _FakeLockoutRow:
        self.calls.append(
            ("upsert", (user_id, failed_count, locked_until))
        )
        existing = self.rows.get(user_id)
        if existing is None:
            row = _FakeLockoutRow(
                user_id,
                failed_count=failed_count,
                locked_until=locked_until,
            )
            self.rows[user_id] = row
            return row
        existing.failed_count = failed_count
        existing.locked_until = locked_until
        return existing

    async def increment_and_apply_ladder(
        self, user_id: uuid.UUID
    ) -> _FakeLockoutRow:
        self.calls.append(("increment_and_apply_ladder", user_id))
        row = self.rows.get(user_id)
        now = datetime.now(UTC)
        if row is None:
            new_count = 1
            new_locked: datetime | None = None
            if new_count in _LADDER:
                new_locked = now + _LADDER[new_count]
            row = _FakeLockoutRow(
                user_id, failed_count=new_count, locked_until=new_locked
            )
            self.rows[user_id] = row
            return row
        row.failed_count += 1
        if row.failed_count in _LADDER:
            row.locked_until = now + _LADDER[row.failed_count]
        # else: leave locked_until AS IS — in-flight lockout stays.
        return row

    async def clear(self, user_id: uuid.UUID) -> None:
        self.calls.append(("clear", user_id))
        if user_id in self.rows:
            self.rows[user_id].failed_count = 0
            self.rows[user_id].locked_until = None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def repo() -> _FakeLockoutRepo:
    return _FakeLockoutRepo()


@pytest.fixture
def audit_logger() -> MagicMock:
    return MagicMock()


@pytest.fixture
def service(
    repo: _FakeLockoutRepo, audit_logger: MagicMock
) -> AccountLockoutService:
    return AccountLockoutService(repo, audit_logger)


@pytest.fixture
def user() -> _FakeUser:
    return _FakeUser()


# ---------------------------------------------------------------------------
# check_locked / record_failed — ladder boundary behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_four_fails_no_lockout(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
    audit_logger: MagicMock,
) -> None:
    """4 fails do not cross any ladder threshold; ``check_locked`` no-ops
    and no ``USER_ACCOUNT_LOCKED`` audit is emitted."""

    for _ in range(4):
        await service.record_failed(user)

    row = repo.rows[user.id]
    assert row.failed_count == 4
    assert row.locked_until is None

    # check_locked must be a no-op (no exception) when there's no active lockout.
    await service.check_locked(user)

    locked_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_LOCKED
    ]
    assert locked_calls == []


@pytest.mark.asyncio
async def test_fifth_fail_triggers_one_minute_lockout_with_audit(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
    audit_logger: MagicMock,
) -> None:
    """The 5th failed attempt sets ``locked_until ≈ now + 1 min`` and
    audits ``USER_ACCOUNT_LOCKED`` with ``failed_count=5`` in ``extra``."""

    before = datetime.now(UTC)
    for _ in range(5):
        await service.record_failed(user)
    after = datetime.now(UTC)

    row = repo.rows[user.id]
    assert row.failed_count == 5
    assert row.locked_until is not None
    # locked_until is roughly now + 1 min (tolerate test wall-clock skew).
    assert row.locked_until >= before + timedelta(minutes=1) - timedelta(seconds=2)
    assert row.locked_until <= after + timedelta(minutes=1) + timedelta(seconds=2)

    locked_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_LOCKED
    ]
    assert len(locked_calls) == 1
    call = locked_calls[0]
    assert call.kwargs["subject_user_id"] == user.id
    extra = call.kwargs["extra"]
    assert extra["failed_count"] == 5
    assert "locked_until" in extra  # ISO 8601 string


@pytest.mark.asyncio
async def test_check_locked_raises_during_active_lockout(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
) -> None:
    """While ``locked_until`` is in the future, ``check_locked`` raises
    ``AccountLocked`` with a positive ``retry_after_seconds``."""

    for _ in range(5):
        await service.record_failed(user)

    with pytest.raises(AccountLocked) as exc_info:
        await service.check_locked(user)

    assert exc_info.value.retry_after_seconds > 0
    # 1-minute lockout: retry_after must be at most 60s (and at least ~58 to
    # tolerate execution time between record_failed and check_locked).
    assert exc_info.value.retry_after_seconds <= 60


@pytest.mark.asyncio
async def test_check_locked_auto_unlocks_after_window(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
    audit_logger: MagicMock,
) -> None:
    """At ``locked_until + 1s``, ``check_locked`` clears ``locked_until``,
    KEEPS ``failed_count``, and audits ``USER_ACCOUNT_AUTO_UNLOCKED``."""

    for _ in range(5):
        await service.record_failed(user)

    row = repo.rows[user.id]
    assert row.locked_until is not None
    # Manually move the lockout into the past to simulate window elapsed.
    row.locked_until = datetime.now(UTC) - timedelta(seconds=1)

    audit_logger.reset_mock()
    await service.check_locked(user)

    # locked_until cleared, failed_count preserved.
    assert row.locked_until is None
    assert row.failed_count == 5

    auto_unlock_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_AUTO_UNLOCKED
    ]
    assert len(auto_unlock_calls) == 1
    call = auto_unlock_calls[0]
    assert call.kwargs["subject_user_id"] == user.id
    assert call.kwargs["extra"]["failed_count"] == 5


@pytest.mark.asyncio
async def test_tenth_fail_triggers_five_minute_lockout(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
    audit_logger: MagicMock,
) -> None:
    """The 10th failed attempt sets ``locked_until ≈ now + 5 min``."""

    before = datetime.now(UTC)
    for _ in range(10):
        await service.record_failed(user)
    after = datetime.now(UTC)

    row = repo.rows[user.id]
    assert row.failed_count == 10
    assert row.locked_until is not None
    assert row.locked_until >= before + timedelta(minutes=5) - timedelta(seconds=2)
    assert row.locked_until <= after + timedelta(minutes=5) + timedelta(seconds=2)

    locked_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_LOCKED
    ]
    # Once at 5, once at 10.
    assert len(locked_calls) == 2
    assert locked_calls[-1].kwargs["extra"]["failed_count"] == 10


@pytest.mark.asyncio
async def test_twentieth_fail_triggers_fifteen_minute_lockout(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
    audit_logger: MagicMock,
) -> None:
    before = datetime.now(UTC)
    for _ in range(20):
        await service.record_failed(user)
    after = datetime.now(UTC)

    row = repo.rows[user.id]
    assert row.failed_count == 20
    assert row.locked_until is not None
    assert row.locked_until >= before + timedelta(minutes=15) - timedelta(seconds=2)
    assert row.locked_until <= after + timedelta(minutes=15) + timedelta(seconds=2)

    locked_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_LOCKED
    ]
    # 5, 10, 20 — three rungs crossed.
    assert len(locked_calls) == 3
    assert locked_calls[-1].kwargs["extra"]["failed_count"] == 20


@pytest.mark.asyncio
async def test_fiftieth_fail_triggers_twenty_four_hour_lockout(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
    audit_logger: MagicMock,
) -> None:
    before = datetime.now(UTC)
    for _ in range(50):
        await service.record_failed(user)
    after = datetime.now(UTC)

    row = repo.rows[user.id]
    assert row.failed_count == 50
    assert row.locked_until is not None
    assert row.locked_until >= before + timedelta(hours=24) - timedelta(seconds=2)
    assert row.locked_until <= after + timedelta(hours=24) + timedelta(seconds=2)

    locked_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_LOCKED
    ]
    # 5, 10, 20, 50 — four rungs crossed.
    assert len(locked_calls) == 4
    assert locked_calls[-1].kwargs["extra"]["failed_count"] == 50


@pytest.mark.asyncio
async def test_sixth_fail_does_not_emit_locked_audit(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
    audit_logger: MagicMock,
) -> None:
    """Fails between thresholds (e.g. 6th) do not emit ``USER_ACCOUNT_LOCKED``.

    The 5th fail already audited; subsequent failures inside the active
    lockout still increment the counter but must not re-audit on every
    bump.
    """

    for _ in range(5):
        await service.record_failed(user)
    audit_logger.reset_mock()

    # 6th fail (still inside the 1-min lockout window).
    await service.record_failed(user)

    row = repo.rows[user.id]
    assert row.failed_count == 6

    locked_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_LOCKED
    ]
    assert locked_calls == []


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reset_clears_failed_count_and_lockout(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
) -> None:
    """``reset`` zeros ``failed_count`` and clears ``locked_until``."""

    for _ in range(5):
        await service.record_failed(user)
    row = repo.rows[user.id]
    assert row.failed_count == 5
    assert row.locked_until is not None

    await service.reset(user)

    assert row.failed_count == 0
    assert row.locked_until is None


@pytest.mark.asyncio
async def test_reset_on_unknown_user_is_noop(
    service: AccountLockoutService, user: _FakeUser, repo: _FakeLockoutRepo
) -> None:
    """``reset`` on a user with no row is silently a no-op (delegates to
    repo.clear which itself short-circuits)."""

    await service.reset(user)
    # No row was ever created.
    assert user.id not in repo.rows
    # And clear was still invoked (the service does not pre-check).
    assert ("clear", user.id) in repo.calls


# ---------------------------------------------------------------------------
# check_locked: row absent / locked_until null edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_locked_no_row_is_noop(
    service: AccountLockoutService, user: _FakeUser, audit_logger: MagicMock
) -> None:
    """No row at all -> ``check_locked`` returns without raising or auditing."""

    await service.check_locked(user)
    auto_unlock_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_AUTO_UNLOCKED
    ]
    assert auto_unlock_calls == []


@pytest.mark.asyncio
async def test_check_locked_row_without_active_lockout_is_noop(
    service: AccountLockoutService,
    user: _FakeUser,
    repo: _FakeLockoutRepo,
    audit_logger: MagicMock,
) -> None:
    """A row with ``failed_count > 0`` but ``locked_until is None`` (e.g.
    after auto-unlock) does not raise and does not re-audit."""

    # Below the first ladder rung — counter increments but no lockout set.
    for _ in range(3):
        await service.record_failed(user)
    audit_logger.reset_mock()

    await service.check_locked(user)

    auto_unlock_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_ACCOUNT_AUTO_UNLOCKED
    ]
    assert auto_unlock_calls == []
