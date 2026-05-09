"""Unit tests for :class:`RecoveryCodeService` (T12).

These tests stub out the repository and audit logger so they don't require
a database. The repository fake stores :class:`UserMfaRecoveryCode` rows in a
plain in-memory list keyed by ``user_id`` so we can drive the
``generate_for`` / ``consume`` lifecycle end-to-end.

Hashing uses ``passlib.hash.bcrypt`` for real (not mocked); bcrypt is fast
enough for a 10-row test set and we want to exercise the actual verify path.
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest

from fief.models import AuditLogMessage, UserMfaRecoveryCode
from fief.services.security.recovery_codes import RecoveryCodeService

CODE_RE = re.compile(r"^[A-Z2-7]{4}-[A-Z2-7]{4}$")


class _FakeUser:
    def __init__(self) -> None:
        self.id = uuid.uuid4()


class _FakeRecoveryRepo:
    """In-memory stand-in for :class:`UserMfaRecoveryCodeRepository`.

    Records calls so tests can assert ordering (e.g. delete-before-insert).
    """

    def __init__(self) -> None:
        self.rows: list[UserMfaRecoveryCode] = []
        self.calls: list[tuple[str, Any]] = []

    async def list_by_user_id(
        self, user_id: uuid.UUID, *, only_unused: bool = False
    ) -> list[UserMfaRecoveryCode]:
        self.calls.append(("list_by_user_id", (user_id, only_unused)))
        out = [r for r in self.rows if r.user_id == user_id]
        if only_unused:
            out = [r for r in out if r.used_at is None]
        return out

    async def delete_by_user_id(self, user_id: uuid.UUID) -> None:
        self.calls.append(("delete_by_user_id", user_id))
        self.rows = [r for r in self.rows if r.user_id != user_id]

    async def create(self, row: UserMfaRecoveryCode) -> UserMfaRecoveryCode:
        self.calls.append(("create", row))
        self.rows.append(row)
        return row

    async def mark_used(
        self, code: UserMfaRecoveryCode
    ) -> UserMfaRecoveryCode:
        from datetime import datetime, timezone

        self.calls.append(("mark_used", code))
        code.used_at = datetime.now(timezone.utc)
        return code


@pytest.fixture
def repo() -> _FakeRecoveryRepo:
    return _FakeRecoveryRepo()


@pytest.fixture
def audit_logger() -> MagicMock:
    return MagicMock()


@pytest.fixture
def service(repo: _FakeRecoveryRepo, audit_logger: MagicMock) -> RecoveryCodeService:
    return RecoveryCodeService(repo, audit_logger)


@pytest.fixture
def user() -> _FakeUser:
    return _FakeUser()


@pytest.mark.asyncio
async def test_generate_for_returns_ten_unique_formatted_codes(
    service: RecoveryCodeService, user: _FakeUser
) -> None:
    codes = await service.generate_for(user)

    assert len(codes) == RecoveryCodeService.NUM_CODES == 10
    assert len(set(codes)) == 10
    for code in codes:
        assert CODE_RE.match(code), f"unexpected format: {code!r}"


@pytest.mark.asyncio
async def test_generate_for_audits_regeneration(
    service: RecoveryCodeService,
    user: _FakeUser,
    audit_logger: MagicMock,
) -> None:
    await service.generate_for(user)

    audit_logger.assert_any_call(
        AuditLogMessage.USER_MFA_RECOVERY_CODES_REGENERATED,
        subject_user_id=user.id,
    )


@pytest.mark.asyncio
async def test_generate_for_replaces_existing_rows(
    service: RecoveryCodeService,
    user: _FakeUser,
    repo: _FakeRecoveryRepo,
) -> None:
    await service.generate_for(user)
    first_rows = list(repo.rows)
    assert len(first_rows) == 10

    repo.calls.clear()
    await service.generate_for(user)

    # delete must come before any creates on regenerate
    op_names = [c[0] for c in repo.calls]
    assert op_names[0] == "delete_by_user_id"
    assert op_names.count("delete_by_user_id") == 1
    assert op_names.count("create") == 10
    assert all(
        op_names.index("delete_by_user_id") < i
        for i, name in enumerate(op_names)
        if name == "create"
    )

    # Old rows are gone — new set is fresh.
    assert len(repo.rows) == 10
    assert all(r not in first_rows for r in repo.rows)


@pytest.mark.asyncio
async def test_consume_accepts_formatted_code_and_marks_used(
    service: RecoveryCodeService,
    user: _FakeUser,
    repo: _FakeRecoveryRepo,
    audit_logger: MagicMock,
) -> None:
    codes = await service.generate_for(user)
    target = codes[3]

    assert await service.consume(user, target) is True

    # Replay must fail.
    assert await service.consume(user, target) is False

    # mark_used was called exactly once.
    assert sum(1 for c in repo.calls if c[0] == "mark_used") == 1

    audit_logger.assert_any_call(
        AuditLogMessage.USER_MFA_RECOVERY_CODE_USED,
        subject_user_id=user.id,
    )


@pytest.mark.asyncio
async def test_consume_accepts_unformatted_code(
    service: RecoveryCodeService, user: _FakeUser
) -> None:
    codes = await service.generate_for(user)
    raw = codes[0].replace("-", "")
    assert await service.consume(user, raw) is True


@pytest.mark.asyncio
async def test_consume_is_case_insensitive(
    service: RecoveryCodeService, user: _FakeUser
) -> None:
    codes = await service.generate_for(user)
    assert await service.consume(user, codes[0].lower()) is True


@pytest.mark.asyncio
async def test_consume_rejects_malformed_code_without_calling_bcrypt(
    service: RecoveryCodeService,
    user: _FakeUser,
    repo: _FakeRecoveryRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await service.generate_for(user)

    # Hard-fail if the service tries to verify a malformed code.
    from fief.services.security import recovery_codes as rc_module

    def _explode(*args: Any, **kwargs: Any) -> bool:
        raise AssertionError("bcrypt.verify must not be called for malformed input")

    monkeypatch.setattr(rc_module.bcrypt, "verify", _explode)

    assert await service.consume(user, "ABCDEF") is False  # 6 chars
    assert await service.consume(user, "ABCDEFG!") is False  # bad char
    assert await service.consume(user, "") is False
    assert await service.consume(user, "ABCDEFGHI") is False  # 9 chars


@pytest.mark.asyncio
async def test_consume_returns_false_when_all_codes_exhausted(
    service: RecoveryCodeService, user: _FakeUser
) -> None:
    codes = await service.generate_for(user)
    for code in codes:
        assert await service.consume(user, code) is True

    # Subsequent attempts (even with valid-shaped codes) return False.
    assert await service.consume(user, codes[0]) is False
    assert await service.consume(user, "AAAA-BBBB") is False
