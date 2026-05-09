"""Unit tests for :class:`DeviceSessionsService` (UX-1 T10).

The service combines :class:`SessionToken` and :class:`RefreshToken` rows
for a single user into a deduplicated list of :class:`DeviceRow` views.
These tests mirror the in-memory fake-repo style of
``tests/services/test_account_lockout.py`` so they stay isolated from
the database while exercising the full UA parse + dedup + audit
behaviour.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from fief.models import AuditLogMessage
from fief.services.security.device_sessions import (
    DeviceRow,
    DeviceSessionsService,
)


# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------


_SAFARI_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Safari/605.1.15"
)
_IPHONE_SAFARI = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Mobile/15E148 Safari/604.1"
)


def _now() -> datetime:
    # Frozen-ish timestamp; we avoid datetime.now to keep tests deterministic.
    return datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)


class _FakeSessionToken:
    """Minimal stand-in for :class:`fief.models.SessionToken`."""

    def __init__(
        self,
        *,
        user_id: uuid.UUID,
        created_at: datetime,
        last_seen_at: datetime | None,
        last_seen_ip: str | None,
        created_ip: str | None,
        created_user_agent: str | None,
        token_id: uuid.UUID | None = None,
    ) -> None:
        self.id = token_id if token_id is not None else uuid.uuid4()
        self.user_id = user_id
        self.created_at = created_at
        self.last_seen_at = last_seen_at
        self.last_seen_ip = last_seen_ip
        self.created_ip = created_ip
        self.created_user_agent = created_user_agent


class _FakeClient:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeRefreshToken:
    """Minimal stand-in for :class:`fief.models.RefreshToken`."""

    def __init__(
        self,
        *,
        user_id: uuid.UUID,
        created_at: datetime,
        last_seen_at: datetime | None,
        last_seen_ip: str | None,
        created_ip: str | None,
        created_user_agent: str | None,
        client: _FakeClient | None = None,
        token_id: uuid.UUID | None = None,
    ) -> None:
        self.id = token_id if token_id is not None else uuid.uuid4()
        self.user_id = user_id
        self.created_at = created_at
        self.last_seen_at = last_seen_at
        self.last_seen_ip = last_seen_ip
        self.created_ip = created_ip
        self.created_user_agent = created_user_agent
        self.client = client


class _FakeSessionRepo:
    def __init__(self) -> None:
        self.rows: list[_FakeSessionToken] = []
        self.calls: list[tuple[str, Any]] = []

    async def list_by_user_id(
        self, user_id: uuid.UUID
    ) -> list[_FakeSessionToken]:
        self.calls.append(("list_by_user_id", user_id))
        return [r for r in self.rows if r.user_id == user_id]

    async def delete_by_id_for_user(
        self, token_id: uuid.UUID, user_id: uuid.UUID
    ) -> int:
        self.calls.append(("delete_by_id_for_user", (token_id, user_id)))
        before = len(self.rows)
        self.rows = [
            r
            for r in self.rows
            if not (r.id == token_id and r.user_id == user_id)
        ]
        return before - len(self.rows)

    async def delete_all_except_for_user(
        self, user_id: uuid.UUID, except_ids: list[uuid.UUID]
    ) -> int:
        self.calls.append(("delete_all_except_for_user", (user_id, list(except_ids))))
        keep_ids = set(except_ids)
        before = len(self.rows)
        self.rows = [
            r
            for r in self.rows
            if r.user_id != user_id or r.id in keep_ids
        ]
        return before - len(self.rows)


class _FakeRefreshRepo:
    def __init__(self) -> None:
        self.rows: list[_FakeRefreshToken] = []
        self.calls: list[tuple[str, Any]] = []

    async def list_by_user_id(
        self, user_id: uuid.UUID
    ) -> list[_FakeRefreshToken]:
        self.calls.append(("list_by_user_id", user_id))
        return [r for r in self.rows if r.user_id == user_id]

    async def delete_by_id_for_user(
        self, token_id: uuid.UUID, user_id: uuid.UUID
    ) -> int:
        self.calls.append(("delete_by_id_for_user", (token_id, user_id)))
        before = len(self.rows)
        self.rows = [
            r
            for r in self.rows
            if not (r.id == token_id and r.user_id == user_id)
        ]
        return before - len(self.rows)

    async def delete_all_except_for_user(
        self, user_id: uuid.UUID, except_ids: list[uuid.UUID]
    ) -> int:
        self.calls.append(("delete_all_except_for_user", (user_id, list(except_ids))))
        keep_ids = set(except_ids)
        before = len(self.rows)
        self.rows = [
            r
            for r in self.rows
            if r.user_id != user_id or r.id in keep_ids
        ]
        return before - len(self.rows)


@pytest.fixture
def session_repo() -> _FakeSessionRepo:
    return _FakeSessionRepo()


@pytest.fixture
def refresh_repo() -> _FakeRefreshRepo:
    return _FakeRefreshRepo()


@pytest.fixture
def audit_logger() -> MagicMock:
    return MagicMock()


@pytest.fixture
def service(
    session_repo: _FakeSessionRepo,
    refresh_repo: _FakeRefreshRepo,
    audit_logger: MagicMock,
) -> DeviceSessionsService:
    return DeviceSessionsService(session_repo, refresh_repo, audit_logger)


@pytest.fixture
def user_id() -> uuid.UUID:
    return uuid.uuid4()


# ---------------------------------------------------------------------------
# list_for_user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_empty_user(
    service: DeviceSessionsService, user_id: uuid.UUID
) -> None:
    """A user with no tokens at all returns an empty list."""

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert rows == []


@pytest.mark.asyncio
async def test_two_session_tokens_same_ua_same_24_dedup_to_one_row(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    user_id: uuid.UUID,
) -> None:
    """Same UA + OS + same /24 IP collapses two session tokens into one row."""

    now = _now()
    s1 = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(hours=2),
        last_seen_at=now - timedelta(hours=1),
        last_seen_ip="192.0.2.55",
        created_ip="192.0.2.55",
        created_user_agent=_SAFARI_MAC,
    )
    s2 = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(hours=3),
        last_seen_at=now - timedelta(minutes=5),
        last_seen_ip="192.0.2.99",
        created_ip="192.0.2.99",
        created_user_agent=_SAFARI_MAC,
    )
    session_repo.rows = [s1, s2]

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, DeviceRow)
    assert sorted(row.session_token_ids) == sorted([s1.id, s2.id])
    assert row.refresh_token_ids == []
    # last_seen comes from the most recent token (s2 here).
    assert row.last_seen == s2.last_seen_at
    assert row.last_seen_ip == "192.0.2.99"
    # first_seen is the earliest created_at.
    assert row.first_seen == s2.created_at
    assert row.device_label == "Safari on Mac OS X"
    assert row.device_kind == "computer"


@pytest.mark.asyncio
async def test_two_session_tokens_different_16_split_into_two_rows(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    user_id: uuid.UUID,
) -> None:
    """Same UA + OS but different /24 IPs (different /16 here) split into
    two separate device rows."""

    now = _now()
    s1 = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(hours=2),
        last_seen_at=now - timedelta(hours=1),
        last_seen_ip="192.0.2.55",
        created_ip="192.0.2.55",
        created_user_agent=_SAFARI_MAC,
    )
    s2 = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(hours=3),
        last_seen_at=now - timedelta(minutes=5),
        last_seen_ip="198.51.100.7",
        created_ip="198.51.100.7",
        created_user_agent=_SAFARI_MAC,
    )
    session_repo.rows = [s1, s2]

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_is_current_flagged_on_row_containing_current_session(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    user_id: uuid.UUID,
) -> None:
    now = _now()
    s_other = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(hours=10),
        last_seen_at=now - timedelta(hours=9),
        last_seen_ip="198.51.100.10",
        created_ip="198.51.100.10",
        created_user_agent=_IPHONE_SAFARI,
    )
    s_curr = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(hours=1),
        last_seen_at=now - timedelta(minutes=2),
        last_seen_ip="192.0.2.42",
        created_ip="192.0.2.42",
        created_user_agent=_SAFARI_MAC,
    )
    session_repo.rows = [s_other, s_curr]

    rows = await service.list_for_user(
        user_id, current_session_id=s_curr.id
    )

    current_rows = [r for r in rows if r.is_current]
    assert len(current_rows) == 1
    assert s_curr.id in current_rows[0].session_token_ids


@pytest.mark.asyncio
async def test_safari_ua_label_and_kind(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    user_id: uuid.UUID,
) -> None:
    s = _FakeSessionToken(
        user_id=user_id,
        created_at=_now(),
        last_seen_at=_now(),
        last_seen_ip="192.0.2.10",
        created_ip="192.0.2.10",
        created_user_agent=_SAFARI_MAC,
    )
    session_repo.rows = [s]

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert len(rows) == 1
    assert rows[0].device_label == "Safari on Mac OS X"
    assert rows[0].device_kind == "computer"


@pytest.mark.asyncio
async def test_empty_ua_label_unknown(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    user_id: uuid.UUID,
) -> None:
    s = _FakeSessionToken(
        user_id=user_id,
        created_at=_now(),
        last_seen_at=_now(),
        last_seen_ip=None,
        created_ip=None,
        created_user_agent=None,
    )
    session_repo.rows = [s]

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert len(rows) == 1
    assert rows[0].device_label == "Unknown device"
    assert rows[0].device_kind == "unknown"


@pytest.mark.asyncio
async def test_mobile_ua_kind_phone(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    user_id: uuid.UUID,
) -> None:
    s = _FakeSessionToken(
        user_id=user_id,
        created_at=_now(),
        last_seen_at=_now(),
        last_seen_ip="192.0.2.10",
        created_ip="192.0.2.10",
        created_user_agent=_IPHONE_SAFARI,
    )
    session_repo.rows = [s]

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert len(rows) == 1
    assert rows[0].device_kind == "phone"


@pytest.mark.asyncio
async def test_rows_sorted_by_last_seen_desc(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    user_id: uuid.UUID,
) -> None:
    now = _now()
    older = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(days=2),
        last_seen_at=now - timedelta(days=1),
        last_seen_ip="198.51.100.7",
        created_ip="198.51.100.7",
        created_user_agent=_IPHONE_SAFARI,
    )
    newer = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(hours=3),
        last_seen_at=now - timedelta(minutes=1),
        last_seen_ip="192.0.2.10",
        created_ip="192.0.2.10",
        created_user_agent=_SAFARI_MAC,
    )
    session_repo.rows = [older, newer]

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert len(rows) == 2
    assert rows[0].last_seen >= rows[1].last_seen
    # Newer first.
    assert newer.id in rows[0].session_token_ids


@pytest.mark.asyncio
async def test_refresh_token_client_label(
    service: DeviceSessionsService,
    refresh_repo: _FakeRefreshRepo,
    user_id: uuid.UUID,
) -> None:
    """A refresh-token-only row picks up the client.name as client_label."""

    rt = _FakeRefreshToken(
        user_id=user_id,
        created_at=_now(),
        last_seen_at=_now(),
        last_seen_ip="192.0.2.10",
        created_ip="192.0.2.10",
        created_user_agent=_SAFARI_MAC,
        client=_FakeClient("LightNVR Web"),
    )
    refresh_repo.rows = [rt]

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert len(rows) == 1
    assert rows[0].client_label == "LightNVR Web"
    assert rows[0].refresh_token_ids == [rt.id]
    assert rows[0].session_token_ids == []


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_deletes_underlying_tokens_and_audits(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    refresh_repo: _FakeRefreshRepo,
    audit_logger: MagicMock,
    user_id: uuid.UUID,
) -> None:
    now = _now()
    s = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(hours=1),
        last_seen_at=now - timedelta(minutes=1),
        last_seen_ip="192.0.2.10",
        created_ip="192.0.2.10",
        created_user_agent=_SAFARI_MAC,
    )
    rt = _FakeRefreshToken(
        user_id=user_id,
        created_at=now - timedelta(hours=1),
        last_seen_at=now - timedelta(minutes=1),
        last_seen_ip="192.0.2.10",
        created_ip="192.0.2.10",
        created_user_agent=_SAFARI_MAC,
        client=_FakeClient("LightNVR Web"),
    )
    session_repo.rows = [s]
    refresh_repo.rows = [rt]

    rows = await service.list_for_user(user_id, current_session_id=None)
    assert len(rows) == 1
    device_key = rows[0].device_key

    revoked = await service.revoke(user_id, device_key)
    assert revoked is not None
    assert revoked.device_label == "Safari on Mac OS X"
    # All underlying tokens must be gone.
    assert session_repo.rows == []
    assert refresh_repo.rows == []

    revoke_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_SESSION_REVOKED
    ]
    assert len(revoke_calls) == 1
    extra = revoke_calls[0].kwargs["extra"]
    assert extra["device_label"] == "Safari on Mac OS X"
    assert extra["revoked_session_count"] == 1
    assert extra["revoked_refresh_count"] == 1


@pytest.mark.asyncio
async def test_revoke_with_stale_device_key_returns_none(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    audit_logger: MagicMock,
    user_id: uuid.UUID,
) -> None:
    s = _FakeSessionToken(
        user_id=user_id,
        created_at=_now(),
        last_seen_at=_now(),
        last_seen_ip="192.0.2.10",
        created_ip="192.0.2.10",
        created_user_agent=_SAFARI_MAC,
    )
    session_repo.rows = [s]

    revoked = await service.revoke(user_id, "deadbeef00000000")
    assert revoked is None
    # No session revoke audit emitted.
    revoke_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_SESSION_REVOKED
    ]
    assert revoke_calls == []
    # Underlying row untouched.
    assert session_repo.rows == [s]


# ---------------------------------------------------------------------------
# sign_out_others
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sign_out_others_preserves_current_session_revokes_all_refresh(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    refresh_repo: _FakeRefreshRepo,
    audit_logger: MagicMock,
    user_id: uuid.UUID,
) -> None:
    now = _now()
    s_curr = _FakeSessionToken(
        user_id=user_id,
        created_at=now,
        last_seen_at=now,
        last_seen_ip="192.0.2.1",
        created_ip="192.0.2.1",
        created_user_agent=_SAFARI_MAC,
    )
    s_other = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(days=1),
        last_seen_at=now - timedelta(hours=1),
        last_seen_ip="198.51.100.1",
        created_ip="198.51.100.1",
        created_user_agent=_IPHONE_SAFARI,
    )
    rt = _FakeRefreshToken(
        user_id=user_id,
        created_at=now,
        last_seen_at=now,
        last_seen_ip="192.0.2.1",
        created_ip="192.0.2.1",
        created_user_agent=_SAFARI_MAC,
    )
    session_repo.rows = [s_curr, s_other]
    refresh_repo.rows = [rt]

    s_count, r_count = await service.sign_out_others(
        user_id, current_session_id=s_curr.id
    )
    assert s_count == 1
    assert r_count == 1

    # current session preserved
    assert [r.id for r in session_repo.rows] == [s_curr.id]
    # refresh tokens fully wiped
    assert refresh_repo.rows == []

    out_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args
        and c.args[0] == AuditLogMessage.USER_SESSIONS_SIGNED_OUT_OTHERS
    ]
    assert len(out_calls) == 1
    extra = out_calls[0].kwargs["extra"]
    assert extra["revoked_session_count"] == 1
    assert extra["revoked_refresh_count"] == 1


# ---------------------------------------------------------------------------
# auto_revoke_others
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_revoke_others_audits_with_trigger_reason(
    service: DeviceSessionsService,
    session_repo: _FakeSessionRepo,
    refresh_repo: _FakeRefreshRepo,
    audit_logger: MagicMock,
    user_id: uuid.UUID,
) -> None:
    now = _now()
    s_curr = _FakeSessionToken(
        user_id=user_id,
        created_at=now,
        last_seen_at=now,
        last_seen_ip="192.0.2.1",
        created_ip="192.0.2.1",
        created_user_agent=_SAFARI_MAC,
    )
    s_other = _FakeSessionToken(
        user_id=user_id,
        created_at=now - timedelta(days=1),
        last_seen_at=now - timedelta(hours=1),
        last_seen_ip="198.51.100.1",
        created_ip="198.51.100.1",
        created_user_agent=_IPHONE_SAFARI,
    )
    rt = _FakeRefreshToken(
        user_id=user_id,
        created_at=now,
        last_seen_at=now,
        last_seen_ip="192.0.2.1",
        created_ip="192.0.2.1",
        created_user_agent=_SAFARI_MAC,
    )
    session_repo.rows = [s_curr, s_other]
    refresh_repo.rows = [rt]

    s_count, r_count = await service.auto_revoke_others(
        user_id,
        current_session_id=s_curr.id,
        reason="password_change",
    )
    assert s_count == 1
    assert r_count == 1

    auto_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args
        and c.args[0] == AuditLogMessage.USER_SESSIONS_AUTO_REVOKED
    ]
    assert len(auto_calls) == 1
    extra = auto_calls[0].kwargs["extra"]
    assert extra["trigger_reason"] == "password_change"
    assert extra["revoked_session_count"] == 1
    assert extra["revoked_refresh_count"] == 1
