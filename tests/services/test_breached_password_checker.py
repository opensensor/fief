"""Unit tests for the SEC-2 T6 :class:`BreachedPasswordChecker` service.

These tests exercise the k-anonymity HIBP integration with:

- ``respx`` to mock the HIBP HTTP responses without contacting the real API.
- ``fakeredis.aioredis.FakeRedis`` for the prefix cache layer.

We verify the four service contracts: positive identification (count >=
threshold), negative paths (below threshold / not in suffix list / kill
switch off / tenant override), the cache HIT/MISS path (including TTL),
and all four fail-open branches (timeout, 5xx, 429, malformed body) with
their accompanying ``USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN`` audit
emissions.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from unittest.mock import MagicMock

import fakeredis.aioredis
import httpx
import pytest
import pytest_asyncio
import respx

from fief.models.audit_log import AuditLogMessage
from fief.services.security.breached_passwords import BreachedPasswordChecker
from fief.settings import settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hibp_pair(password: str) -> tuple[str, str]:
    """Return ``(prefix5, suffix35)`` for a password's SHA-1 (uppercase)."""

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def _hibp_body(suffix_counts: dict[str, int]) -> str:
    """Render a fake HIBP range body of ``SUFFIX:COUNT`` lines."""

    return "\r\n".join(f"{s}:{c}" for s, c in suffix_counts.items())


class _FakeTenant:
    """Minimal duck-typed stand-in for ``Tenant`` (only the field the
    service touches matters)."""

    def __init__(self, breached_password_threshold: int | None = None):
        self.breached_password_threshold = breached_password_threshold


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis() -> fakeredis.aioredis.FakeRedis:
    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def audit_logger() -> MagicMock:
    return MagicMock()


@pytest_asyncio.fixture
async def http_client() -> Any:
    async with httpx.AsyncClient() as client:
        yield client


@pytest_asyncio.fixture
async def checker(
    fake_redis: fakeredis.aioredis.FakeRedis,
    http_client: httpx.AsyncClient,
    audit_logger: MagicMock,
) -> BreachedPasswordChecker:
    return BreachedPasswordChecker(fake_redis, http_client, audit_logger)


# ---------------------------------------------------------------------------
# Positive / negative path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_sighted_above_threshold_returns_true(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
    audit_logger: MagicMock,
) -> None:
    password = "Password1"  # noqa: S105 — test fixture, not a credential
    prefix, suffix = _hibp_pair(password)
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        return_value=httpx.Response(
            200, text=_hibp_body({suffix: 999, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": 1}),
        )
    )

    assert await checker.is_breached(password, tenant=None) is True

    # No fail-open audit on the happy path.
    failed_open_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args
        and c.args[0] == AuditLogMessage.USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN
    ]
    assert failed_open_calls == []


@pytest.mark.asyncio
async def test_password_sighted_below_threshold_returns_false(
    respx_mock: respx.MockRouter,
    fake_redis: fakeredis.aioredis.FakeRedis,
    http_client: httpx.AsyncClient,
    audit_logger: MagicMock,
) -> None:
    """With a tenant threshold of 100 and HIBP count=50, 50 < 100 → False."""

    password = "lukewarm-password"
    prefix, suffix = _hibp_pair(password)
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        return_value=httpx.Response(200, text=_hibp_body({suffix: 50})),
    )

    checker = BreachedPasswordChecker(fake_redis, http_client, audit_logger)
    tenant = _FakeTenant(breached_password_threshold=100)

    assert await checker.is_breached(password, tenant=tenant) is False


@pytest.mark.asyncio
async def test_password_not_in_returned_suffixes_returns_false(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
) -> None:
    password = "novel-passphrase"
    prefix, suffix = _hibp_pair(password)
    # Body contains a different suffix → our suffix is absent → count=0
    other_suffix = "F" * 35
    if other_suffix == suffix:
        other_suffix = "0" * 35
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        return_value=httpx.Response(200, text=_hibp_body({other_suffix: 5})),
    )

    assert await checker.is_breached(password, tenant=None) is False


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_hit_avoids_second_http_call(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
) -> None:
    password = "test-cache-hit"
    prefix, suffix = _hibp_pair(password)
    route = respx_mock.get(
        f"{settings.breached_password_api_url}/{prefix}"
    ).mock(return_value=httpx.Response(200, text=_hibp_body({suffix: 1})))

    # Two consecutive calls: only the first should hit HIBP.
    assert await checker.is_breached(password, tenant=None) is True
    assert await checker.is_breached(password, tenant=None) is True

    assert route.call_count == 1


@pytest.mark.asyncio
async def test_cache_miss_writes_with_ttl(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    password = "test-ttl"
    prefix, suffix = _hibp_pair(password)
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        return_value=httpx.Response(200, text=_hibp_body({suffix: 7})),
    )

    await checker.is_breached(password, tenant=None)

    cache_key = f"{BreachedPasswordChecker.CACHE_KEY_PREFIX}{prefix}".encode()
    raw = await fake_redis.get(cache_key)
    assert raw is not None

    # Stored payload is valid JSON of {suffix: count}.
    payload = json.loads(raw)
    assert payload[suffix] == 7

    ttl = await fake_redis.ttl(cache_key)
    # Positive (the key has an expiry) and bounded by the configured TTL.
    assert 0 < ttl <= settings.breached_password_cache_ttl_s


# ---------------------------------------------------------------------------
# Fail-open branches
# ---------------------------------------------------------------------------


def _failed_open_calls(audit_logger: MagicMock) -> list[Any]:
    return [
        c
        for c in audit_logger.call_args_list
        if c.args
        and c.args[0] == AuditLogMessage.USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN
    ]


@pytest.mark.asyncio
async def test_hibp_timeout_fails_open_with_audit(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
    audit_logger: MagicMock,
) -> None:
    password = "timeout-password"
    prefix, _ = _hibp_pair(password)
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        side_effect=httpx.TimeoutException("simulated timeout"),
    )

    assert await checker.is_breached(password, tenant=None) is False
    assert len(_failed_open_calls(audit_logger)) == 1


@pytest.mark.asyncio
async def test_hibp_5xx_fails_open_with_audit(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
    audit_logger: MagicMock,
) -> None:
    password = "fivexx-password"
    prefix, _ = _hibp_pair(password)
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        return_value=httpx.Response(503, text="upstream down"),
    )

    assert await checker.is_breached(password, tenant=None) is False
    assert len(_failed_open_calls(audit_logger)) == 1


@pytest.mark.asyncio
async def test_hibp_429_fails_open_with_audit(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
    audit_logger: MagicMock,
) -> None:
    password = "ratelimited-password"
    prefix, _ = _hibp_pair(password)
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        return_value=httpx.Response(429, text="slow down"),
    )

    assert await checker.is_breached(password, tenant=None) is False
    calls = _failed_open_calls(audit_logger)
    assert len(calls) == 1
    # 429 path uses its own reason for forensics.
    assert calls[0].kwargs["extra"]["reason"] == "hibp_rate_limited"


@pytest.mark.asyncio
async def test_hibp_malformed_body_fails_open_with_audit(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
    audit_logger: MagicMock,
) -> None:
    password = "malformed-password"
    prefix, _ = _hibp_pair(password)
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        return_value=httpx.Response(
            200,
            text="this is not a SUFFIX:COUNT line",
        ),
    )

    assert await checker.is_breached(password, tenant=None) is False
    calls = _failed_open_calls(audit_logger)
    assert len(calls) == 1
    assert calls[0].kwargs["extra"]["reason"] == "malformed_body"


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kill_switch_off_skips_http_call(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``breached_password_check_enabled=False`` the service must
    short-circuit before any HTTP request is made."""

    monkeypatch.setattr(settings, "breached_password_check_enabled", False)

    # Register a route but assert it never matches.
    route = respx_mock.get(
        f"{settings.breached_password_api_url}/AAAAA"
    ).mock(return_value=httpx.Response(200, text=""))

    assert await checker.is_breached("anything", tenant=None) is False
    assert route.call_count == 0


# ---------------------------------------------------------------------------
# Padding row filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_padding_rows_filtered_from_cache(
    respx_mock: respx.MockRouter,
    checker: BreachedPasswordChecker,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """HIBP ``Add-Padding`` returns rows with ``count=0`` to mask the true
    suffix list size. Those rows must NOT be cached — they'd inflate
    Redis memory and pollute the cache view."""

    password = "test-padding"
    prefix, suffix = _hibp_pair(password)

    # 1 real row + several padding rows (count=0).
    body = {
        suffix: 5,
        "1" * 35: 0,
        "2" * 35: 0,
        "3" * 35: 0,
    }
    respx_mock.get(f"{settings.breached_password_api_url}/{prefix}").mock(
        return_value=httpx.Response(200, text=_hibp_body(body)),
    )

    await checker.is_breached(password, tenant=None)

    cache_key = f"{BreachedPasswordChecker.CACHE_KEY_PREFIX}{prefix}".encode()
    raw = await fake_redis.get(cache_key)
    payload = json.loads(raw)

    # Only the real row survives.
    assert payload == {suffix: 5}
