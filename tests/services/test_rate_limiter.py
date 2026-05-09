"""Unit tests for the SEC-1 T9 :class:`RateLimiter` service.

These tests use ``fakeredis.aioredis.FakeRedis`` for the Redis dependency
so we exercise the real ZADD / ZREMRANGEBYSCORE / ZCARD / EXPIRE pipeline
without contacting a server.

Time control: the sliding-window check uses ``time.time()`` *in the
service*, and the values it writes are stored as ZSET scores inside
fakeredis — fakeredis itself doesn't have its own clock for ZSCORE
purposes, so monkeypatching the service's view of ``time.time`` is
sufficient to simulate window expiry.

Fail-open: we cover the ``RedisError`` path with a custom client that
raises on ``pipeline()`` to confirm the service swallows the exception
and returns ``0``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import fakeredis.aioredis
import pytest
from redis import RedisError

from fief.services.security.rate_limiter import (
    RateLimiter,
    RateLimitExceeded,
    RateLimitWindow,
)


@pytest.fixture
def fake_redis() -> fakeredis.aioredis.FakeRedis:
    """A fresh fakeredis instance per test (no cross-test bleed)."""

    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def limiter(fake_redis: fakeredis.aioredis.FakeRedis) -> RateLimiter:
    return RateLimiter(fake_redis)


@pytest.mark.asyncio
async def test_under_limit_returns_running_count(limiter: RateLimiter) -> None:
    """Under the cap: every call returns the post-add count, no exception."""

    window = RateLimitWindow(max_count=10, per_seconds=60)

    counts = []
    for _ in range(5):
        counts.append(
            await limiter.check(scope="test", key="alice", window=window)
        )

    assert counts == [1, 2, 3, 4, 5]


@pytest.mark.asyncio
async def test_at_limit_returns_max_count(limiter: RateLimiter) -> None:
    """The Nth call (where N == max_count) returns N and does NOT raise."""

    window = RateLimitWindow(max_count=10, per_seconds=60)

    last = 0
    for _ in range(10):
        last = await limiter.check(scope="test", key="alice", window=window)

    assert last == 10


@pytest.mark.asyncio
async def test_over_limit_raises_with_positive_retry_after(
    limiter: RateLimiter,
) -> None:
    """The (max_count + 1)th call raises ``RateLimitExceeded``."""

    window = RateLimitWindow(max_count=10, per_seconds=60)

    for _ in range(10):
        await limiter.check(scope="test", key="alice", window=window)

    with pytest.raises(RateLimitExceeded) as excinfo:
        await limiter.check(scope="test", key="alice", window=window)

    assert excinfo.value.retry_after_seconds > 0
    # retry_after must never exceed window length (the oldest entry can't
    # be older than ``per_seconds`` ago by definition of the sliding
    # window).
    assert excinfo.value.retry_after_seconds <= window.per_seconds


@pytest.mark.asyncio
async def test_sliding_window_expires_old_entries(
    limiter: RateLimiter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request older than ``per_seconds`` must not be counted on the
    next check — that's the whole point of a sliding window."""

    window = RateLimitWindow(max_count=10, per_seconds=60)

    # Anchor time at t=0 for the first request.
    fake_now = {"value": 1_000_000.0}

    def _now() -> float:
        return fake_now["value"]

    from fief.services.security import rate_limiter as mod

    monkeypatch.setattr(mod.time, "time", _now)

    first = await limiter.check(scope="test", key="bob", window=window)
    assert first == 1

    # Advance past the window — now the first entry is older than
    # ``per_seconds`` and must be removed by ZREMRANGEBYSCORE before the
    # next ZADD.
    fake_now["value"] += window.per_seconds + 1

    second = await limiter.check(scope="test", key="bob", window=window)
    assert second == 1, (
        "Expected the previous entry to be evicted by the sliding window; "
        f"got count={second}"
    )


@pytest.mark.asyncio
async def test_bucket_ttl_is_set_and_within_window(
    limiter: RateLimiter, fake_redis: fakeredis.aioredis.FakeRedis
) -> None:
    """The ``EXPIRE`` call must give the bucket a positive TTL no greater
    than ``per_seconds`` so idle buckets self-evict."""

    window = RateLimitWindow(max_count=10, per_seconds=60)

    await limiter.check(scope="test", key="carol", window=window)

    ttl = await fake_redis.ttl(b"rl:test:carol")
    assert ttl > 0
    assert ttl <= window.per_seconds


@pytest.mark.asyncio
async def test_independent_buckets_for_different_scope_and_key(
    limiter: RateLimiter,
) -> None:
    """``(scope, key)`` tuples must produce independent buckets — saturating
    one must not affect another."""

    window = RateLimitWindow(max_count=2, per_seconds=60)

    # Saturate bucket A.
    assert await limiter.check(scope="A", key="x", window=window) == 1
    assert await limiter.check(scope="A", key="x", window=window) == 2

    # Same scope, different key: independent.
    assert await limiter.check(scope="A", key="y", window=window) == 1

    # Different scope, same key: independent.
    assert await limiter.check(scope="B", key="x", window=window) == 1

    # Bucket A is still at 2 — third call raises.
    with pytest.raises(RateLimitExceeded):
        await limiter.check(scope="A", key="x", window=window)

    # Bucket B is still at 1 — second call is fine.
    assert await limiter.check(scope="B", key="x", window=window) == 2


@pytest.mark.asyncio
async def test_fail_open_on_redis_error_returns_zero() -> None:
    """If Redis raises ``RedisError``, the service must swallow it and
    return 0 (under-limit) so the caller proceeds. Bot-mitigation
    *must* fail open so an outage doesn't lock everyone out."""

    class _BrokenClient:
        def pipeline(self, *_: Any, **__: Any) -> Any:
            raise RedisError("simulated outage")

    limiter = RateLimiter(_BrokenClient())  # type: ignore[arg-type]

    result = await limiter.check(
        scope="test",
        key="dave",
        window=RateLimitWindow(max_count=1, per_seconds=60),
    )

    assert result == 0


@pytest.mark.asyncio
async def test_fail_open_on_pipeline_execute_error() -> None:
    """``RedisError`` raised during pipeline ``execute()`` (not just at
    construction) must also be swallowed."""

    class _BrokenPipeline:
        async def __aenter__(self) -> "_BrokenPipeline":
            return self

        async def __aexit__(self, *_: Any) -> None:
            return None

        def zremrangebyscore(self, *_: Any, **__: Any) -> None:
            return None

        def zadd(self, *_: Any, **__: Any) -> None:
            return None

        def zcard(self, *_: Any, **__: Any) -> None:
            return None

        def expire(self, *_: Any, **__: Any) -> None:
            return None

        async def execute(self) -> Any:
            raise RedisError("EXEC failed")

    class _ClientWithBrokenExecute:
        def pipeline(self, *_: Any, **__: Any) -> Any:
            return _BrokenPipeline()

    limiter = RateLimiter(_ClientWithBrokenExecute())  # type: ignore[arg-type]

    result = await limiter.check(
        scope="test",
        key="eve",
        window=RateLimitWindow(max_count=1, per_seconds=60),
    )

    assert result == 0


@pytest.mark.asyncio
async def test_rate_limit_exceeded_carries_retry_after_attribute() -> None:
    """The exception type exposes ``retry_after_seconds`` for the route
    handler to drop into a ``Retry-After`` header."""

    exc = RateLimitExceeded(retry_after_seconds=42)
    assert exc.retry_after_seconds == 42
    assert "42" in str(exc)


def test_rate_limit_window_is_immutable() -> None:
    """``RateLimitWindow`` is frozen so the policy cannot be mutated by
    accident from a route handler."""

    window = RateLimitWindow(max_count=10, per_seconds=60)
    with pytest.raises((AttributeError, Exception)):
        window.max_count = 99  # type: ignore[misc]


@pytest.mark.asyncio
async def test_get_rate_limiter_dependency_factory_returns_service() -> None:
    """The ``get_rate_limiter`` dependency yields a ``RateLimiter`` bound
    to the injected client."""

    from fief.dependencies.security import get_rate_limiter

    fake = fakeredis.aioredis.FakeRedis()
    service = await get_rate_limiter(redis_client=fake)

    assert isinstance(service, RateLimiter)
    assert service.redis is fake
