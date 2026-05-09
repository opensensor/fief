"""Smoke tests for the SEC-1 T6 async Redis client dependency.

These tests verify the lazy singleton behavior, the shutdown hook, and
that the dependency module imports cleanly. We never touch a real
Redis: production code paths are stubbed via ``unittest.mock`` and
``fakeredis`` is what real consumers use through
``app.dependency_overrides``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


def test_module_imports_cleanly() -> None:
    """The dependency factory should import without side effects."""

    from fief.dependencies import redis as redis_dep

    assert hasattr(redis_dep, "get_redis")
    assert hasattr(redis_dep, "close_redis")


def test_get_redis_returns_singleton_across_calls() -> None:
    """``get_redis()`` must hand back the same client on repeated calls."""

    from fief.dependencies import redis as redis_dep

    # Reset any module-level state captured from earlier tests.
    redis_dep._client = None  # type: ignore[attr-defined]

    first = redis_dep.get_redis()
    second = redis_dep.get_redis()

    assert first is second


@pytest.mark.asyncio
async def test_close_redis_closes_pool_and_resets_singleton() -> None:
    """``close_redis()`` should aclose the pool, then a subsequent
    ``get_redis()`` must return a *fresh* instance (not the closed one)."""

    from fief.dependencies import redis as redis_dep

    redis_dep._client = None  # type: ignore[attr-defined]

    fake_client = AsyncMock()
    fake_client.aclose = AsyncMock(return_value=None)

    with patch.object(redis_dep, "_build_client", return_value=fake_client):
        first = redis_dep.get_redis()
        assert first is fake_client

        await redis_dep.close_redis()

        fake_client.aclose.assert_awaited_once()

        # After close, the singleton has been cleared, so the next
        # ``get_redis()`` should build a brand-new client.
        new_client = AsyncMock()
        with patch.object(redis_dep, "_build_client", return_value=new_client):
            second = redis_dep.get_redis()

        assert second is not first


@pytest.mark.asyncio
async def test_close_redis_is_safe_when_uninitialized() -> None:
    """Calling ``close_redis()`` before any ``get_redis()`` must not error."""

    from fief.dependencies import redis as redis_dep

    redis_dep._client = None  # type: ignore[attr-defined]

    # Should be a no-op.
    await redis_dep.close_redis()


def test_fakeredis_can_back_the_dependency_in_app_overrides() -> None:
    """Documenting the test pattern: ``fakeredis.aioredis.FakeRedis`` is
    a drop-in replacement for the real client and is what consumers
    install via ``app.dependency_overrides[get_redis]``."""

    import fakeredis.aioredis

    fake = fakeredis.aioredis.FakeRedis()
    # The mere fact that this constructs without contacting a server
    # is what tests rely on. We don't assert anything fancier.
    assert fake is not None
