"""Async Redis client dependency for SEC-1.

Exposes a lazily-initialized module-level :class:`redis.asyncio.Redis`
client and a FastAPI-compatible :func:`get_redis` factory. The lifespan
in :mod:`fief.lifespan` invokes :func:`close_redis` on shutdown to
return connections cleanly to the pool.

The client is intentionally *separate* from the dramatiq broker
configured in :mod:`fief.tasks.base`. Dramatiq owns its own connection
pool for the message bus; this client is for application-level features
that need direct Redis access (rate limiting, login lockout
counters, etc.). Sharing them would be wrong: dramatiq's pool is sized
for queue traffic and decoded as bytes, while application use may want
finer control over decoding per-call.

Tests inject a ``fakeredis.aioredis.FakeRedis`` instance via
``app.dependency_overrides[get_redis] = lambda: fake`` (see
``tests/dependencies/test_redis_smoke.py``).
"""

from __future__ import annotations

import redis.asyncio as redis_asyncio

from fief.settings import settings

__all__ = ["get_redis", "close_redis"]


# Module-level singleton. Initialised on first call to ``get_redis()``
# and torn down by ``close_redis()`` (which also resets it to None so a
# subsequent call rebuilds the pool — useful for tests and for
# defensive shutdown ordering).
_client: redis_asyncio.Redis | None = None


def _build_client() -> redis_asyncio.Redis:
    """Construct a fresh async Redis client from settings.

    Factored out so tests can patch the constructor without monkey-
    patching ``redis.asyncio`` itself. ``decode_responses=False`` is
    explicit because rate-limiting and lockout code stores binary
    payloads (and ZADD members are random UUID bytes); callers that
    want strings call ``.decode()`` themselves.
    """

    return redis_asyncio.Redis.from_url(
        settings.redis_url,
        decode_responses=False,
    )


def get_redis() -> redis_asyncio.Redis:
    """Return the process-wide async Redis client, building it on first
    use. This is the FastAPI dependency consumed via ``Depends``."""

    global _client
    if _client is None:
        _client = _build_client()
    return _client


async def close_redis() -> None:
    """Close the pool on app shutdown. Safe to call when the client was
    never built (e.g. shutdown after a failed startup): in that case
    this is a no-op."""

    global _client
    if _client is None:
        return

    client = _client
    # Clear the singleton *before* awaiting close so a concurrent
    # ``get_redis()`` won't hand out an in-flight-closing client.
    _client = None
    await client.aclose()
