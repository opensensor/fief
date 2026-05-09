"""Sliding-window rate limiter backed by Redis sorted sets (SEC-1 T9).

Each ``(scope, key)`` tuple gets its own Redis ZSET at
``rl:{scope}:{key}``. Entries are timestamped events in the window; on
every call we:

1. Drop entries older than ``now - per_seconds`` (the sliding edge).
2. Add the current request as a fresh ZSET member (UUID so duplicate
   timestamps don't dedup via ZADD's NX-on-equal-score behaviour).
3. Read ``ZCARD`` to get the post-add count.
4. Re-arm ``EXPIRE`` so an idle bucket eventually self-evicts.

All four commands are sent in a single ``MULTI/EXEC`` pipeline so the
count returned is consistent with the eviction we just performed; the
window cannot grow under our feet between steps 2 and 3.

**Fail-open design.** The whole point of this service is bot mitigation:
on a Redis outage we'd rather let real users through (and tolerate a
short attack window) than lock everyone out. Any ``RedisError`` is
swallowed, logged at WARNING level, and the call returns ``0`` (treated
as "under limit" by every caller). This matches the failure mode
documented by Auth0 and Cloudflare for their own rate limiters.

**Key namespace.** ``rl:`` is reserved for SEC-1 alone. Dramatiq uses
``dramatiq:*`` (different prefix, no collision); future security
features should pick their own prefix rather than crowding ``rl:``.

**Privacy.** The ``key`` argument may be a raw email or IP. We deliberately
do **not** include the key in fail-open log lines — it would put PII in
ops logs. Audit-log call sites (T17) hash the key before recording it.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

import redis.asyncio
from redis import RedisError

__all__ = [
    "RateLimitExceeded",
    "RateLimitWindow",
    "RateLimiter",
]

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when a ``RateLimiter.check`` call would push the bucket
    over its ``max_count``. ``retry_after_seconds`` is a floor — the
    caller can use it for the ``Retry-After`` HTTP header."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Rate limit exceeded; retry in {retry_after_seconds}s")


@dataclass(frozen=True)
class RateLimitWindow:
    """Immutable ``(max_count, per_seconds)`` policy. Frozen so a route
    handler cannot mutate a shared policy in flight."""

    max_count: int
    per_seconds: int


class RateLimiter:
    """Sliding window log rate limiter via Redis sorted sets.

    Construct one per request from :func:`fief.dependencies.security.get_rate_limiter`
    or once per process if you have your own Redis client. The instance
    is stateless; all state lives in Redis under ``rl:{scope}:{key}``.
    """

    def __init__(self, redis: redis.asyncio.Redis):
        self.redis = redis

    async def check(
        self,
        *,
        scope: str,
        key: str,
        window: RateLimitWindow,
    ) -> int:
        """Record a single hit and return the post-add count.

        Raises :class:`RateLimitExceeded` (with a positive
        ``retry_after_seconds``) when the post-add count exceeds
        ``window.max_count``. Returns ``0`` on any ``RedisError``
        (fail-open) so callers proceed; a structured warning is logged so
        ops can correlate the outage.
        """

        bucket_key = f"rl:{scope}:{key}".encode()
        now = time.time()
        cutoff = now - window.per_seconds
        # ZADD members must be unique, otherwise a second hit at the same
        # ``now`` (clock granularity quirk, or a fast retry) would silently
        # update the existing member's score instead of adding a new
        # row — meaning ``ZCARD`` would under-count. A random UUID avoids
        # the dedup entirely.
        member = uuid.uuid4().hex.encode()

        try:
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(bucket_key, 0, cutoff)
                pipe.zadd(bucket_key, {member: now})
                pipe.zcard(bucket_key)
                pipe.expire(bucket_key, window.per_seconds)
                _, _, count, _ = await pipe.execute()
        except RedisError as exc:
            # Deliberately do NOT log the raw ``key`` here: it may be a
            # plaintext email address. Audit-log call sites (T17) are
            # responsible for hashing keys before recording them; the
            # operational warning here is just enough for ops to spot a
            # Redis outage.
            logger.warning(
                "rate_limiter_fail_open",
                extra={
                    "scope": scope,
                    "exc_class": type(exc).__name__,
                },
            )
            return 0  # fail open

        if count > window.max_count:
            # The oldest entry in the bucket sets the floor for the
            # ``Retry-After`` header: it's the entry that, once it falls
            # off the sliding edge, will free up a slot.
            oldest = await self.redis.zrange(
                bucket_key, 0, 0, withscores=True
            )
            if oldest:
                _member, oldest_score = oldest[0]
                retry_after = max(
                    1, int((oldest_score + window.per_seconds) - now)
                )
            else:
                # Unexpected — we just ZADD'd a member, so the bucket
                # cannot be empty. Degrade to the full window length
                # rather than crashing.
                retry_after = window.per_seconds
            raise RateLimitExceeded(retry_after)

        return int(count)
