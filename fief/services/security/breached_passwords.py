"""HaveIBeenPwned k-anonymity password check (SEC-2 T6).

This service is the network-side half of SEC-2's layered defence: every
password-set attempt that has already passed the local zxcvbn validator
is k-anonymously checked against HIBP's `Pwned Passwords range API
<https://haveibeenpwned.com/API/v3#PwnedPasswords>`_. Only the first 5
hex chars of the password's SHA-1 leave our process; the password and
even the full hash never do.

Caching
-------
Each prefix's response is cached in Redis under
``bpc:<5-char-prefix>`` for ``settings.breached_password_cache_ttl_s``
(24 h by default). The ``bpc:`` namespace mirrors SEC-1's ``rl:``
reservation — there is no collision with Dramatiq's ``dramatiq:*`` queue
keys nor with the rate-limiter's sorted sets. With even modest traffic
the cache hit rate climbs above 95 % within hours of deploy, which
matters because the free HIBP range API rate-limits per source IP.

Fail-OPEN posture
-----------------
The whole point of the check is layered defence; if HIBP is unavailable
(timeout, ``RequestError``, 429 rate-limit, any non-2xx, malformed body)
we deliberately let the password through rather than block every
password change in production. zxcvbn already ran at the validator
layer and rejected the obvious weak ones. Each fail-open path emits an
``USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN`` audit log so ops can spot a
sustained outage and decide whether to flip the kill switch.

Padding
-------
HIBP supports an opt-in ``Add-Padding: true`` header that pads each
response with up to 1000 random suffixes carrying ``count=0`` so the
response size doesn't leak prefix popularity. We send the header on
every request and filter padding rows out before caching, both to keep
Redis memory tight and to make the cached payload reflect reality.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING

import httpx
import redis.asyncio
from redis import RedisError

from fief.logger import AuditLogger
from fief.models.audit_log import AuditLogMessage
from fief.settings import settings

if TYPE_CHECKING:
    from fief.models import Tenant

__all__ = ["BreachedPasswordChecker"]

logger = logging.getLogger(__name__)


class BreachedPasswordChecker:
    """k-anonymity HIBP password check with Redis prefix cache.

    The service is stateless apart from its three dependency handles
    (Redis, httpx client, audit logger), so a fresh instance per request
    is fine — see :func:`fief.dependencies.security.get_breached_password_checker`.
    """

    CACHE_KEY_PREFIX = "bpc:"

    def __init__(
        self,
        redis: redis.asyncio.Redis,
        http_client: httpx.AsyncClient,
        audit_logger: AuditLogger,
    ):
        self.redis = redis
        self.http_client = http_client
        self.audit_logger = audit_logger

    async def is_breached(
        self, password: str, tenant: "Tenant | None"
    ) -> bool:
        """Return ``True`` iff the password's SHA-1 suffix appears in
        HIBP with a count >= the effective threshold.

        The effective threshold is the tenant's
        ``breached_password_threshold`` if set, else
        ``settings.breached_password_default_threshold``. A threshold of
        1 means "reject any sighting"; higher values let leniency-minded
        tenants accept passwords that have only been seen a handful of
        times.

        Returns ``False`` when the global kill switch
        (``settings.breached_password_check_enabled``) is off, on any
        HIBP unavailability (fail-open), or when the suffix simply isn't
        in the returned set.
        """

        if not settings.breached_password_check_enabled:
            return False

        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        suffixes = await self._fetch_prefix(prefix)
        count = suffixes.get(suffix, 0)

        threshold = (
            tenant.breached_password_threshold
            if tenant is not None
            and tenant.breached_password_threshold is not None
            else settings.breached_password_default_threshold
        )
        return count >= threshold

    async def _fetch_prefix(self, prefix: str) -> dict[str, int]:
        """Return the ``{suffix: count}`` map for a given 5-char prefix.

        Tries the Redis cache first; on miss, calls HIBP and caches the
        parsed result. Returns ``{}`` (empty map → no breach
        identified) on any fail-open path so the caller's
        ``is_breached`` returns ``False``.
        """

        cache_key = f"{self.CACHE_KEY_PREFIX}{prefix}".encode()

        # 1. Try Redis cache first. The cache layer is best-effort: a
        # ``RedisError`` here just means we miss and re-fetch from HIBP.
        try:
            cached = await self.redis.get(cache_key)
        except RedisError:
            cached = None
        if cached is not None:
            try:
                return json.loads(cached)
            except (ValueError, TypeError):
                # Stale / corrupt cache row; fall through to refetch.
                pass

        # 2. Cache miss — call HIBP.
        url = f"{settings.breached_password_api_url}/{prefix}"
        try:
            response = await self.http_client.get(
                url,
                headers={
                    "User-Agent": settings.breached_password_user_agent,
                    # `Add-Padding` masks prefix popularity by padding the
                    # response with up to 1000 dummy `count=0` rows. We
                    # filter those out before caching.
                    "Add-Padding": "true",
                },
                timeout=httpx.Timeout(
                    settings.breached_password_timeout_ms / 1000.0
                ),
            )
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            self._fail_open("transport_error", type(exc).__name__)
            return {}

        # 429 has its own bucket so support can distinguish "HIBP is
        # throttling us" from "HIBP is broken" in audit log queries.
        if response.status_code == 429:
            self._fail_open("hibp_rate_limited", "429")
            return {}
        if not (200 <= response.status_code < 300):
            self._fail_open("hibp_non_2xx", str(response.status_code))
            return {}

        # 3. Parse text body.
        try:
            parsed = self._parse_body(response.text)
        except ValueError as exc:
            self._fail_open("malformed_body", str(exc))
            return {}

        # 4. Cache (best-effort). A Redis outage here doesn't block the
        # password set; we just take the cache miss next time.
        try:
            await self.redis.set(
                cache_key,
                json.dumps(parsed).encode(),
                ex=settings.breached_password_cache_ttl_s,
            )
        except RedisError:
            pass

        return parsed

    @staticmethod
    def _parse_body(text: str) -> dict[str, int]:
        """Parse an HIBP range body of ``SUFFIX:COUNT`` lines.

        Padding rows (``count=0``) are filtered so the cached payload
        reflects only real sightings — keeps Redis memory tight and
        prevents accidental hits on padding suffixes that happen to
        collide with a real password's hash.

        Raises :class:`ValueError` on any unparseable line. Callers
        treat that as a fail-open path.
        """

        result: dict[str, int] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                suffix, count_str = line.split(":")
            except ValueError as exc:
                raise ValueError(
                    f"unparseable HIBP line: {line[:32]!r}"
                ) from exc
            try:
                count = int(count_str)
            except ValueError as exc:
                raise ValueError(
                    f"non-int count in HIBP line: {line[:32]!r}"
                ) from exc
            if count > 0:
                result[suffix.upper()] = count
        return result

    def _fail_open(self, reason: str, exc_class: str) -> None:
        """Emit a structured fail-open log + audit-log entry.

        ``reason`` is one of: ``transport_error``, ``hibp_rate_limited``,
        ``hibp_non_2xx``, ``malformed_body``. ``exc_class`` carries the
        exception name (or HTTP status code for non-exception paths) for
        forensic correlation.
        """

        logger.warning(
            "breached_password_check_fail_open",
            extra={"reason": reason, "exc_class": exc_class},
        )
        self.audit_logger(
            AuditLogMessage.USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN,
            extra={"reason": reason, "exc_class": exc_class},
        )
