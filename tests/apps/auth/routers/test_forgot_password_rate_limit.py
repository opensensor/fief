"""Integration tests for SEC-1 T12 rate limiting on /forgot-password.

The route under test is ``POST /forgot`` in
:mod:`fief.apps.auth.routers.reset`. The handler already returns identical
responses for known and unknown emails (enumeration parity, verified in
``reset.py:40-49``). T12 layers two sliding-window rate limits on top:

* Per-IP throttle: ``settings.rate_limit_forgot_per_ip_per_min`` (default 10
  requests / minute / IP).
* Per-email throttle: ``settings.rate_limit_forgot_per_email_per_hour``
  (default 3 requests / hour / email).

When **either** rate limit is exceeded, the handler MUST:

1. Audit ``USER_RATE_LIMIT_EXCEEDED`` with ``extra={"scope": "forgot",
   "key_hash": <16-char sha256 prefix>, "endpoint": "/forgot-password",
   "client_ip": <raw IP>}``. ``key_hash`` is the SHA-256 hex digest of the
   bucket key (the IP or the normalised email) truncated to 16 chars so a
   support engineer can correlate two log lines reporting the same bucket
   without ever seeing a raw email.
2. Return the SAME response shape the existing successful submit returns
   ("Check your inbox..." page) — parity beats a strict 429 here, because
   surfacing "you are rate-limited" would itself be an attacker oracle.

When ``settings.rate_limit_enabled`` is ``False`` the rate-limit checks
are skipped entirely (kill switch).

Test harness notes
------------------

* The Redis dependency is overridden to a fresh ``fakeredis.aioredis.FakeRedis``
  per-test so buckets do not bleed between cases.
* The audit logger dependency is overridden to a ``MagicMock`` wrapping a
  real :class:`AuditLogger` so we can introspect every call.
* We use ``test_client_auth_csrf`` (existing fixture) which already wires
  the CSRF cookie; we do NOT override ``get_user_manager`` because the
  rate-limit checks happen before any DB lookup, so the existing test data
  is sufficient.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import fakeredis.aioredis
import httpx
import pytest
from fastapi import status

from fief.apps import auth_app
from fief.dependencies.logger import get_audit_logger
from fief.dependencies.redis import get_redis
from fief.logger import AuditLogger, logger as loguru_logger
from fief.models import AuditLogMessage
from fief.settings import settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_key(key: str) -> str:
    """Mirror the production ``_hash_key`` helper exactly so we can assert
    on the audit log's ``key_hash`` field deterministically."""

    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _audit_calls_for(
    mock: MagicMock, message: AuditLogMessage
) -> list:
    """Return every call to ``mock`` whose first positional arg is ``message``."""

    return [
        call
        for call in mock.call_args_list
        if call.args and call.args[0] is message
    ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis() -> fakeredis.aioredis.FakeRedis:
    """Fresh fakeredis instance — no cross-test bleed."""

    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    """``MagicMock`` wrapping a real :class:`AuditLogger`.

    The mock is wired into the ``auth_app`` so the route under test sees
    this exact instance. ``wraps`` keeps the underlying loguru calls
    firing; assertions go through ``call_args_list``.
    """

    real = AuditLogger(loguru_logger)
    mock = MagicMock(spec=AuditLogger, wraps=real)
    mock.admin_user_id = real.admin_user_id
    mock.admin_api_key_id = real.admin_api_key_id
    return mock


@pytest.fixture
def _override_forgot_deps(
    fake_redis: fakeredis.aioredis.FakeRedis,
    captured_audit_logger: MagicMock,
    test_client_auth_csrf: httpx.AsyncClient,
):
    """Splice fakeredis + captured audit logger into ``auth_app``.

    Depends on ``test_client_auth_csrf`` so the override happens AFTER the
    test client generator has reset ``auth_app.dependency_overrides``
    (it does so for every test) — otherwise our overrides would be wiped
    before the request is issued.
    """

    auth_app.dependency_overrides[get_redis] = lambda: fake_redis
    auth_app.dependency_overrides[get_audit_logger] = (
        lambda: captured_audit_logger
    )
    try:
        yield
    finally:
        auth_app.dependency_overrides.pop(get_redis, None)
        auth_app.dependency_overrides.pop(get_audit_logger, None)


@pytest.fixture
def _pin_rate_limit_settings(monkeypatch: pytest.MonkeyPatch):
    """Pin the rate-limit settings to the documented defaults so test
    arithmetic does not drift if the production defaults are tuned.

    Defaults from T2 of SEC-1:
        rate_limit_enabled = True
        rate_limit_forgot_per_ip_per_min = 10
        rate_limit_forgot_per_email_per_hour = 3
    """

    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_forgot_per_ip_per_min", 10)
    monkeypatch.setattr(settings, "rate_limit_forgot_per_email_per_hour", 3)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestForgotPasswordPerIpRateLimit:
    """The per-IP rate limit is the first gate: 10 calls/min/IP."""

    async def test_under_per_ip_limit_does_not_audit(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        captured_audit_logger: MagicMock,
        _override_forgot_deps: None,
        _pin_rate_limit_settings: None,
    ):
        """10 calls in a minute from the same IP must succeed without the
        rate-limit audit firing. Each call uses a DIFFERENT email so we
        are not exercising the per-email cap (3/hour) here."""

        for i in range(10):
            response = await test_client_auth_csrf.post(
                "/forgot",
                data={
                    "email": f"unknown_{i}@bretagne.duchy",
                    "csrf_token": csrf_token,
                },
            )
            assert response.status_code == status.HTTP_200_OK, (
                f"Iteration {i}: expected 200, got {response.status_code} "
                f"body={response.text[:200]}"
            )

        # No rate-limit audit emitted under the cap.
        assert _audit_calls_for(
            captured_audit_logger, AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        ) == []

    async def test_over_per_ip_limit_audits_but_returns_same_response(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        captured_audit_logger: MagicMock,
        _override_forgot_deps: None,
        _pin_rate_limit_settings: None,
    ):
        """The 11th call from the same IP within a minute must:

        - still return 200 (parity with the success page),
        - audit ``USER_RATE_LIMIT_EXCEEDED`` with ``scope="forgot"``.
        """

        # Saturate the per-IP cap with 10 unique emails so only the IP
        # bucket fills up.
        for i in range(10):
            response = await test_client_auth_csrf.post(
                "/forgot",
                data={
                    "email": f"unknown_{i}@bretagne.duchy",
                    "csrf_token": csrf_token,
                },
            )
            assert response.status_code == status.HTTP_200_OK

        # 11th call: still under the per-email cap (different email each
        # time), but over the per-IP cap.
        response = await test_client_auth_csrf.post(
            "/forgot",
            data={
                "email": "unknown_overflow@bretagne.duchy",
                "csrf_token": csrf_token,
            },
        )

        # Parity: same status as the existing success page.
        assert response.status_code == status.HTTP_200_OK
        # Body must NOT leak any rate-limit terminology.
        body_lower = response.text.lower()
        for forbidden in ("rate", "throttle", "lockout"):
            assert forbidden not in body_lower, (
                f"Throttled response leaked the word {forbidden!r} in body"
            )

        # Audit log fires exactly once (only the 11th call breaches).
        rl_calls = _audit_calls_for(
            captured_audit_logger, AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        )
        assert len(rl_calls) == 1, (
            f"Expected 1 rate-limit audit, got {len(rl_calls)}"
        )

        kwargs = rl_calls[0].kwargs
        extra = kwargs.get("extra", {})
        assert extra.get("scope") == "forgot"
        assert extra.get("endpoint") == "/forgot-password"
        # ``client_ip`` must be present (raw IP for forensics).
        assert "client_ip" in extra
        # ``key_hash`` must be present and must NOT be the raw key.
        assert "key_hash" in extra
        assert "@" not in extra["key_hash"]
        # Hash format: 16-char hex prefix.
        assert len(extra["key_hash"]) == 16
        int(extra["key_hash"], 16)  # raises if not hex


@pytest.mark.asyncio
class TestForgotPasswordPerEmailRateLimit:
    """The per-email rate limit is the second gate: 3 calls/hour/email."""

    async def test_under_per_email_limit_does_not_audit(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        captured_audit_logger: MagicMock,
        _override_forgot_deps: None,
        _pin_rate_limit_settings: None,
    ):
        """3 calls/hour for the same email must succeed without auditing."""

        for _ in range(3):
            response = await test_client_auth_csrf.post(
                "/forgot",
                data={
                    "email": "anne@bretagne.duchy",
                    "csrf_token": csrf_token,
                },
            )
            assert response.status_code == status.HTTP_200_OK

        assert _audit_calls_for(
            captured_audit_logger, AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        ) == []

    async def test_over_per_email_limit_audits_with_email_hash(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        captured_audit_logger: MagicMock,
        _override_forgot_deps: None,
        _pin_rate_limit_settings: None,
    ):
        """The 4th call for the same email within an hour must:

        - return 200 (parity),
        - audit ``USER_RATE_LIMIT_EXCEEDED`` with ``scope="forgot"`` and
          ``key_hash`` matching ``_hash_key(email_normalized)`` for the
          per-email breach.
        """

        email = "Anne@Bretagne.Duchy"  # mixed case to exercise normalisation
        email_normalized = email.strip().lower()

        for _ in range(3):
            response = await test_client_auth_csrf.post(
                "/forgot",
                data={"email": email, "csrf_token": csrf_token},
            )
            assert response.status_code == status.HTTP_200_OK

        # 4th call breaches the per-email cap.
        response = await test_client_auth_csrf.post(
            "/forgot",
            data={"email": email, "csrf_token": csrf_token},
        )
        assert response.status_code == status.HTTP_200_OK

        rl_calls = _audit_calls_for(
            captured_audit_logger, AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        )
        assert len(rl_calls) == 1

        # The breach is on the per-email bucket, so the audit's key_hash
        # must match the hash of the *normalised* email.
        kwargs = rl_calls[0].kwargs
        extra = kwargs.get("extra", {})
        assert extra.get("scope") == "forgot"
        assert extra.get("key_hash") == _hash_key(email_normalized)


@pytest.mark.asyncio
class TestForgotPasswordExistingBehaviourPreserved:
    """Within the rate-limit caps, the existing handler logic must be
    untouched: the user-manager.forgot_password call still fires for known
    emails, and the success message still renders for unknown ones."""

    async def test_known_email_under_limit_still_dispatches_email(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        send_task_mock: MagicMock,
        _override_forgot_deps: None,
        _pin_rate_limit_settings: None,
    ):
        """A known email under the cap still triggers the password-reset
        task — proving the rate-limit gate did not short-circuit the
        existing flow on the happy path."""

        # ``test_data["users"]["regular"]`` is ``anne@bretagne.duchy`` per
        # ``tests/data.py``; we don't need to import it explicitly because
        # the test_client_auth_csrf fixture already loaded the test data.
        response = await test_client_auth_csrf.post(
            "/forgot",
            data={"email": "anne@bretagne.duchy", "csrf_token": csrf_token},
        )

        assert response.status_code == status.HTTP_200_OK
        # The reset-password dramatiq actor must have been enqueued.
        assert send_task_mock.called, (
            "Existing forgot-password flow was suppressed by the new "
            "rate-limit gate; the password-reset task should still fire."
        )

    async def test_kill_switch_disables_rate_limit_entirely(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        captured_audit_logger: MagicMock,
        _override_forgot_deps: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """When ``settings.rate_limit_enabled is False`` the gate is a
        no-op even past 10 calls/IP. No audit log, no throttling."""

        monkeypatch.setattr(settings, "rate_limit_enabled", False)
        monkeypatch.setattr(settings, "rate_limit_forgot_per_ip_per_min", 10)
        monkeypatch.setattr(
            settings, "rate_limit_forgot_per_email_per_hour", 3
        )

        # 12 calls > the per-IP cap; with the kill switch off, all pass.
        for i in range(12):
            response = await test_client_auth_csrf.post(
                "/forgot",
                data={
                    "email": f"unknown_{i}@bretagne.duchy",
                    "csrf_token": csrf_token,
                },
            )
            assert response.status_code == status.HTTP_200_OK

        # No rate-limit audit emitted.
        assert _audit_calls_for(
            captured_audit_logger, AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        ) == []
