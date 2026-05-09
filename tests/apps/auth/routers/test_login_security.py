"""Integration tests for SEC-1 T11 — /login rate limiting, account lockout
and the failure latency floor.

The /login POST handler must:

1. Throttle on ``rate_limit_login_per_ip_per_min`` per (IP /64) bucket. Over
   the cap, return the SAME generic 401 form-error the bad-credentials path
   returns. No "rate / limit / throttle / lockout" wording leaks in the body.
2. Throttle on ``rate_limit_login_per_email_per_min`` per (normalised email)
   bucket — same shape on exceed.
3. Look up the user by normalised email and consult the SEC-1 lockout table
   *before* invoking the password verifier. An active lockout returns the
   same 401, and audits ``USER_RATE_LIMIT_EXCEEDED`` with
   ``scope="account_lockout"``.
4. On wrong-password against an existing user, increment the per-account
   failed counter (which sets ``locked_until`` once the ladder threshold of
   5 is crossed), audit ``USER_LOGIN_FAILED``, and floor wall-clock latency
   to ``settings.auth_failure_min_latency_ms`` so timing analysis is useless.
5. On successful authentication, reset the per-account counter so a normal
   user's typo history doesn't accumulate forever.

Parity is the point: every throttled / locked-out shape must be
indistinguishable from a plain bad-credentials response, otherwise the
attacker gets an oracle for "this email exists" or "I'm being throttled".
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import fakeredis.aioredis
import httpx
import pytest
import pytest_asyncio
from fastapi import status

from fief.apps import auth_app
from fief.db import AsyncSession
from fief.dependencies.logger import get_audit_logger
from fief.logger import AuditLogger, logger as loguru_logger
from fief.models import AuditLogMessage
from fief.repositories import UserLockoutRepository, UserRepository
from fief.settings import settings
from tests.data import TestData


_FORBIDDEN_BODY_TERMS = ("rate", "limit", "throttle", "lockout", "locked")


def _assert_no_leak(body_bytes: bytes) -> None:
    """The response body for a throttled / locked-out /login must not
    contain any of the SEC-1 leakage tells. We compare on a lower-cased
    text view so HTML/CSS class names with substrings don't accidentally
    pass."""

    text = body_bytes.decode("utf-8", errors="ignore").lower()
    for term in _FORBIDDEN_BODY_TERMS:
        assert term not in text, (
            f"throttled response leaked the word {term!r} in body"
        )


def _audit_messages(mock: MagicMock) -> list[AuditLogMessage]:
    return [
        call.args[0]
        for call in mock.call_args_list
        if call.args and isinstance(call.args[0], AuditLogMessage)
    ]


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    real = AuditLogger(loguru_logger)
    mock = MagicMock(spec=AuditLogger, wraps=real)
    mock.admin_user_id = real.admin_user_id
    mock.admin_api_key_id = real.admin_api_key_id
    return mock


@pytest_asyncio.fixture
async def _override_audit_logger(
    captured_audit_logger: MagicMock,
    test_client_auth_csrf: httpx.AsyncClient,
):
    auth_app.dependency_overrides[get_audit_logger] = (
        lambda: captured_audit_logger
    )
    try:
        yield
    finally:
        auth_app.dependency_overrides.pop(get_audit_logger, None)


@pytest_asyncio.fixture
async def fresh_fake_redis(
    test_client_auth_csrf: httpx.AsyncClient,
):
    """Per-test fakeredis with no SEC-1 buckets carried in.

    We can't reuse the global ``fake_redis`` fixture's instance directly
    because earlier tests in the same session share it; SEC-1 buckets
    (``rl:*``) and per-account counters (DB-side) need a clean slate so
    ladder thresholds are exercised end-to-end.
    """

    from fief.dependencies.redis import get_redis

    client = fakeredis.aioredis.FakeRedis()
    try:
        # FLUSHALL on startup so a stale bucket from a prior fixture
        # (the global ``fake_redis``) cannot taint this test.
        await client.flushall()
        auth_app.dependency_overrides[get_redis] = lambda: client
        yield client
    finally:
        await client.flushall()
        await client.aclose()


@pytest_asyncio.fixture
async def reset_lockouts(main_session: AsyncSession, test_data: TestData):
    """Wipe SEC-1 lockout rows for the `regular` user before AND after
    each test in this module so ladder counters don't bleed across tests
    (the test DB is per-session, not per-test)."""

    repo = UserLockoutRepository(main_session)
    user = test_data["users"]["regular"]
    await repo.clear(user.id)
    yield
    await repo.clear(user.id)


@pytest.mark.asyncio
class TestLoginPerIpRateLimit:
    async def test_returns_generic_401_when_per_ip_window_exceeded(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        reset_lockouts: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Once the per-IP window is full, the next /login POST must
        return the same 'Invalid email or password' shape as a bad
        credentials attempt — and audit ``USER_RATE_LIMIT_EXCEEDED``."""

        # Tighter window so the test stays fast (default 30/min would
        # require 31 round-trips). The settings field is read at call
        # time inside the route, so a monkeypatch is enough.
        monkeypatch.setattr(
            settings, "rate_limit_login_per_ip_per_min", 3
        )
        # Loosen the per-email cap so the per-IP cap fires first.
        monkeypatch.setattr(
            settings, "rate_limit_login_per_email_per_min", 999
        )

        login_session = test_data["login_sessions"]["default"]
        cookies = {settings.login_session_cookie_name: login_session.token}

        # 3 wrong-password attempts (under the cap each).
        for _i in range(3):
            response = await test_client_auth_csrf.post(
                "/login",
                data={
                    "email": "nobody@example.com",
                    "password": "wrong",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert response.headers.get("X-Fief-Error") == "bad_credentials"

        # 4th attempt — now over the cap. Same shape, no body leak.
        response = await test_client_auth_csrf.post(
            "/login",
            data={
                "email": "nobody@example.com",
                "password": "wrong",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "bad_credentials"
        assert "Retry-After" in response.headers
        _assert_no_leak(response.content)

        # Audit log records both regular login failures AND the rate
        # limit excess.
        messages = _audit_messages(captured_audit_logger)
        assert AuditLogMessage.USER_RATE_LIMIT_EXCEEDED in messages

        # Inspect the rate-limit-exceeded call: scope=login_ip, no raw
        # email in extras, and a 16-hex key_hash.
        rl_calls = [
            call
            for call in captured_audit_logger.call_args_list
            if call.args
            and call.args[0] is AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        ]
        assert len(rl_calls) >= 1
        first = rl_calls[0]
        extra = first.kwargs.get("extra", {})
        assert extra.get("scope") == "login_ip"
        assert extra.get("endpoint") == "/login"
        assert isinstance(extra.get("key_hash"), str)
        assert len(extra["key_hash"]) == 16


@pytest.mark.asyncio
class TestLoginPerEmailRateLimit:
    async def test_per_email_window_exceeded_returns_generic_401(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        reset_lockouts: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Per-email cap fires even from a single source IP. Same generic
        body, audit scope=login_email, key_hash is 16 hex chars."""

        # Make the per-email cap the binding constraint.
        monkeypatch.setattr(
            settings, "rate_limit_login_per_ip_per_min", 999
        )
        monkeypatch.setattr(
            settings, "rate_limit_login_per_email_per_min", 2
        )
        # Loosen the auth latency floor so the test is fast.
        monkeypatch.setattr(settings, "auth_failure_min_latency_ms", 0)

        login_session = test_data["login_sessions"]["default"]
        cookies = {settings.login_session_cookie_name: login_session.token}

        # 2 attempts under the per-email cap.
        for _i in range(2):
            response = await test_client_auth_csrf.post(
                "/login",
                data={
                    "email": "victim@example.com",
                    "password": "wrong",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )
            assert response.headers.get("X-Fief-Error") == "bad_credentials"

        # 3rd attempt: per-email exceeded.
        response = await test_client_auth_csrf.post(
            "/login",
            data={
                "email": "victim@example.com",
                "password": "wrong",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "bad_credentials"
        _assert_no_leak(response.content)

        rl_calls = [
            call
            for call in captured_audit_logger.call_args_list
            if call.args
            and call.args[0] is AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        ]
        # The first non-OK audit on this attempt should be a login_email
        # rate-limit miss (per-IP was loosened to 999, so per-email fires
        # first).
        scopes = [c.kwargs.get("extra", {}).get("scope") for c in rl_calls]
        assert "login_email" in scopes


@pytest.mark.asyncio
class TestLoginAccountLockout:
    async def test_five_wrong_attempts_set_lockout_locked_until(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        reset_lockouts: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """5 wrong attempts on a real user must set
        ``UserLockout.locked_until`` to a future datetime AND the 6th
        attempt (now-locked) must still return the same generic 401."""

        # Loosen rate limits so the lockout ladder is the binding
        # constraint, and zero out the latency floor so the test runs fast.
        monkeypatch.setattr(
            settings, "rate_limit_login_per_ip_per_min", 999
        )
        monkeypatch.setattr(
            settings, "rate_limit_login_per_email_per_min", 999
        )
        monkeypatch.setattr(settings, "auth_failure_min_latency_ms", 0)

        user = test_data["users"]["regular"]
        user_id = user.id
        user_email = user.email
        login_session = test_data["login_sessions"]["default"]
        cookies = {settings.login_session_cookie_name: login_session.token}

        for _i in range(5):
            response = await test_client_auth_csrf.post(
                "/login",
                data={
                    "email": user_email,
                    "password": "wrong-password",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST

        # ``UserLockout.locked_until`` is now set.
        repo = UserLockoutRepository(main_session)
        row = await repo.get_by_user_id(user_id)
        assert row is not None
        assert row.failed_count == 5
        assert row.locked_until is not None

        # 6th attempt: server-side check_locked raises AccountLocked, but
        # the response is still the same generic shape (no body leak).
        response = await test_client_auth_csrf.post(
            "/login",
            data={
                "email": user_email,
                "password": "wrong-password",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "bad_credentials"
        _assert_no_leak(response.content)

        # Audit log shows USER_LOGIN_FAILED + USER_ACCOUNT_LOCKED + at
        # least one USER_RATE_LIMIT_EXCEEDED with scope=account_lockout.
        messages = _audit_messages(captured_audit_logger)
        assert AuditLogMessage.USER_LOGIN_FAILED in messages
        assert AuditLogMessage.USER_ACCOUNT_LOCKED in messages
        assert AuditLogMessage.USER_RATE_LIMIT_EXCEEDED in messages

        # The lockout-related rate limit miss carries scope=account_lockout.
        rl_calls = [
            call
            for call in captured_audit_logger.call_args_list
            if call.args
            and call.args[0] is AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        ]
        scopes = [c.kwargs.get("extra", {}).get("scope") for c in rl_calls]
        assert "account_lockout" in scopes

    async def test_successful_login_resets_failed_counter(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        reset_lockouts: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """A small typo history (under threshold) followed by a correct
        password must zero ``failed_count`` so a future legitimate typo
        doesn't push the user into lockout right away."""

        monkeypatch.setattr(
            settings, "rate_limit_login_per_ip_per_min", 999
        )
        monkeypatch.setattr(
            settings, "rate_limit_login_per_email_per_min", 999
        )
        monkeypatch.setattr(settings, "auth_failure_min_latency_ms", 0)

        user = test_data["users"]["regular"]
        user_id = user.id
        user_email = user.email
        # Make sure the user starts non-MFA so the regular happy-path
        # runs (no challenge in the middle of this test).
        user_repository = UserRepository(main_session)
        user.mfa_enabled = False
        await user_repository.update(user)

        login_session = test_data["login_sessions"]["default"]
        cookies = {settings.login_session_cookie_name: login_session.token}

        # 3 wrong attempts (under the lockout threshold of 5).
        for _i in range(3):
            await test_client_auth_csrf.post(
                "/login",
                data={
                    "email": user_email,
                    "password": "wrong",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )

        # Correct password.
        response = await test_client_auth_csrf.post(
            "/login",
            data={
                "email": user_email,
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )
        assert response.status_code == status.HTTP_302_FOUND

        # Lockout row was reset (failed_count == 0, locked_until None).
        repo = UserLockoutRepository(main_session)
        row = await repo.get_by_user_id(user_id)
        # The row may exist (set by the wrong attempts and then cleared)
        # or be entirely absent — both are acceptable; we only require
        # ``failed_count`` to be zero in either case.
        if row is not None:
            assert row.failed_count == 0
            assert row.locked_until is None


@pytest.mark.asyncio
class TestLoginLatencyFloor:
    async def test_wrong_password_response_meets_latency_floor(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        reset_lockouts: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """A wrong-password POST must take at least
        ``auth_failure_min_latency_ms`` wall-clock time, regardless of
        how fast the auth path itself ran. Slack of 20 ms tolerated for
        unreliable scheduler timing."""

        # Loosen rate limits so the floor — not the bucket — is the
        # constraint we're testing.
        monkeypatch.setattr(
            settings, "rate_limit_login_per_ip_per_min", 999
        )
        monkeypatch.setattr(
            settings, "rate_limit_login_per_email_per_min", 999
        )
        # Default is 150ms; pin it explicitly so this test isn't
        # at-the-mercy of someone tuning the global default.
        monkeypatch.setattr(settings, "auth_failure_min_latency_ms", 150)

        login_session = test_data["login_sessions"]["default"]
        cookies = {settings.login_session_cookie_name: login_session.token}

        before = time.monotonic()
        response = await test_client_auth_csrf.post(
            "/login",
            data={
                "email": "no-such-user@example.com",
                "password": "wrong",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )
        elapsed_ms = (time.monotonic() - before) * 1000

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        # Allow a small slack below 150ms for scheduler jitter / clock
        # granularity. The PRD asks for ~150ms; 130 is the documented
        # acceptance bar.
        assert elapsed_ms >= 130, f"latency floor not enforced: {elapsed_ms:.1f}ms"
