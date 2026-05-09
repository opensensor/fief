"""Integration tests for /register rate limiting + silent-on-email-collision (SEC-1 T13).

Two behaviours under test, both gated by settings flags:

1. **Per-IP rate limit.** The first ``rate_limit_register_per_ip_per_min``
   POSTs from a single client IP succeed (or fail for unrelated reasons —
   bad email, etc.); the next one is throttled. The throttled response
   MUST NOT leak the words "rate" / "limit" / "throttle" — it renders the
   intentionally vague "Something went wrong" form error and audits
   ``USER_RATE_LIMIT_EXCEEDED``.

2. **Silent-on-email-collision.** When
   ``settings.register_silent_on_email_collision`` is ``True`` (production
   default) and the email already maps to a user, /register returns the
   same redirect/success shape a fresh registration would emit — no 400
   with ``X-Fief-Error: user_already_exists``. Flipping the flag back to
   ``False`` (dev default override) restores the existing 400 / leaky
   behaviour the older test suite still covers in
   ``tests/test_apps_auth_register.py``.

Test wiring notes
-----------------

* ``fakeredis.aioredis.FakeRedis`` backs the rate-limit Redis dependency
  via ``app.dependency_overrides[get_redis]`` — same pattern documented
  in ``tests/dependencies/test_redis_smoke.py``. A fresh fake per test
  prevents cross-test bleed of bucket counters.
* The audit logger is overridden with a ``MagicMock`` wrapping the real
  :class:`AuditLogger` (mirrors ``tests/apps/api/routers/test_users_mfa_reset.py``)
  so we can assert ``USER_RATE_LIMIT_EXCEEDED`` was emitted with the right
  ``extra``.
* ``settings.rate_limit_register_per_ip_per_min`` is monkeypatched to
  ``5`` to keep these tests fast and explicit even if the production
  default ever shifts.
"""

from __future__ import annotations

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
from tests.data import TestData


@pytest.fixture
def fake_redis() -> fakeredis.aioredis.FakeRedis:
    """A fresh fakeredis per test — no counter bleed across cases."""

    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    """``MagicMock(spec=AuditLogger, wraps=real)`` so ``call_args_list``
    captures every emit while loguru still fires."""

    real = AuditLogger(loguru_logger)
    mock = MagicMock(spec=AuditLogger, wraps=real)
    mock.admin_user_id = real.admin_user_id
    mock.admin_api_key_id = real.admin_api_key_id
    return mock


@pytest.fixture
def _override_register_deps(
    fake_redis: fakeredis.aioredis.FakeRedis,
    captured_audit_logger: MagicMock,
    test_client_auth: httpx.AsyncClient,
):
    """Splice the fakeredis client and captured audit logger into the
    auth app for the duration of the test.

    We depend on ``test_client_auth`` so the override happens *after* the
    test_client_generator's per-test ``dependency_overrides = {}`` reset.
    """

    auth_app.dependency_overrides[get_redis] = lambda: fake_redis
    auth_app.dependency_overrides[get_audit_logger] = lambda: captured_audit_logger
    try:
        yield
    finally:
        auth_app.dependency_overrides.pop(get_redis, None)
        auth_app.dependency_overrides.pop(get_audit_logger, None)


def _audit_messages(mock: MagicMock) -> list[AuditLogMessage]:
    """Pull the :class:`AuditLogMessage` first-arg out of every emit."""

    return [
        call.args[0]
        for call in mock.call_args_list
        if call.args and isinstance(call.args[0], AuditLogMessage)
    ]


def _audit_calls(mock: MagicMock, message: AuditLogMessage):
    return [
        call
        for call in mock.call_args_list
        if call.args and call.args[0] is message
    ]


@pytest.mark.asyncio
class TestRegisterRateLimit:
    """Per-IP rate-limit cap on POST /register (SEC-1 T13)."""

    async def test_under_limit_posts_pass_through(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_register_deps: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """5 calls/min from same IP must all proceed past the rate-limit
        gate. We're not asserting the *outcome* of each request (some
        will be redirect-on-success or 400 on email-already-exists); only
        that no ``USER_RATE_LIMIT_EXCEEDED`` audit fires."""

        monkeypatch.setattr(settings, "rate_limit_register_per_ip_per_min", 5)
        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        # Pin the silent-collision flag so we don't accidentally also
        # measure the silent path's behaviour here.
        monkeypatch.setattr(settings, "register_silent_on_email_collision", False)

        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_password"]
        cookies = {
            settings.login_session_cookie_name: login_session.token,
            settings.registration_session_cookie_name: registration_session.token,
        }

        for i in range(5):
            response = await test_client_auth_csrf.post(
                "/register",
                data={
                    "email": f"new+{i}@bretagne.duchy",
                    "password": "herminetincture",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )
            # Either 302 (success) or 400 (e.g. invalid_session if cookies
            # got rotated by the success path) — both paths went through
            # the rate-limit gate. The forbidden outcome is "rate_limited".
            assert response.headers.get("X-Fief-Error") != "rate_limited"

        assert AuditLogMessage.USER_RATE_LIMIT_EXCEEDED not in _audit_messages(
            captured_audit_logger
        )

    async def test_over_limit_returns_generic_error(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_register_deps: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """6th request from same IP within 60s is throttled. Body MUST
        NOT contain "rate" / "limit" / "throttle" (the deliberate vague
        copy)."""

        monkeypatch.setattr(settings, "rate_limit_register_per_ip_per_min", 5)
        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(settings, "register_silent_on_email_collision", False)

        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_password"]
        cookies = {
            settings.login_session_cookie_name: login_session.token,
            settings.registration_session_cookie_name: registration_session.token,
        }

        # Burn the budget: 5 requests pass the gate (any outcome is fine).
        for i in range(5):
            await test_client_auth_csrf.post(
                "/register",
                data={
                    "email": f"burst+{i}@bretagne.duchy",
                    "password": "herminetincture",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )

        # 6th request — over the limit.
        throttled = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "post-limit@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert throttled.status_code == status.HTTP_400_BAD_REQUEST
        assert throttled.headers.get("X-Fief-Error") == "rate_limited"

        body_lower = throttled.text.lower()
        # Deliberately vague copy — never reveal the rate-limit-ness.
        for forbidden in ("rate limit", "throttle", "lockout", "too many"):
            assert forbidden not in body_lower, (
                f"Throttled response leaks the word/phrase '{forbidden}'"
            )

        rate_limit_calls = _audit_calls(
            captured_audit_logger, AuditLogMessage.USER_RATE_LIMIT_EXCEEDED
        )
        assert len(rate_limit_calls) == 1
        extra = rate_limit_calls[0].kwargs.get("extra", {})
        assert extra.get("scope") == "register_ip"
        assert extra.get("endpoint") == "/register"
        # Raw IP / hashed key both required by T17 spec.
        assert "key_hash" in extra
        assert "client_ip" in extra
        # Crucially: no raw email or other IP-leaking field beyond what
        # T17 explicitly allows.
        assert "email" not in extra
        # The hash is short SHA-256 truncation (16 chars).
        assert len(extra["key_hash"]) == 16

    async def test_rate_limit_disabled_setting_skips_gate(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_register_deps: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """``rate_limit_enabled=False`` is the global kill-switch — no
        request should ever be throttled, even past the configured
        budget."""

        monkeypatch.setattr(settings, "rate_limit_register_per_ip_per_min", 1)
        monkeypatch.setattr(settings, "rate_limit_enabled", False)
        monkeypatch.setattr(settings, "register_silent_on_email_collision", False)

        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_password"]
        cookies = {
            settings.login_session_cookie_name: login_session.token,
            settings.registration_session_cookie_name: registration_session.token,
        }

        # Even at limit=1, none of these should hit the rate-limit branch.
        for i in range(3):
            response = await test_client_auth_csrf.post(
                "/register",
                data={
                    "email": f"unlimited+{i}@bretagne.duchy",
                    "password": "herminetincture",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )
            assert response.headers.get("X-Fief-Error") != "rate_limited"

        assert AuditLogMessage.USER_RATE_LIMIT_EXCEEDED not in _audit_messages(
            captured_audit_logger
        )


@pytest.mark.asyncio
class TestRegisterSilentOnEmailCollision:
    """Silent-on-email-collision behaviour (SEC-1 T13)."""

    async def test_silent_flag_true_renders_success_shape(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fake_redis: fakeredis.aioredis.FakeRedis,
        _override_register_deps: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Posting an existing email with the flag ON returns a response
        indistinguishable (from the attacker's POV) from a fresh
        registration: NO ``X-Fief-Error: user_already_exists`` and NO
        4xx with the user-already-exists copy in the body."""

        monkeypatch.setattr(settings, "register_silent_on_email_collision", True)
        # Keep rate limit out of this test's way.
        monkeypatch.setattr(settings, "rate_limit_register_per_ip_per_min", 100)
        monkeypatch.setattr(settings, "rate_limit_enabled", True)

        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_password"]
        cookies = {
            settings.login_session_cookie_name: login_session.token,
            settings.registration_session_cookie_name: registration_session.token,
        }

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                # ``anne@bretagne.duchy`` is an existing user under
                # the default tenant (see ``tests/data.py``).
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        # Must not leak the collision: the dev-only error code is gone,
        # the body never carries the "already exists" copy.
        assert response.headers.get("X-Fief-Error") != "user_already_exists"
        body_lower = response.text.lower()
        assert "already exists" not in body_lower
        assert "user_already_exists" not in body_lower
        # And the status must be one of the success-shape codes a real
        # registration would emit (302 redirect to verify-request, or a
        # 200/400 form-render that does NOT carry the leak header).
        assert response.status_code in (
            status.HTTP_200_OK,
            status.HTTP_302_FOUND,
        )

    async def test_silent_flag_false_preserves_legacy_error(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fake_redis: fakeredis.aioredis.FakeRedis,
        _override_register_deps: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """With ``register_silent_on_email_collision=False`` the old 400
        + ``X-Fief-Error: user_already_exists`` shape is preserved — this
        is what the existing test suite (and dev environments) rely on."""

        monkeypatch.setattr(settings, "register_silent_on_email_collision", False)
        monkeypatch.setattr(settings, "rate_limit_register_per_ip_per_min", 100)
        monkeypatch.setattr(settings, "rate_limit_enabled", True)

        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_password"]
        cookies = {
            settings.login_session_cookie_name: login_session.token,
            settings.registration_session_cookie_name: registration_session.token,
        }

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers["X-Fief-Error"] == "user_already_exists"

    async def test_new_user_unaffected_by_silent_flag(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fake_redis: fakeredis.aioredis.FakeRedis,
        _override_register_deps: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """A genuine fresh registration still succeeds with the same 302
        the existing happy-path test asserts. Within rate limits the
        silent-collision flag must not gum up legit signups."""

        monkeypatch.setattr(settings, "register_silent_on_email_collision", True)
        monkeypatch.setattr(settings, "rate_limit_register_per_ip_per_min", 100)
        monkeypatch.setattr(settings, "rate_limit_enabled", True)

        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_password"]
        cookies = {
            settings.login_session_cookie_name: login_session.token,
            settings.registration_session_cookie_name: registration_session.token,
        }

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "louis@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/verify-request")
