"""Integration tests for SEC-1 T14 — rate limits on /verify-email,
/mfa/totp, and /mfa/recover.

Each handler must layer the SEC-1 per-IP / per-email rate-limit gates ON
TOP of the existing per-LoginSession MFA-1 lockout (when applicable),
*without* triggering the SEC-1 ``account_lockout.record_failed`` ladder
on MFA failures (that scope is for /login only — losing your phone
shouldn't lock your whole account).

Throttled responses must:

- Use the same shape as the existing bad-code error path.
- Audit ``USER_RATE_LIMIT_EXCEEDED`` with ``scope`` set to
  ``verify_<ip|email>`` / ``mfa_totp_ip`` / ``mfa_recover_<ip|email>``.
- Carry a 16-char ``key_hash`` and never leak the raw email.
- For MFA endpoints: NOT increment ``LoginSession.mfa_attempts_count``
  (the SEC-1 gate fires before the MFA-1 counter logic).
- For /mfa/recover: NOT consume any recovery codes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import fakeredis.aioredis
import httpx
import pyotp
import pytest
import pytest_asyncio
from fastapi import status
from jinja2 import ChoiceLoader, DictLoader

from fief.apps import auth_app
from fief.db import AsyncSession
from fief.dependencies.logger import get_audit_logger
from fief.dependencies.redis import get_redis
from fief.logger import AuditLogger, logger as loguru_logger
from fief.models import AuditLogMessage, UserTotpSecret
from fief.repositories import (
    LoginSessionRepository,
    UserRepository,
    UserTotpSecretRepository,
)
from fief.repositories.user_mfa_recovery_code import (
    UserMfaRecoveryCodeRepository,
)
from fief.services.security.encryption import encrypt
from fief.services.security.recovery_codes import RecoveryCodeService
from fief.settings import settings
from fief.templates import templates
from tests.data import TestData, email_verification_codes, session_token_tokens


# ---------------------------------------------------------------------------
# Stub MFA challenge templates (shared with test_mfa_challenge.py)
# ---------------------------------------------------------------------------
_STUB_TEMPLATES = {
    "auth/mfa/totp.html": (
        "{{ {'has_form': form is defined,"
        " 'errors': ((form.code.errors if form is defined else [])|list)|map('string')|list,"
        " 'error': (error|default(''))|string}|tojson }}"
    ),
    "auth/mfa/recover.html": (
        "{{ {'has_form': form is defined,"
        " 'errors': ((form.code.errors if form is defined else [])|list)|map('string')|list,"
        " 'error': (error|default(''))|string}|tojson }}"
    ),
}


@pytest.fixture(autouse=True)
def _inject_mfa_template_stubs():
    original = templates.env.loader
    templates.env.loader = ChoiceLoader(
        [DictLoader(_STUB_TEMPLATES), original]
    )
    try:
        yield
    finally:
        templates.env.loader = original


def _body_json(response: httpx.Response) -> dict:
    return json.loads(response.text)


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    real = AuditLogger(loguru_logger)
    mock = MagicMock(spec=AuditLogger, wraps=real)
    mock.admin_user_id = real.admin_user_id
    mock.admin_api_key_id = real.admin_api_key_id
    return mock


@pytest_asyncio.fixture
async def fresh_fake_redis(test_client_auth_csrf: httpx.AsyncClient):
    """Per-test fresh fakeredis with no SEC-1 buckets carried in."""

    client = fakeredis.aioredis.FakeRedis()
    try:
        await client.flushall()
        auth_app.dependency_overrides[get_redis] = lambda: client
        yield client
    finally:
        await client.flushall()
        await client.aclose()


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


def _audit_messages(mock: MagicMock) -> list[AuditLogMessage]:
    return [
        call.args[0]
        for call in mock.call_args_list
        if call.args and isinstance(call.args[0], AuditLogMessage)
    ]


def _audit_calls_with_scope(
    mock: MagicMock,
    message: AuditLogMessage,
    scope: str,
) -> list:
    return [
        call
        for call in mock.call_args_list
        if call.args
        and call.args[0] is message
        and call.kwargs.get("extra", {}).get("scope") == scope
    ]


async def _seed_confirmed_totp(
    main_session: AsyncSession, user_id, secret_b32: str
) -> None:
    repo = UserTotpSecretRepository(main_session)
    existing = await repo.get_by_user_id(user_id)
    if existing is not None:
        await repo.delete_by_user_id(user_id)
    row = UserTotpSecret(
        user_id=user_id,
        secret_encrypted=encrypt(secret_b32),
        confirmed_at=datetime.now(UTC),
        last_used_step=None,
    )
    await repo.create(row)


# ---------------------------------------------------------------------------
# /verify-email
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestVerifyEmailRateLimit:
    async def test_per_ip_cap_returns_invalid_code_shape(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """When per-IP cap is exceeded, /verify-email POST returns the
        SAME 400 shape with ``X-Fief-Error: invalid_code`` the bad-code
        path returns, and audits ``USER_RATE_LIMIT_EXCEEDED`` with
        ``scope=verify_ip``."""

        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        # Tighter cap so test is fast.
        monkeypatch.setattr(settings, "rate_limit_verify_per_ip_per_min", 3)
        # Loosen email cap so per-IP fires first.
        monkeypatch.setattr(
            settings, "rate_limit_verify_per_email_per_5min", 999
        )

        user = test_data["users"]["not_verified_email"]
        tenant = user.tenant
        path_prefix = tenant.slug if not tenant.default else ""
        cookies = {
            settings.session_cookie_name: session_token_tokens[
                "not_verified_email"
            ][0]
        }

        # 3 wrong-code POSTs, all should pass the gate but fail the verify.
        for _i in range(3):
            response = await test_client_auth_csrf.post(
                f"{path_prefix}/verify",
                data={"code": "WRONGC", "csrf_token": csrf_token},
                cookies=cookies,
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert response.headers.get("X-Fief-Error") == "invalid_code"

        # 4th attempt — exceeds the per-IP cap. Same 400 / invalid_code.
        response = await test_client_auth_csrf.post(
            f"{path_prefix}/verify",
            data={"code": "WRONGC", "csrf_token": csrf_token},
            cookies=cookies,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "invalid_code"

        # No leakage in body.
        body_lower = response.text.lower()
        for forbidden in ("rate", "throttle", "too many", "limit"):
            assert forbidden not in body_lower, (
                f"throttled /verify response leaked '{forbidden}'"
            )

        # Audit fired for verify_ip scope.
        rl_calls = _audit_calls_with_scope(
            captured_audit_logger,
            AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
            "verify_ip",
        )
        assert len(rl_calls) >= 1
        extra = rl_calls[0].kwargs.get("extra", {})
        assert extra.get("endpoint") == "/verify-email"
        assert isinstance(extra.get("key_hash"), str)
        assert len(extra["key_hash"]) == 16

    async def test_per_email_cap_returns_invalid_code_shape(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Per-email cap fires from a single source IP. Audit scope is
        ``verify_email``. We loosen the per-IP cap so per-email is the
        binding constraint."""

        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(
            settings, "rate_limit_verify_per_ip_per_min", 999
        )
        monkeypatch.setattr(
            settings, "rate_limit_verify_per_email_per_5min", 2
        )

        user = test_data["users"]["not_verified_email"]
        tenant = user.tenant
        path_prefix = tenant.slug if not tenant.default else ""
        cookies = {
            settings.session_cookie_name: session_token_tokens[
                "not_verified_email"
            ][0]
        }

        # 2 attempts under cap.
        for _i in range(2):
            await test_client_auth_csrf.post(
                f"{path_prefix}/verify",
                data={"code": "WRONGC", "csrf_token": csrf_token},
                cookies=cookies,
            )

        # 3rd attempt — over the per-email cap.
        response = await test_client_auth_csrf.post(
            f"{path_prefix}/verify",
            data={"code": "WRONGC", "csrf_token": csrf_token},
            cookies=cookies,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "invalid_code"

        rl_calls = _audit_calls_with_scope(
            captured_audit_logger,
            AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
            "verify_email",
        )
        assert len(rl_calls) >= 1
        extra = rl_calls[0].kwargs.get("extra", {})
        assert extra.get("endpoint") == "/verify-email"
        assert len(extra.get("key_hash", "")) == 16
        # Don't leak raw email in audit extras.
        assert "email" not in extra

    async def test_under_limit_happy_path_still_works(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """A correct verification code under the rate-limit cap still
        completes the verification (302 to /consent or /)."""

        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        # Generous caps so we can submit one POST without throttling.
        monkeypatch.setattr(settings, "rate_limit_verify_per_ip_per_min", 30)
        monkeypatch.setattr(
            settings, "rate_limit_verify_per_email_per_5min", 10
        )

        user = test_data["users"]["not_verified_email"]
        tenant = user.tenant
        path_prefix = tenant.slug if not tenant.default else ""
        code = email_verification_codes["not_verified_email"][0]

        cookies = {
            settings.session_cookie_name: session_token_tokens[
                "not_verified_email"
            ][0]
        }
        login_session = test_data["login_sessions"]["default"]
        cookies[settings.login_session_cookie_name] = login_session.token

        response = await test_client_auth_csrf.post(
            f"{path_prefix}/verify",
            data={"code": code, "csrf_token": csrf_token},
            cookies=cookies,
        )
        assert response.status_code == status.HTTP_302_FOUND


# ---------------------------------------------------------------------------
# /mfa/totp — SEC-1 per-IP layer ON TOP of MFA-1's per-LoginSession lockout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMfaTotpRateLimit:
    async def test_per_ip_cap_does_not_increment_mfa_attempts_count(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Once the per-IP cap is exceeded, the SEC-1 gate fires *before*
        the MFA-1 verify logic — so ``mfa_attempts_count`` MUST NOT
        increment. The response shape is the same generic invalid-code
        form error."""

        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(settings, "rate_limit_mfa_per_ip_per_min", 2)

        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]

        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        secret_b32 = pyotp.random_base32()
        await _seed_confirmed_totp(main_session, user.id, secret_b32)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        try:
            cookies = {
                settings.login_session_cookie_name: login_session.token
            }

            # 2 wrong-code attempts (under the cap). These DO increment
            # the MFA-1 per-LoginSession counter because the gate passes.
            for _i in range(2):
                await test_client_auth_csrf.post(
                    "/mfa/totp",
                    cookies=cookies,
                    data={"csrf_token": csrf_token, "code": "000000"},
                )

            # Read counter pre-throttle.
            mid = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert mid is not None
            count_before_throttle = mid.mfa_attempts_count
            # Conservatively, both wrong codes incremented MFA-1.
            assert count_before_throttle == 2

            # 3rd attempt — over the per-IP cap. The SEC-1 gate must fire
            # BEFORE MFA-1's verify, so the counter MUST NOT increment.
            response = await test_client_auth_csrf.post(
                "/mfa/totp",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": "000000"},
            )

            # Same form-error shape the bad-code path returns.
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            body = _body_json(response)
            assert body["has_form"] is True

            # Counter unchanged.
            after = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert after is not None
            assert after.mfa_attempts_count == count_before_throttle, (
                "SEC-1 gate must fire before MFA-1's per-session counter"
            )
            assert after.mfa_locked_until is None

            # Audit fired with scope=mfa_totp_ip.
            rl_calls = _audit_calls_with_scope(
                captured_audit_logger,
                AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                "mfa_totp_ip",
            )
            assert len(rl_calls) >= 1
            extra = rl_calls[0].kwargs.get("extra", {})
            assert extra.get("endpoint") == "/mfa/totp"
            assert len(extra.get("key_hash", "")) == 16
        finally:
            user.mfa_enabled = False

    async def test_under_limit_post_still_increments_mfa_counter(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Sanity: when under the SEC-1 cap, the MFA-1 per-LoginSession
        counter still increments — i.e. the SEC-1 gate doesn't break the
        existing MFA-1 lockout logic."""

        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(settings, "rate_limit_mfa_per_ip_per_min", 30)

        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]

        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        secret_b32 = pyotp.random_base32()
        await _seed_confirmed_totp(main_session, user.id, secret_b32)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        try:
            cookies = {
                settings.login_session_cookie_name: login_session.token
            }
            response = await test_client_auth_csrf.post(
                "/mfa/totp",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": "000000"},
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST

            after = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert after is not None
            assert after.mfa_attempts_count == 1
        finally:
            user.mfa_enabled = False


# ---------------------------------------------------------------------------
# /mfa/recover — per-IP at 5/10min and per-email at 3/hour (hardcoded)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMfaRecoverRateLimit:
    async def test_per_ip_cap_does_not_consume_recovery_codes(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """When the per-IP cap is exceeded on /mfa/recover, the SEC-1
        gate fires before recovery-code consumption — so the stored
        codes remain intact AND mfa_attempts_count is not incremented."""

        monkeypatch.setattr(settings, "rate_limit_enabled", True)

        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]

        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        secret_b32 = pyotp.random_base32()
        await _seed_confirmed_totp(main_session, user.id, secret_b32)

        recovery_repo = UserMfaRecoveryCodeRepository(main_session)
        await recovery_repo.delete_by_user_id(user.id)
        recovery_service = RecoveryCodeService(
            recovery_repo=recovery_repo,
            audit_logger=AuditLogger(loguru_logger),
        )
        codes = await recovery_service.generate_for(user)
        assert len(codes) == 10

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        try:
            cookies = {
                settings.login_session_cookie_name: login_session.token
            }

            # 5 attempts (the hardcoded per-IP cap is 5 in 10 min).
            for _i in range(5):
                await test_client_auth_csrf.post(
                    "/mfa/recover",
                    cookies=cookies,
                    data={"csrf_token": csrf_token, "code": "AAAA-BBBB"},
                )

            # Snapshot recovery codes before the 6th throttled call.
            existing_pre = await recovery_repo.list_by_user_id(user.id)
            count_pre = len(existing_pre)

            # 6th attempt — over the per-IP cap of 5.
            response = await test_client_auth_csrf.post(
                "/mfa/recover",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": "AAAA-BBBB"},
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            body = _body_json(response)
            assert body["has_form"] is True

            # Recovery codes NOT consumed by the throttled call.
            existing_post = await recovery_repo.list_by_user_id(user.id)
            assert len(existing_post) == count_pre

            # Audit fired with scope=mfa_recover_ip.
            rl_calls = _audit_calls_with_scope(
                captured_audit_logger,
                AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                "mfa_recover_ip",
            )
            assert len(rl_calls) >= 1
            extra = rl_calls[0].kwargs.get("extra", {})
            assert extra.get("endpoint") == "/mfa/recover"
            assert len(extra.get("key_hash", "")) == 16
        finally:
            user.mfa_enabled = False

    async def test_per_email_cap_audits_with_correct_scope(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        fresh_fake_redis: fakeredis.aioredis.FakeRedis,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """The per-email gate (3 attempts in 1 hour, hardcoded) fires
        independently of the per-IP gate. We exhaust the per-email gate
        with only 3 wrong attempts; the 4th breaches with audit scope
        ``mfa_recover_email``. The per-IP cap is 5 in 10 min so it
        doesn't interfere."""

        monkeypatch.setattr(settings, "rate_limit_enabled", True)

        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]

        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        secret_b32 = pyotp.random_base32()
        await _seed_confirmed_totp(main_session, user.id, secret_b32)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        try:
            cookies = {
                settings.login_session_cookie_name: login_session.token
            }

            # 3 attempts to exhaust the per-email/hour cap.
            for _i in range(3):
                await test_client_auth_csrf.post(
                    "/mfa/recover",
                    cookies=cookies,
                    data={"csrf_token": csrf_token, "code": "AAAA-BBBB"},
                )

            # 4th attempt — per-email cap exceeded. The per-IP cap of 5 is
            # still under, so this audit must be scope=mfa_recover_email.
            response = await test_client_auth_csrf.post(
                "/mfa/recover",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": "AAAA-BBBB"},
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST

            rl_calls = _audit_calls_with_scope(
                captured_audit_logger,
                AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                "mfa_recover_email",
            )
            assert len(rl_calls) >= 1
            extra = rl_calls[0].kwargs.get("extra", {})
            assert extra.get("endpoint") == "/mfa/recover"
            assert len(extra.get("key_hash", "")) == 16
            assert "email" not in extra
        finally:
            user.mfa_enabled = False
