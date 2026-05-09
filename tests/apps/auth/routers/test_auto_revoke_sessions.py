"""Auto-revoke wires for security-relevant actions (UX-1 T12).

Covers four insertion points where the dashboard / login flow must call
:meth:`DeviceSessionsService.auto_revoke_others` AFTER the underlying
operation succeeds:

- ``POST /password`` (password change)               → ``reason="password_change"``
- ``POST /security/mfa/totp/confirm`` (MFA enroll)   → ``reason="mfa_enrolled"``
- ``POST /security/mfa/totp/disable`` (MFA disable)  → ``reason="mfa_disabled"``
- ``POST /mfa/recover`` (recovery code consumed)     → ``reason="recovery_code_used"``

In each case the audit log emits :data:`AuditLogMessage.USER_SESSIONS_AUTO_REVOKED`
with ``extra.trigger_reason`` set to the matching string and the *current*
session preserved while every other session/refresh row for the user is
deleted. For ``/mfa/recover`` the "current" session is the one minted by
:meth:`AuthenticationFlow.complete_login_after_mfa` — the user is mid-login
and has no pre-existing dashboard cookie — so all PRE-recovery sessions are
revoked and only the freshly minted post-MFA session survives.

The dashboard-flow tests reuse the bundled fixture ``regular`` user; we
seed an extra :class:`SessionToken` and :class:`RefreshToken` per test to
exercise the "other devices" set. Audit-log assertions go through the
project's standard :class:`AuditLogger` mock, mirroring the pattern in
``test_sessions.py``.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pyotp
import pytest
import pytest_asyncio
from fastapi import status
from jinja2 import ChoiceLoader, DictLoader

from fief.apps import auth_app
from fief.crypto.token import generate_token
from fief.db import AsyncSession
from fief.dependencies.logger import get_audit_logger
from fief.logger import AuditLogger, logger as loguru_logger
from fief.models import (
    AuditLogMessage,
    RefreshToken,
    SessionToken,
    UserTotpSecret,
)
from fief.repositories import (
    LoginSessionRepository,
    RefreshTokenRepository,
    SessionTokenRepository,
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
from tests.data import TestData, session_token_tokens


# ---------------------------------------------------------------------------
# Shared template stubs. The real templates ship with T13 / T17 / T19; here
# we only care that the ROUTE handlers run end-to-end so the auto-revoke
# wire after the operation succeeds gets exercised.
# ---------------------------------------------------------------------------
_STUB_TEMPLATES = {
    # Dashboard MFA stubs (mirror tests/apps/auth/routers/test_dashboard_mfa.py).
    "auth/dashboard/security/index.html": (
        "{{ {'mfa_enabled': mfa_enabled,"
        " 'error': (error|default(''))|string,"
        " 'success': (success|default(''))|string}|tojson }}"
    ),
    "auth/dashboard/security/setup.html": (
        "{{ {'secret_b32': secret_b32|default(''),"
        " 'qr_png_data_uri': qr_png_data_uri|default(''),"
        " 'has_form': form is defined,"
        " 'errors': ((form.code.errors if form is defined else [])|list)|map('string')|list,"
        " 'error': (error|default(''))|string}|tojson }}"
    ),
    "auth/dashboard/security/recovery_codes.html": (
        "{{ {'codes': codes,"
        " 'success': (success|default(''))|string}|tojson }}"
    ),
    # MFA challenge stubs (mirror tests/apps/auth/routers/test_mfa_challenge.py).
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
def _inject_template_stubs():
    original = templates.env.loader
    templates.env.loader = ChoiceLoader([DictLoader(_STUB_TEMPLATES), original])
    try:
        yield
    finally:
        templates.env.loader = original


def _auth_cookies() -> dict[str, str]:
    return {settings.session_cookie_name: session_token_tokens["regular"][0]}


def _audit_calls(mock: MagicMock, message: AuditLogMessage) -> list:
    """Return every captured call whose first positional arg matches ``message``."""

    return [
        call
        for call in mock.call_args_list
        if call.args and call.args[0] == message
    ]


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    """Wrapping mock that records every audit-logger call while still
    delegating to the real logger so loguru sinks see normal output."""

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


# ---------------------------------------------------------------------------
# Helpers — seed an additional session token / refresh token for the
# fixture's ``regular`` user so the auto-revoke "others" set is non-empty.
# ---------------------------------------------------------------------------


_OTHER_DEVICE_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
)


async def _seed_extra_session(
    main_session: AsyncSession,
    user_id: uuid.UUID,
    *,
    user_agent: str = _OTHER_DEVICE_UA,
    ip: str = "203.0.113.42",
) -> SessionToken:
    repo = SessionTokenRepository(main_session)
    _raw, token_hash = generate_token()
    token = SessionToken(
        token=token_hash,
        user_id=user_id,
        created_ip=ip,
        created_user_agent=user_agent,
        last_seen_at=datetime.now(UTC),
        last_seen_ip=ip,
    )
    main_session.add(token)
    await main_session.commit()
    persisted = await repo.get_by_id(token.id)
    assert persisted is not None
    return persisted


async def _seed_extra_refresh(
    main_session: AsyncSession,
    *,
    user_id: uuid.UUID,
    client_id: uuid.UUID,
    user_agent: str = _OTHER_DEVICE_UA,
    ip: str = "203.0.113.42",
) -> RefreshToken:
    repo = RefreshTokenRepository(main_session)
    _raw, token_hash = generate_token()
    token = RefreshToken(
        token=token_hash,
        user_id=user_id,
        client_id=client_id,
        scope=["openid", "offline_access"],
        authenticated_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=7),
        created_ip=ip,
        created_user_agent=user_agent,
        last_seen_at=datetime.now(UTC),
        last_seen_ip=ip,
    )
    main_session.add(token)
    await main_session.commit()
    persisted = await repo.get_by_id(token.id)
    assert persisted is not None
    return persisted


async def _seed_confirmed_totp(
    main_session: AsyncSession, user_id: uuid.UUID, secret_b32: str
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
# Password change — POST /password
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPasswordChangeAutoRevokes:
    async def test_password_change_revokes_other_sessions(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
        user = test_data["users"]["regular"]
        # Seed a second session row + a refresh token so the "others" set is
        # non-empty for this user.
        other_session = await _seed_extra_session(main_session, user.id)
        # Use the fixture's "default_tenant" client which already exists.
        client_id = test_data["clients"]["default_tenant"].id
        await _seed_extra_refresh(
            main_session, user_id=user.id, client_id=client_id
        )

        current_session_token = test_data["session_tokens"]["regular"]
        current_id = current_session_token.id

        response = await test_client_auth_csrf.post(
            "/password",
            cookies=_auth_cookies(),
            data={
                "csrf_token": csrf_token,
                "old_password": "herminetincture",
                "new_password": "An0therStr0ngPass!42",
                "new_password_confirm": "An0therStr0ngPass!42",
            },
        )
        assert response.status_code == status.HTTP_200_OK

        # Audit log fired with the right shape.
        auto_revoke_calls = _audit_calls(
            captured_audit_logger, AuditLogMessage.USER_SESSIONS_AUTO_REVOKED
        )
        assert len(auto_revoke_calls) == 1
        extra = auto_revoke_calls[0].kwargs.get("extra") or {}
        assert extra.get("trigger_reason") == "password_change"
        assert extra.get("revoked_session_count", 0) >= 1
        assert "revoked_refresh_count" in extra

        # Other sessions / refresh tokens are gone; current is preserved.
        session_repo = SessionTokenRepository(main_session)
        refresh_repo = RefreshTokenRepository(main_session)
        assert await session_repo.get_by_id(other_session.id) is None
        assert await session_repo.get_by_id(current_id) is not None
        # Refresh tokens for the user are wiped.
        remaining = await refresh_repo.list_by_user_id(user.id)
        assert remaining == []


# ---------------------------------------------------------------------------
# MFA enroll confirm — POST /security/mfa/totp/confirm
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMfaConfirmAutoRevokes:
    async def test_mfa_enroll_revokes_other_sessions(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
        user = test_data["users"]["regular"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)

        # Begin enrollment to get a real secret.
        begin_response = await test_client_auth_csrf.post(
            "/security/mfa/totp/begin",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token},
        )
        secret_b32 = json.loads(begin_response.text)["secret_b32"]

        other_session = await _seed_extra_session(main_session, user.id)
        current_session_token = test_data["session_tokens"]["regular"]
        current_id = current_session_token.id

        valid_code = pyotp.TOTP(secret_b32).now()
        response = await test_client_auth_csrf.post(
            "/security/mfa/totp/confirm",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token, "code": valid_code},
        )
        assert response.status_code == status.HTTP_200_OK

        auto_revoke_calls = _audit_calls(
            captured_audit_logger, AuditLogMessage.USER_SESSIONS_AUTO_REVOKED
        )
        assert len(auto_revoke_calls) == 1
        extra = auto_revoke_calls[0].kwargs.get("extra") or {}
        assert extra.get("trigger_reason") == "mfa_enrolled"

        session_repo = SessionTokenRepository(main_session)
        assert await session_repo.get_by_id(other_session.id) is None
        assert await session_repo.get_by_id(current_id) is not None


# ---------------------------------------------------------------------------
# MFA disable — POST /security/mfa/totp/disable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMfaDisableAutoRevokes:
    async def test_mfa_disable_revokes_other_sessions(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
        send_task_mock,
    ):
        user = test_data["users"]["regular"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)

        # Real enrollment so we end up with valid recovery codes for disable.
        begin_response = await test_client_auth_csrf.post(
            "/security/mfa/totp/begin",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token},
        )
        secret_b32 = json.loads(begin_response.text)["secret_b32"]
        first_totp = pyotp.TOTP(secret_b32)

        confirm_response = await test_client_auth_csrf.post(
            "/security/mfa/totp/confirm",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token, "code": first_totp.now()},
        )
        assert confirm_response.status_code == status.HTTP_200_OK
        recovery_codes = json.loads(confirm_response.text)["codes"]

        # Reset captured log so we only assert on the disable-time audit.
        captured_audit_logger.reset_mock()

        # Seed a second session AFTER confirm so the auto-revoke from confirm
        # doesn't sweep it up — we want disable to be the trigger.
        other_session = await _seed_extra_session(main_session, user.id)
        current_session_token = test_data["session_tokens"]["regular"]
        current_id = current_session_token.id

        disable_response = await test_client_auth_csrf.post(
            "/security/mfa/totp/disable",
            cookies=_auth_cookies(),
            data={
                "csrf_token": csrf_token,
                "current_password": "herminetincture",
                "code": recovery_codes[0],
            },
        )
        assert disable_response.status_code == status.HTTP_200_OK

        auto_revoke_calls = _audit_calls(
            captured_audit_logger, AuditLogMessage.USER_SESSIONS_AUTO_REVOKED
        )
        assert len(auto_revoke_calls) == 1
        extra = auto_revoke_calls[0].kwargs.get("extra") or {}
        assert extra.get("trigger_reason") == "mfa_disabled"

        session_repo = SessionTokenRepository(main_session)
        assert await session_repo.get_by_id(other_session.id) is None
        assert await session_repo.get_by_id(current_id) is not None


# ---------------------------------------------------------------------------
# Recovery code consumed — POST /mfa/recover
# ---------------------------------------------------------------------------
#
# Unlike the dashboard cases this is mid-login: the user has NO existing
# dashboard cookie, the "current" session is the brand-new one minted by
# ``complete_login_after_mfa``. Every PRE-recovery session for the user must
# be revoked while the new one survives.


@pytest.mark.asyncio
class TestMfaRecoverAutoRevokes:
    async def test_recovery_code_revokes_pre_recovery_sessions(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
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

        # Seed pre-recovery sessions for the user. The fixture-bundled
        # ``regular`` SessionToken is one; add a second so we can assert
        # both go away. The cookie at /mfa/recover is the LoginSession
        # cookie, NOT a dashboard session — neither pre-recovery session
        # is "current" from the route's perspective.
        pre_session_extra = await _seed_extra_session(main_session, user.id)
        bundled_session_id = test_data["session_tokens"]["regular"].id

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        try:
            cookies = {
                settings.login_session_cookie_name: login_session.token,
            }
            response = await test_client_auth_csrf.post(
                "/mfa/recover",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": codes[0]},
            )
            assert response.status_code == status.HTTP_302_FOUND
            # The handler issued a fresh dashboard session cookie via
            # complete_login_after_mfa.
            assert settings.session_cookie_name in response.cookies
            new_cookie_value = response.cookies[settings.session_cookie_name]

            auto_revoke_calls = _audit_calls(
                captured_audit_logger,
                AuditLogMessage.USER_SESSIONS_AUTO_REVOKED,
            )
            assert len(auto_revoke_calls) == 1
            extra = auto_revoke_calls[0].kwargs.get("extra") or {}
            assert extra.get("trigger_reason") == "recovery_code_used"

            # All PRE-recovery session rows are gone.
            session_repo = SessionTokenRepository(main_session)
            assert await session_repo.get_by_id(pre_session_extra.id) is None
            assert await session_repo.get_by_id(bundled_session_id) is None

            # The new post-MFA session token (cookie value) survived.
            from fief.crypto.token import get_token_hash

            new_hash = get_token_hash(new_cookie_value)
            new_row = await session_repo.get_by_token(new_hash)
            assert new_row is not None
            assert new_row.user_id == user.id
        finally:
            user.mfa_enabled = False
            await user_repository.update(user)
