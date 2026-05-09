"""Tests for the login-time passkey challenge route (MFA-2 T9).

Covers ``GET /mfa/passkey`` and ``POST /mfa/passkey/verify``. Reached after
the /login POST flagged ``LoginSession.mfa_pending_user_id`` for an
MFA-enabled user (same gating as the existing ``/mfa/totp`` route).

The verify endpoint is JSON-only (the WebAuthn JS bridge POSTs the
authenticator response and reads ``redirect_to`` from the JSON reply).
The :class:`WebAuthnService` is overridden with a programmable fake so
the tests do not need real authenticator output.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import status
from jinja2 import ChoiceLoader, DictLoader

from fief.apps import auth_app
from fief.db import AsyncSession
from fief.dependencies.logger import get_audit_logger
from fief.dependencies.security import get_webauthn_service
from fief.logger import AuditLogger
from fief.logger import logger as loguru_logger
from fief.models import AuditLogMessage, UserWebAuthnCredential
from fief.repositories import LoginSessionRepository, UserRepository
from fief.services.security.webauthn import (
    ChallengeExpired,
    CredentialNotFound,
    InvalidAssertion,
    SignCountRollback,
)
from fief.settings import settings
from fief.templates import templates
from tests.data import TestData

# ---------------------------------------------------------------------------
# Stub template (T11 owns the real template). Surfaces the embedded options
# JSON so we can assert against them without running the real Jinja file.
# ---------------------------------------------------------------------------
_STUB_TEMPLATES = {
    "auth/mfa/passkey.html": (
        "{{ {'has_options': options is defined,"
        " 'challenge': (options.get('challenge') if options is defined else '')|string"
        "}|tojson }}"
    ),
}


@pytest.fixture(autouse=True)
def _inject_passkey_template_stub():
    original = templates.env.loader
    templates.env.loader = ChoiceLoader([DictLoader(_STUB_TEMPLATES), original])
    try:
        yield
    finally:
        templates.env.loader = original


# ---------------------------------------------------------------------------
# Fake WebAuthnService — only implements the assertion surface used by /mfa/passkey.
# ---------------------------------------------------------------------------


class _FakeWebAuthnService:
    """Programmable stand-in for :class:`WebAuthnService` used in challenge tests.

    Tests configure ``begin_assertion_options`` / ``verify_assertion_result``
    / ``verify_assertion_exc`` / ``list_for_user_result`` before issuing the
    request, then read ``calls`` to assert the route's behaviour.
    """

    def __init__(self) -> None:
        self.begin_assertion_options: dict[str, Any] = {
            "challenge": "fake-challenge",
            "rpId": "test",
            "allowCredentials": [],
        }
        self.verify_assertion_result: UserWebAuthnCredential | None = None
        self.verify_assertion_exc: Exception | None = None
        self.list_for_user_result: list[UserWebAuthnCredential] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_for_user(self, user) -> list[UserWebAuthnCredential]:
        self.calls.append(("list_for_user", {"user_id": user.id}))
        return self.list_for_user_result

    async def begin_assertion(
        self, user, *, rp_id: str, login_session_id: UUID
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "begin_assertion",
                {
                    "user_id": user.id,
                    "rp_id": rp_id,
                    "login_session_id": login_session_id,
                },
            )
        )
        return self.begin_assertion_options

    async def verify_assertion(
        self,
        user,
        *,
        rp_id: str,
        origin: str,
        login_session_id: UUID,
        assertion_response: dict[str, Any],
    ) -> UserWebAuthnCredential:
        self.calls.append(
            (
                "verify_assertion",
                {
                    "user_id": user.id,
                    "rp_id": rp_id,
                    "origin": origin,
                    "login_session_id": login_session_id,
                    "assertion_response": assertion_response,
                },
            )
        )
        if self.verify_assertion_exc is not None:
            raise self.verify_assertion_exc
        assert self.verify_assertion_result is not None
        return self.verify_assertion_result


@pytest.fixture
def fake_webauthn_service():
    fake = _FakeWebAuthnService()
    auth_app.dependency_overrides[get_webauthn_service] = lambda: fake
    try:
        yield fake
    finally:
        auth_app.dependency_overrides.pop(get_webauthn_service, None)


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    real = AuditLogger(loguru_logger)
    mock = MagicMock(spec=AuditLogger, wraps=real)
    mock.admin_user_id = real.admin_user_id
    mock.admin_api_key_id = real.admin_api_key_id
    return mock


@pytest.fixture
def _override_audit_logger(
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


def _audit_calls_for(mock: MagicMock, message: AuditLogMessage) -> list:
    return [
        call
        for call in mock.call_args_list
        if call.args and call.args[0] is message
    ]


def _make_credential(user_id: UUID) -> UserWebAuthnCredential:
    return UserWebAuthnCredential(
        id=uuid4(),
        user_id=user_id,
        credential_id=b"cred-1",
        public_key=b"pubkey",
        sign_count=0,
        transports=None,
        aaguid=None,
        backup_eligible=False,
        backup_state=False,
        label=None,
        attestation_obj=None,
    )


def _body_json(response: httpx.Response) -> dict:
    return json.loads(response.text)


# ---------------------------------------------------------------------------
# GET /mfa/passkey
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMfaPasskeyGetGating:
    async def test_get_redirects_to_login_when_no_pending_user(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = None
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        cookies = {settings.login_session_cookie_name: login_session.token}
        response = await test_client_auth_csrf.get(
            "/mfa/passkey", cookies=cookies
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")

    async def test_get_redirects_to_login_when_no_login_session_cookie(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        response = await test_client_auth_csrf.get("/mfa/passkey")
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")

    async def test_get_redirects_to_login_when_locked(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 5
        login_session.mfa_locked_until = datetime.now(UTC) + timedelta(
            minutes=10
        )
        await login_session_repository.update(login_session)

        cookies = {settings.login_session_cookie_name: login_session.token}
        response = await test_client_auth_csrf.get(
            "/mfa/passkey", cookies=cookies
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")

    async def test_get_short_circuits_to_totp_when_user_has_no_passkeys(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        """Defensive redirect: a user with no passkeys shouldn't have
        reached /mfa/passkey at all. Bounce them to /mfa/totp instead of
        crashing on an empty allowCredentials list."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        fake_webauthn_service.list_for_user_result = []

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.get(
                "/mfa/passkey", cookies=cookies
            )
            assert response.status_code == status.HTTP_302_FOUND
            assert response.headers["Location"].endswith("/mfa/totp")
            # begin_assertion must NOT have been called for an empty list.
            call_names = [name for name, _ in fake_webauthn_service.calls]
            assert "begin_assertion" not in call_names
        finally:
            user.mfa_enabled = False

    async def test_get_renders_options_when_user_has_passkeys(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        fake_webauthn_service.list_for_user_result = [
            _make_credential(user.id)
        ]
        fake_webauthn_service.begin_assertion_options = {
            "challenge": "abc123",
            "rpId": "test",
            "allowCredentials": [{"id": "cred-1", "type": "public-key"}],
        }

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.get(
                "/mfa/passkey", cookies=cookies
            )
            assert response.status_code == status.HTTP_200_OK
            body = _body_json(response)
            assert body["has_options"] is True
            assert body["challenge"] == "abc123"

            call_names = [name for name, _ in fake_webauthn_service.calls]
            assert "begin_assertion" in call_names
            # begin_assertion was bound to the LoginSession id.
            begin_call = next(
                kwargs
                for name, kwargs in fake_webauthn_service.calls
                if name == "begin_assertion"
            )
            assert begin_call["login_session_id"] == login_session.id
        finally:
            user.mfa_enabled = False


# ---------------------------------------------------------------------------
# POST /mfa/passkey/verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMfaPasskeyVerifyGating:
    async def test_post_redirects_to_login_when_no_pending_user(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = None
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        cookies = {settings.login_session_cookie_name: login_session.token}
        response = await test_client_auth_csrf.post(
            "/mfa/passkey/verify",
            cookies=cookies,
            content=json.dumps({"id": "x", "rawId": "x", "response": {}}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")

    async def test_post_redirects_to_login_when_locked(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 5
        login_session.mfa_locked_until = datetime.now(UTC) + timedelta(
            minutes=10
        )
        await login_session_repository.update(login_session)

        cookies = {settings.login_session_cookie_name: login_session.token}
        response = await test_client_auth_csrf.post(
            "/mfa/passkey/verify",
            cookies=cookies,
            content=json.dumps({"id": "x", "rawId": "x", "response": {}}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")


@pytest.mark.asyncio
class TestMfaPasskeyVerifySuccess:
    async def test_post_valid_assertion_completes_login(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        fake_webauthn_service.verify_assertion_result = _make_credential(
            user.id
        )

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/passkey/verify",
                cookies=cookies,
                content=json.dumps(
                    {"id": "x", "rawId": "x", "response": {}}
                ),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == status.HTTP_200_OK
            body = response.json()
            assert "redirect_to" in body
            assert body["redirect_to"].endswith("/verify-request")

            # New session cookie issued via complete_login_after_mfa.
            assert settings.session_cookie_name in response.cookies

            # Carry-state cleared.
            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_pending_user_id is None
            assert refreshed.mfa_attempts_count == 0
            assert refreshed.mfa_locked_until is None
        finally:
            user.mfa_enabled = False


@pytest.mark.asyncio
class TestMfaPasskeyVerifyFailure:
    async def test_post_credential_not_found_returns_401_and_increments(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        fake_webauthn_service.verify_assertion_exc = CredentialNotFound(
            "no such credential"
        )

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/passkey/verify",
                cookies=cookies,
                content=json.dumps(
                    {"id": "x", "rawId": "x", "response": {}}
                ),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            body = response.json()
            assert body["error"] == "invalid"

            # Counter increments — same lockout ladder as TOTP.
            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_attempts_count == 1
            # Pending user id stays — user can retry until lockout.
            assert refreshed.mfa_pending_user_id == user.id
        finally:
            user.mfa_enabled = False

    async def test_post_invalid_assertion_returns_401_and_increments(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        fake_webauthn_service.verify_assertion_exc = InvalidAssertion(
            "bad signature"
        )

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/passkey/verify",
                cookies=cookies,
                content=json.dumps(
                    {"id": "x", "rawId": "x", "response": {}}
                ),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            body = response.json()
            assert body["error"] == "invalid"

            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_attempts_count == 1
        finally:
            user.mfa_enabled = False

    async def test_post_sign_count_rollback_does_not_increment_counter(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        """SignCountRollback flags a suspect *credential*, not a wrong
        attempt — do not burn the user's lockout budget for a
        sign-count regression."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        fake_webauthn_service.verify_assertion_exc = SignCountRollback(
            "rollback"
        )

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/passkey/verify",
                cookies=cookies,
                content=json.dumps(
                    {"id": "x", "rawId": "x", "response": {}}
                ),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            body = response.json()
            assert body["error"] == "credential_compromised"

            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            # NOT incremented.
            assert refreshed.mfa_attempts_count == 0
        finally:
            user.mfa_enabled = False

    async def test_post_challenge_expired_returns_400(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        fake_webauthn_service.verify_assertion_exc = ChallengeExpired(
            "no challenge"
        )

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/passkey/verify",
                cookies=cookies,
                content=json.dumps(
                    {"id": "x", "rawId": "x", "response": {}}
                ),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            body = response.json()
            assert body["error"] == "challenge_expired"

            # Counter NOT incremented (challenge expiry is a system-level
            # condition, not a user-attributable wrong attempt).
            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_attempts_count == 0
        finally:
            user.mfa_enabled = False

    async def test_post_fifth_wrong_assertion_locks_session(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        # Pretend four wrong attempts have already happened.
        login_session.mfa_attempts_count = 4
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        fake_webauthn_service.verify_assertion_exc = InvalidAssertion(
            "bad sig"
        )

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/passkey/verify",
                cookies=cookies,
                content=json.dumps(
                    {"id": "x", "rawId": "x", "response": {}}
                ),
                headers={"Content-Type": "application/json"},
            )
            # Fifth wrong attempt: locked → 401 still (response is JSON,
            # not a redirect — the JS bridge surfaces a generic error and
            # the next request will be gated to /login by the GET handler).
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_attempts_count == 5
            assert refreshed.mfa_locked_until is not None
            assert refreshed.mfa_locked_until > datetime.now(UTC)
        finally:
            user.mfa_enabled = False
