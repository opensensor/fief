"""Tests for the MFA-aware branch of the /login route (T15).

The login POST handler must:

1. Always wipe stale MFA carry-state on the LoginSession at the start of a
   fresh POST (defends against an abandoned MFA challenge leaving residue on
   the same session).
2. When the authenticated user has ``mfa_enabled=True`` defer issuing a
   session cookie, mark ``login_session.mfa_pending_user_id``, and redirect
   to the TOTP challenge (``/mfa/totp``).
3. When the user does not have MFA the existing happy-path
   (``rotate_session_token`` + redirect to verify-request) is unchanged.

The tests also cover the new ``AuthenticationFlow.complete_login_after_mfa``
helper, which the verify route (T14) will invoke on success.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import status
from fastapi.responses import RedirectResponse

from fief.crypto.token import get_token_hash
from fief.db import AsyncSession
from fief.repositories import (
    LoginSessionRepository,
    SessionTokenRepository,
    UserRepository,
)
from fief.services.authentication_flow import AuthenticationFlow
from fief.settings import settings
from tests.data import TestData


@pytest.mark.asyncio
class TestLoginPostMFABranch:
    async def test_user_without_mfa_unchanged_happy_path(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """A user with mfa_enabled=False must follow the existing path:
        redirect to /verify-request and receive a session cookie."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = False
        await user_repository.update(user)
        client = login_session.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        cookies = {settings.login_session_cookie_name: login_session.token}

        response = await test_client_auth_csrf.post(
            f"{path_prefix}/login",
            data={
                "email": user.email,
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith(
            f"{path_prefix}/verify-request"
        )

        # Session cookie was issued (rotate_session_token ran).
        assert settings.session_cookie_name in response.cookies
        session_cookie = response.cookies[settings.session_cookie_name]
        session_token_repository = SessionTokenRepository(main_session)
        session_token = await session_token_repository.get_by_token(
            get_token_hash(session_cookie)
        )
        assert session_token is not None

    async def test_user_with_mfa_enabled_redirects_to_totp_without_session_cookie(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """When the user is enrolled in MFA, the login route must defer
        session-token rotation, set ``mfa_pending_user_id`` on the login
        session, and redirect to the TOTP challenge."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)
        client = login_session.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}

            response = await test_client_auth_csrf.post(
                f"{path_prefix}/login",
                data={
                    "email": user.email,
                    "password": "herminetincture",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )

            assert response.status_code == status.HTTP_302_FOUND
            location = response.headers["Location"]
            assert location.endswith(f"{path_prefix}/mfa/totp"), (
                f"expected MFA totp redirect, got {location!r}"
            )

            # No session cookie may be issued before /mfa/totp succeeds.
            assert settings.session_cookie_name not in response.cookies

            # mfa_pending_user_id was persisted on the login session.
            login_session_repository = LoginSessionRepository(main_session)
            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_pending_user_id == user.id
        finally:
            user.mfa_enabled = False

    async def test_stale_mfa_state_cleared_on_fresh_login_post(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """If a LoginSession still carries pending MFA state from an
        abandoned challenge, a fresh /login POST (for a non-MFA user) must
        zero the carry-state out before continuing."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = False
        await user_repository.update(user)
        # Simulate stale residue from a previously abandoned MFA challenge.
        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 3
        login_session.mfa_locked_until = datetime.now(UTC) + timedelta(
            minutes=10
        )
        await login_session_repository.update(login_session)

        client = login_session.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        cookies = {settings.login_session_cookie_name: login_session.token}

        response = await test_client_auth_csrf.post(
            f"{path_prefix}/login",
            data={
                "email": user.email,
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_302_FOUND

        refreshed = await login_session_repository.get_by_token(
            login_session.token, fresh=False
        )
        assert refreshed is not None
        assert refreshed.mfa_pending_user_id is None
        assert refreshed.mfa_attempts_count == 0
        assert refreshed.mfa_locked_until is None


@pytest.mark.asyncio
class TestCompleteLoginAfterMFA:
    async def test_clears_carry_state_and_rotates_session_token(
        self,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """``complete_login_after_mfa`` must wipe MFA carry-state on the
        login session AND rotate the session token (issuing a new cookie)."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 2
        login_session.mfa_locked_until = datetime.now(UTC) + timedelta(
            minutes=10
        )
        await login_session_repository.update(login_session)

        session_token_repository = SessionTokenRepository(main_session)
        flow = AuthenticationFlow(
            authorization_code_repository=MagicMock(),
            login_session_repository=login_session_repository,
            session_token_repository=session_token_repository,
            grant_repository=MagicMock(),
            get_user_permissions=MagicMock(),
        )

        response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
        response = await flow.complete_login_after_mfa(
            response, login_session, user, session_token=None
        )

        # Session cookie was set by rotate_session_token via create_session_token.
        set_cookie_headers = response.raw_headers
        cookie_header_values = [
            v.decode() for k, v in set_cookie_headers if k == b"set-cookie"
        ]
        assert any(
            settings.session_cookie_name in h for h in cookie_header_values
        ), (
            "expected session cookie to be issued by complete_login_after_mfa"
        )

        # MFA carry-state was cleared on the login session.
        refreshed = await login_session_repository.get_by_token(
            login_session.token, fresh=False
        )
        assert refreshed is not None
        assert refreshed.mfa_pending_user_id is None
        assert refreshed.mfa_attempts_count == 0
        assert refreshed.mfa_locked_until is None
