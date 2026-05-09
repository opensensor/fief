"""Tests for SEC-2 T8: BreachedPasswordError surfaces correctly in the four
password-set handlers (register / reset / dashboard change-password / admin
PATCH users).

The four routes ALL go through ``UserManager.validate_password`` which (after
T7) calls ``BreachedPasswordChecker.is_breached``. The conftest's default
override is a no-op stub that returns False; these tests swap in a stub that
returns True so we can exercise the breached-password surface without
hitting HIBP over the network.

Each test asserts:

1. The response is 4xx (the handler did NOT 500 on ``BreachedPasswordError``).
2. The user-facing error code (``X-Fief-Error`` header for HTML routes,
   ``code`` field in JSON for the admin API) is ``password_breached``,
   distinct from the existing ``invalid_password`` shape.

A regression test verifies a too-weak (non-breached) password still surfaces
a regular ``invalid_password`` shape, i.e. handlers must NOT collapse all
``InvalidPasswordError`` raises into the breached branch.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import status
from jwcrypto import jwt

from fief.apps import api_app, auth_app
from fief.crypto.password import password_helper
from fief.dependencies.security import get_breached_password_checker
from fief.errors import APIErrorCode
from fief.models import User
from fief.services.user_manager import RESET_PASSWORD_TOKEN_AUDIENCE
from fief.settings import settings
from tests.data import TestData, session_token_tokens


def _generate_reset_jwt(user: User) -> str:
    claims = {
        "sub": str(user.id),
        "password_fgpt": password_helper.hash(user.hashed_password),
        "aud": RESET_PASSWORD_TOKEN_AUDIENCE,
    }
    signing_key = user.tenant.get_sign_jwk()
    token = jwt.JWT(header={"alg": "RS256", "kid": signing_key["kid"]}, claims=claims)
    token.make_signed_token(signing_key)
    return token.serialize()


class _BreachedStub:
    """Stand-in for :class:`BreachedPasswordChecker` that always reports
    the password as breached, mimicking a HIBP hit at-or-above the
    threshold without the network round-trip."""

    async def is_breached(self, password, tenant) -> bool:  # noqa: ARG002
        return True


@pytest.fixture
def _force_breached_auth_app():
    """Override the auth_app ``get_breached_password_checker`` to always
    say "breached". Must be applied AFTER the test_client_auth fixture
    which resets ``app.dependency_overrides`` per test."""

    auth_app.dependency_overrides[get_breached_password_checker] = (
        lambda: _BreachedStub()
    )
    try:
        yield
    finally:
        auth_app.dependency_overrides.pop(get_breached_password_checker, None)


@pytest.fixture
def _force_breached_api_app():
    """Same override, on the admin API app."""

    api_app.dependency_overrides[get_breached_password_checker] = (
        lambda: _BreachedStub()
    )
    try:
        yield
    finally:
        api_app.dependency_overrides.pop(get_breached_password_checker, None)


@pytest.mark.asyncio
class TestRegisterBreachedPassword:
    async def test_register_with_breached_password_returns_password_breached(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        _force_breached_auth_app: None,
    ):
        """POST /register with a strong-form password that the stub
        flags as breached must render a 400 with
        ``X-Fief-Error: password_breached`` (NOT a 500 — the bug T8
        is fixing is the missing except clause)."""

        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"][
            "default_password"
        ]
        cookies = {
            settings.login_session_cookie_name: login_session.token,
            settings.registration_session_cookie_name: registration_session.token,
        }

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "newuser@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "password_breached"

    async def test_register_with_weak_password_still_invalid_password(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
    ):
        """Regression: a wtforms-level / zxcvbn weakness must continue
        to surface the generic invalid-password shape, NOT
        ``password_breached``. The breached-checker stays at its noop
        default for this test so we can isolate the form-validation
        path."""

        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"][
            "default_password"
        ]
        cookies = {
            settings.login_session_cookie_name: login_session.token,
            settings.registration_session_cookie_name: registration_session.token,
        }

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "newuser@bretagne.duchy",
                "password": "h",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        # Form-level validation rejects "h" (too short) — the response is
        # still 400 but does NOT carry the breached-password header.
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") != "password_breached"


@pytest.mark.asyncio
class TestResetPasswordBreachedPassword:
    async def test_reset_with_breached_password_returns_password_breached(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        _force_breached_auth_app: None,
    ):
        """POST /reset with a valid token + strong-form password that
        the stub flags as breached must render a 400 with
        ``X-Fief-Error: password_breached``. Without T8, this path 500s
        because the route only catches ``InvalidResetPasswordTokenError,
        UserDoesNotExistError, UserInactiveError``."""

        user = test_data["users"]["regular"]
        token = _generate_reset_jwt(user)

        response = await test_client_auth_csrf.post(
            "/reset",
            data={
                "password": "anewlongerpassword",
                "token": token,
                "csrf_token": csrf_token,
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "password_breached"


@pytest.mark.asyncio
class TestDashboardChangePasswordBreached:
    async def test_change_password_with_breached_password_returns_password_breached(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        _force_breached_auth_app: None,
    ):
        """POST /password (auth-app dashboard change-password) with the
        right old password but a "breached" new password must surface
        the password_breached error code, not 500.

        The HTMX header is set by the conftest's ``htmx`` fixture (this
        test runs under the parametrize True/False sweep)."""

        cookies = {
            settings.session_cookie_name: session_token_tokens["regular"][0],
        }
        response = await test_client_auth_csrf.post(
            "/password",
            cookies=cookies,
            data={
                "old_password": "herminetincture",
                "new_password": "newherminetincture",
                "new_password_confirm": "newherminetincture",
                "csrf_token": csrf_token,
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "password_breached"


@pytest.mark.asyncio
class TestAdminApiUpdateBreachedPassword:
    @pytest.mark.authenticated_admin
    async def test_admin_patch_with_breached_password_returns_password_breached(
        self,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
        _force_breached_api_app: None,
    ):
        """PATCH /users/{id} admin route with a "breached" password must
        return 400 with the existing ``USER_UPDATE_INVALID_PASSWORD``
        detail (the existing ``except InvalidPasswordError`` already
        catches it via subclass) AND a ``code: password_breached``
        discriminator so admin clients can tell the two apart."""

        user = test_data["users"]["regular"]
        response = await test_client_api.patch(
            f"/users/{user.id}",
            json={"password": "anewlongerpassword"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        body = response.json()
        # Existing shape preserved — the subclass relationship means
        # ``except InvalidPasswordError`` matches just fine.
        assert body["detail"] == APIErrorCode.USER_UPDATE_INVALID_PASSWORD
        assert "reason" in body
        # New T8 discriminator: clients that want to differentiate
        # (e.g. surface a custom HIBP-specific UX) can branch on this.
        assert body.get("code") == "password_breached"

    @pytest.mark.authenticated_admin
    async def test_admin_post_with_breached_password_returns_password_breached(
        self,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
        _force_breached_api_app: None,
    ):
        """POST /users (create) — same shape as the PATCH path."""

        tenant = test_data["tenants"]["default"]
        response = await test_client_api.post(
            "/users/",
            json={
                "email": "newadmin@bretagne.duchy",
                "email_verified": True,
                "password": "anewlongerpassword",
                "fields": {},
                "tenant_id": str(tenant.id),
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        body = response.json()
        assert body["detail"] == APIErrorCode.USER_CREATE_INVALID_PASSWORD
        assert "reason" in body
        assert body.get("code") == "password_breached"

    @pytest.mark.authenticated_admin
    async def test_admin_patch_with_weak_password_omits_password_breached_code(
        self,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
    ):
        """Regression: a generic invalid-password (e.g. too-short) must
        NOT carry the password_breached discriminator. The breached
        checker stays at its noop default here."""

        user = test_data["users"]["regular"]
        response = await test_client_api.patch(
            f"/users/{user.id}",
            json={"password": "h"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        body = response.json()
        assert body["detail"] == APIErrorCode.USER_UPDATE_INVALID_PASSWORD
        # No discriminator on the generic path.
        assert body.get("code") != "password_breached"
