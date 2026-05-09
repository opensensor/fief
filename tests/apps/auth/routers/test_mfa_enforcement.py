"""Tests for tenant-level MFA enforcement (T16).

When ``tenant.mfa_required`` is ``True`` and the authenticated user has
``user.mfa_enabled = False``, the user must be funneled to the MFA
enrollment landing page (``/security/mfa``). The enforcement applies in
two places:

1. ``/login`` POST — after credentials validate, before the existing
   per-user MFA branch. The session cookie IS issued (via
   ``rotate_session_token``) so the user can navigate the dashboard
   normally to enroll, but they're redirected to ``/security/mfa`` with
   a ``?mfa_required=1`` flag instead of the usual post-login destination.
2. Dashboard route guard — every dashboard route running through
   ``get_base_context`` checks the same condition. If the request path
   isn't already under ``/security/mfa``, the user is redirected to the
   enrollment landing.

Tests intentionally use the same DictLoader stub pattern as
``test_dashboard_mfa.py`` because the real security templates ship in
T17.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi import status
from jinja2 import ChoiceLoader, DictLoader

from fief.crypto.token import get_token_hash
from fief.db import AsyncSession
from fief.repositories import (
    SessionTokenRepository,
    TenantRepository,
    UserRepository,
)
from fief.settings import settings
from fief.templates import templates
from tests.data import TestData, session_token_tokens


# ---------------------------------------------------------------------------
# Stub templates so dashboard routes can render even though the real
# T17/T19 security templates haven't shipped yet. We reuse the same shape
# as ``test_dashboard_mfa.py``.
# ---------------------------------------------------------------------------
_STUB_TEMPLATES = {
    "auth/dashboard/security/index.html": (
        "{{ {'mfa_enabled': mfa_enabled,"
        " 'mfa_enforcement_active': (mfa_enforcement_active|default(False)),"
        " 'error': (error|default(''))|string,"
        " 'success': (success|default(''))|string}|tojson }}"
    ),
}


@pytest.fixture(autouse=True)
def _inject_security_template_stubs():
    original = templates.env.loader
    templates.env.loader = ChoiceLoader([DictLoader(_STUB_TEMPLATES), original])
    try:
        yield
    finally:
        templates.env.loader = original


def _auth_cookies() -> dict:
    return {
        settings.session_cookie_name: session_token_tokens["regular"][0],
    }


@pytest.mark.asyncio
class TestDashboardGuard:
    async def test_tenant_mfa_not_required_dashboard_index_unaffected(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """``tenant.mfa_required=False`` → dashboard index renders normally."""
        user = test_data["users"]["regular"]
        tenant = test_data["tenants"]["default"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)
        tenant.mfa_required = False
        await TenantRepository(main_session).update(tenant)

        response = await test_client_auth_csrf.get(
            "/", cookies=_auth_cookies()
        )
        # Dashboard index renders (200) — no enforcement redirect.
        assert response.status_code == status.HTTP_200_OK

    async def test_tenant_mfa_required_redirects_dashboard_index_to_mfa_enroll(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """``tenant.mfa_required=True`` and user not enrolled → GET ``/`` is
        redirected to ``/security/mfa``."""
        user = test_data["users"]["regular"]
        tenant = test_data["tenants"]["default"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)
        tenant.mfa_required = True
        await TenantRepository(main_session).update(tenant)

        try:
            response = await test_client_auth_csrf.get(
                "/", cookies=_auth_cookies()
            )

            assert response.status_code in (
                status.HTTP_302_FOUND,
                status.HTTP_307_TEMPORARY_REDIRECT,
            )
            location = response.headers["Location"]
            assert "/security/mfa" in location
            # The banner-trigger query flag should be on the redirect.
            assert "mfa_required=1" in location
        finally:
            tenant.mfa_required = False
            await TenantRepository(main_session).update(tenant)

    async def test_tenant_mfa_required_allows_security_mfa_index(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """The enforcement gate must NOT redirect the enrollment landing
        itself (otherwise the user can never enroll)."""
        user = test_data["users"]["regular"]
        tenant = test_data["tenants"]["default"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)
        tenant.mfa_required = True
        await TenantRepository(main_session).update(tenant)

        try:
            response = await test_client_auth_csrf.get(
                "/security/mfa", cookies=_auth_cookies()
            )

            assert response.status_code == status.HTTP_200_OK
            body = json.loads(response.text)
            # Banner flag should be plumbed through the base context.
            assert body["mfa_enforcement_active"] is True
        finally:
            tenant.mfa_required = False
            await TenantRepository(main_session).update(tenant)

    async def test_tenant_mfa_required_user_already_enrolled_dashboard_unaffected(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """If the user is already enrolled, the gate is a no-op even when
        the tenant requires MFA."""
        user = test_data["users"]["regular"]
        tenant = test_data["tenants"]["default"]
        user.mfa_enabled = True
        await UserRepository(main_session).update(user)
        tenant.mfa_required = True
        await TenantRepository(main_session).update(tenant)

        try:
            response = await test_client_auth_csrf.get(
                "/", cookies=_auth_cookies()
            )
            assert response.status_code == status.HTTP_200_OK
        finally:
            user.mfa_enabled = False
            await UserRepository(main_session).update(user)
            tenant.mfa_required = False
            await TenantRepository(main_session).update(tenant)


@pytest.mark.asyncio
class TestLoginEnforcement:
    async def test_tenant_mfa_required_login_redirects_to_enrollment_with_session_cookie(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """``/login`` POST with valid creds, ``tenant.mfa_required=True``
        and user not enrolled: the session cookie IS issued (so they can
        navigate the dashboard to enroll) but they're redirected to
        ``/security/mfa`` with a banner flag rather than the normal
        post-login destination."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        tenant = login_session.client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        user.mfa_enabled = False
        await UserRepository(main_session).update(user)
        tenant.mfa_required = True
        await TenantRepository(main_session).update(tenant)

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
            assert "/security/mfa" in location, (
                f"expected enrollment redirect, got {location!r}"
            )
            assert "mfa_required=1" in location

            # Session cookie WAS issued (unlike the per-user MFA branch).
            assert settings.session_cookie_name in response.cookies
            session_cookie = response.cookies[settings.session_cookie_name]
            session_token_repository = SessionTokenRepository(main_session)
            session_token = await session_token_repository.get_by_token(
                get_token_hash(session_cookie)
            )
            assert session_token is not None
        finally:
            tenant.mfa_required = False
            await TenantRepository(main_session).update(tenant)

    async def test_tenant_mfa_required_user_already_enrolled_takes_normal_mfa_branch(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """``tenant.mfa_required=True`` with a user that's already enrolled
        must STILL take the per-user MFA branch (redirect to
        ``/mfa/totp`` without a session cookie). The tenant gate is
        irrelevant when the user is already enrolled."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        tenant = login_session.client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        user.mfa_enabled = True
        await UserRepository(main_session).update(user)
        tenant.mfa_required = True
        await TenantRepository(main_session).update(tenant)

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
                f"expected per-user MFA challenge redirect, got {location!r}"
            )
            # No session cookie until the challenge succeeds.
            assert settings.session_cookie_name not in response.cookies
        finally:
            user.mfa_enabled = False
            await UserRepository(main_session).update(user)
            tenant.mfa_required = False
            await TenantRepository(main_session).update(tenant)
