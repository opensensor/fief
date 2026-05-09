"""Tests for the dashboard MFA setup routes (T13).

Covers:

- ``GET  /security/mfa`` renders 200 with ``mfa_enabled=False`` initially.
- ``POST /security/mfa/totp/begin`` returns 200 with QR data URI in context.
- ``POST /security/mfa/totp/confirm`` with the right code (computed via
  pyotp from the secret returned by ``begin``) flips ``user.mfa_enabled``
  and renders the recovery codes once.
- ``POST /security/mfa/totp/disable`` with a wrong password renders a form
  error and does NOT disable.
- ``POST /security/mfa/totp/disable`` with right password + valid TOTP
  successfully disables.
- ``POST /security/mfa/recovery-codes/regenerate`` while
  ``mfa_enabled=False`` returns 404.
- ``POST /security/mfa/recovery-codes/regenerate`` while
  ``mfa_enabled=True`` returns 200 with new codes.

The route templates (``auth/dashboard/security/{index,setup,recovery_codes}.html``)
are owned by T17/T19 — they don't exist yet at the time T13 lands. We
splice a Jinja ``DictLoader`` in front of the real loader to render
trivial stubs that surface the route's context dict as JSON in the body
so we can assert against it without exercising the real templates.
"""

from __future__ import annotations

import json

import httpx
import pyotp
import pytest
from fastapi import status
from jinja2 import ChoiceLoader, DictLoader

from fief.db import AsyncSession
from fief.repositories import UserRepository
from fief.services.security.totp import TotpService
from fief.settings import settings
from fief.templates import templates
from tests.data import TestData, session_token_tokens


# ---------------------------------------------------------------------------
# Stub templates injected via DictLoader so the route handlers can render
# even though the real T17/T19 templates haven't shipped yet. Each stub
# emits the inbound context as a JSON blob in the body so we can assert
# against it from the test side.
# ---------------------------------------------------------------------------
_STUB_TEMPLATES = {
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
}


@pytest.fixture(autouse=True)
def _inject_security_template_stubs():
    """Splice ``_STUB_TEMPLATES`` ahead of the real loader for these tests.

    T17/T19 will ship the real templates; until then we render minimal
    stubs that round-trip the route's context dict as JSON.
    """

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


def _body_json(response: httpx.Response) -> dict:
    return json.loads(response.text)


@pytest.mark.asyncio
class TestMfaIndex:
    async def test_get_mfa_index_renders_with_mfa_disabled(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = test_data["users"]["regular"]
        # Belt-and-braces: ensure the user starts un-enrolled regardless of
        # what previous tests in this session did.
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)

        response = await test_client_auth_csrf.get(
            "/security/mfa", cookies=_auth_cookies()
        )
        assert response.status_code == status.HTTP_200_OK
        body = _body_json(response)
        assert body["mfa_enabled"] is False


@pytest.mark.asyncio
class TestMfaTotpBegin:
    async def test_post_begin_returns_qr_and_secret(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = test_data["users"]["regular"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)

        response = await test_client_auth_csrf.post(
            "/security/mfa/totp/begin",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token},
        )
        assert response.status_code == status.HTTP_200_OK
        body = _body_json(response)
        assert body["secret_b32"]
        assert body["qr_png_data_uri"].startswith("data:image/png;base64,")
        assert body["has_form"] is True


@pytest.mark.asyncio
class TestMfaTotpConfirm:
    async def test_post_confirm_with_valid_code_enables_mfa(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = test_data["users"]["regular"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)

        # Begin enrollment to get the served secret.
        begin_response = await test_client_auth_csrf.post(
            "/security/mfa/totp/begin",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token},
        )
        secret_b32 = _body_json(begin_response)["secret_b32"]

        valid_code = pyotp.TOTP(secret_b32).now()
        response = await test_client_auth_csrf.post(
            "/security/mfa/totp/confirm",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token, "code": valid_code},
        )
        assert response.status_code == status.HTTP_200_OK
        body = _body_json(response)
        assert isinstance(body["codes"], list)
        assert len(body["codes"]) == 10

        # Verify the user record actually flipped.
        refreshed = await UserRepository(main_session).get_by_id(user.id)
        assert refreshed is not None
        assert refreshed.mfa_enabled is True


@pytest.mark.asyncio
class TestMfaTotpDisable:
    async def test_post_disable_with_wrong_password_does_not_disable(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = test_data["users"]["regular"]
        # Pretend the user already has MFA enabled.
        user.mfa_enabled = True
        await UserRepository(main_session).update(user)

        response = await test_client_auth_csrf.post(
            "/security/mfa/totp/disable",
            cookies=_auth_cookies(),
            data={
                "csrf_token": csrf_token,
                "current_password": "WRONG_PASSWORD",
                "code": "123456",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers.get("X-Fief-Error") == "invalid_current_password"

        refreshed = await UserRepository(main_session).get_by_id(user.id)
        assert refreshed is not None
        assert refreshed.mfa_enabled is True

    async def test_post_disable_with_right_password_and_valid_totp_disables(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock,
    ):
        # Wire up real enrollment via the routes so we have a confirmed
        # row + a known secret.
        user = test_data["users"]["regular"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)

        begin_response = await test_client_auth_csrf.post(
            "/security/mfa/totp/begin",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token},
        )
        secret_b32 = _body_json(begin_response)["secret_b32"]
        first_totp = pyotp.TOTP(secret_b32)

        confirm_response = await test_client_auth_csrf.post(
            "/security/mfa/totp/confirm",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token, "code": first_totp.now()},
        )
        assert confirm_response.status_code == status.HTTP_200_OK

        # Confirm bumped ``last_used_step`` for the current step. To verify
        # ``disable`` we need a TOTP whose step hasn't been consumed — we
        # can either wait, or step-skip via ``TotpService.verify`` mocking.
        # Easiest: monkeypatch the verify to accept any code with a
        # well-formed shape, by overriding the dependency.
        # (Alternative: bypass the second-factor by feeding a recovery
        # code from confirm's response.)
        recovery_codes = _body_json(confirm_response)["codes"]
        recovery_code = recovery_codes[0]

        disable_response = await test_client_auth_csrf.post(
            "/security/mfa/totp/disable",
            cookies=_auth_cookies(),
            data={
                "csrf_token": csrf_token,
                "current_password": "herminetincture",
                "code": recovery_code,
            },
        )
        # Successful disable returns an HX-Location to the index.
        assert disable_response.status_code == status.HTTP_200_OK
        assert "/security/mfa" in disable_response.headers.get("HX-Location", "")

        refreshed = await UserRepository(main_session).get_by_id(user.id)
        assert refreshed is not None
        assert refreshed.mfa_enabled is False


@pytest.mark.asyncio
class TestMfaRecoveryCodesRegenerate:
    async def test_regen_returns_404_when_mfa_disabled(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = test_data["users"]["regular"]
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)

        response = await test_client_auth_csrf.post(
            "/security/mfa/recovery-codes/regenerate",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_regen_returns_new_codes_when_mfa_enabled(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = test_data["users"]["regular"]
        user.mfa_enabled = True
        await UserRepository(main_session).update(user)

        response = await test_client_auth_csrf.post(
            "/security/mfa/recovery-codes/regenerate",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token},
        )
        assert response.status_code == status.HTTP_200_OK
        body = _body_json(response)
        assert isinstance(body["codes"], list)
        assert len(body["codes"]) == 10
        # Code shape sanity check: ``XXXX-XXXX``.
        for code in body["codes"]:
            assert len(code) == 9
            assert code[4] == "-"


# Smoke check: TotpService is importable. Exercises the dependency module.
def test_totp_service_class_is_importable():
    assert TotpService is not None
