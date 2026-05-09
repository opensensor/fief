"""Tests for the login-time MFA challenge routes (T14).

Covers ``GET /mfa/totp``, ``POST /mfa/totp``, ``GET /mfa/recover``, and
``POST /mfa/recover``. These routes are reached after the /login POST has
flagged ``LoginSession.mfa_pending_user_id`` for an MFA-enabled user
(see T15 / commit ``3e51874``). They must:

- Refuse to render anything if the LoginSession cookie is missing or its
  ``mfa_pending_user_id`` is unset (anti-hijack), redirecting to /login.
- Honor ``LoginSession.mfa_locked_until`` and bounce locked sessions back
  to /login.
- Defensively self-heal an orphaned ``user.mfa_enabled=true`` flag at the
  GET handlers (calls ``TotpService.disable``, audit-logs
  ``USER_MFA_STATE_INCONSISTENT``, redirects to /login).
- Issue a session cookie + clear MFA carry-state via
  ``AuthenticationFlow.complete_login_after_mfa`` on a valid TOTP code
  (or recovery code), and then redirect to the post-login destination.
- Increment ``LoginSession.mfa_attempts_count`` on a wrong code, and at
  five strikes set ``mfa_locked_until`` and bounce to /login.

The challenge templates (T18) don't exist yet — we splice trivial stubs
ahead of the real loader so the routes can render. The stubs surface the
form's errors as JSON so we can assert against them without exercising
the real templates.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pyotp
import pytest
from fastapi import status
from jinja2 import ChoiceLoader, DictLoader

from fief.db import AsyncSession
from fief.models import UserTotpSecret
from fief.repositories import (
    LoginSessionRepository,
    UserRepository,
    UserTotpSecretRepository,
)
from fief.services.security.encryption import encrypt
from fief.settings import settings
from fief.templates import templates
from tests.data import TestData


# ---------------------------------------------------------------------------
# Stub templates (T18 will own the real ones).
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
    templates.env.loader = ChoiceLoader([DictLoader(_STUB_TEMPLATES), original])
    try:
        yield
    finally:
        templates.env.loader = original


def _body_json(response: httpx.Response) -> dict:
    return json.loads(response.text)


async def _seed_confirmed_totp(
    main_session: AsyncSession, user_id, secret_b32: str
) -> None:
    """Insert a confirmed ``UserTotpSecret`` for ``user_id``.

    Skips ``begin_enrollment`` so we control the secret directly.
    """

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


@pytest.mark.asyncio
class TestMfaTotpGetGating:
    async def test_get_redirects_to_login_when_no_pending_user(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """Without ``mfa_pending_user_id`` set, GET /mfa/totp must redirect
        to /login — no leakage that an MFA challenge does or doesn't exist
        for some other cookie."""
        login_session = test_data["login_sessions"]["default"]
        # Defensive: clear any residue.
        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = None
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        cookies = {settings.login_session_cookie_name: login_session.token}

        response = await test_client_auth_csrf.get(
            "/mfa/totp", cookies=cookies
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")

    async def test_get_redirects_to_login_when_no_login_session_cookie(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
    ):
        """With no LoginSession cookie at all, GET /mfa/totp must redirect
        to /login — generic flash, no leakage."""
        response = await test_client_auth_csrf.get("/mfa/totp")
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")

    async def test_get_redirects_to_login_when_locked(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """If ``mfa_locked_until`` is in the future, GET /mfa/totp must
        redirect to /login."""
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
            "/mfa/totp", cookies=cookies
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")

    async def test_get_orphan_self_heal_when_user_enabled_without_secret(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """If ``user.mfa_enabled`` is True but no confirmed secret exists,
        GET /mfa/totp must call ``TotpService.disable`` (flipping
        ``mfa_enabled=False``), and redirect to /login."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)
        # Make sure no confirmed secret row exists.
        totp_repository = UserTotpSecretRepository(main_session)
        await totp_repository.delete_by_user_id(user.id)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        cookies = {settings.login_session_cookie_name: login_session.token}
        response = await test_client_auth_csrf.get(
            "/mfa/totp", cookies=cookies
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")

        refreshed = await user_repository.get_by_id(user.id)
        assert refreshed is not None
        assert refreshed.mfa_enabled is False

    async def test_get_renders_form_for_valid_pending_session(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """With a valid pending challenge and a confirmed secret, GET
        /mfa/totp must render the form."""
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
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.get(
                "/mfa/totp", cookies=cookies
            )
            assert response.status_code == status.HTTP_200_OK
            body = _body_json(response)
            assert body["has_form"] is True
        finally:
            user.mfa_enabled = False


@pytest.mark.asyncio
class TestMfaTotpPost:
    async def test_post_valid_code_completes_login(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
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
            valid_code = pyotp.TOTP(secret_b32).now()
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/totp",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": valid_code},
            )
            assert response.status_code == status.HTTP_302_FOUND
            # Issued a session cookie via complete_login_after_mfa.
            assert settings.session_cookie_name in response.cookies

            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_pending_user_id is None
            assert refreshed.mfa_attempts_count == 0
            assert refreshed.mfa_locked_until is None
        finally:
            user.mfa_enabled = False

    async def test_post_invalid_code_increments_attempt_counter(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
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
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/totp",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": "000000"},
            )
            # Form-validation passes (regex matches), but the code is wrong;
            # the route re-renders the form with a field error.
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            body = _body_json(response)
            assert body["has_form"] is True
            assert any("invalid" in e.lower() for e in body["errors"])

            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_attempts_count == 1
            assert refreshed.mfa_locked_until is None
            # Pending user id is NOT cleared on a wrong attempt.
            assert refreshed.mfa_pending_user_id == user.id
        finally:
            user.mfa_enabled = False

    async def test_post_fifth_wrong_attempt_locks_session_and_redirects(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """After 5 cumulative wrong attempts, the session is locked for
        10 minutes and the route redirects to /login."""
        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        secret_b32 = pyotp.random_base32()
        await _seed_confirmed_totp(main_session, user.id, secret_b32)

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        # Pretend four wrong attempts have already happened.
        login_session.mfa_attempts_count = 4
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/totp",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": "000000"},
            )
            # Fifth wrong attempt: lock + redirect to /login.
            assert response.status_code == status.HTTP_302_FOUND
            assert response.headers["Location"].endswith("/login")

            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_attempts_count == 5
            assert refreshed.mfa_locked_until is not None
            assert refreshed.mfa_locked_until > datetime.now(UTC)
        finally:
            user.mfa_enabled = False


@pytest.mark.asyncio
class TestMfaRecoverGetGating:
    async def test_get_redirects_to_login_when_no_pending_user(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        login_session = test_data["login_sessions"]["default"]
        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = None
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        cookies = {settings.login_session_cookie_name: login_session.token}
        response = await test_client_auth_csrf.get(
            "/mfa/recover", cookies=cookies
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith("/login")


@pytest.mark.asyncio
class TestMfaRecoverPost:
    async def test_post_valid_recovery_code_disables_mfa_and_completes_login(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        """A valid recovery code consumes the row, calls TotpService.disable
        (forcing re-enroll), issues a session cookie, and clears carry-state."""
        from fief.dependencies.logger import get_audit_logger
        from fief.logger import logger as base_logger
        from fief.logger import AuditLogger
        from fief.repositories.user_mfa_recovery_code import (
            UserMfaRecoveryCodeRepository,
        )
        from fief.services.security.recovery_codes import RecoveryCodeService

        login_session = test_data["login_sessions"]["default"]
        user = test_data["users"]["regular"]
        user_repository = UserRepository(main_session)
        user.mfa_enabled = True
        await user_repository.update(user)

        # Seed a confirmed TOTP secret + recovery codes.
        secret_b32 = pyotp.random_base32()
        await _seed_confirmed_totp(main_session, user.id, secret_b32)
        recovery_repo = UserMfaRecoveryCodeRepository(main_session)
        # Wipe any existing recovery codes from prior tests.
        await recovery_repo.delete_by_user_id(user.id)
        recovery_service = RecoveryCodeService(
            recovery_repo=recovery_repo,
            audit_logger=AuditLogger(base_logger),
        )
        codes = await recovery_service.generate_for(user)
        assert len(codes) == 10

        login_session_repository = LoginSessionRepository(main_session)
        login_session.mfa_pending_user_id = user.id
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)

        try:
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/recover",
                cookies=cookies,
                data={"csrf_token": csrf_token, "code": codes[0]},
            )
            assert response.status_code == status.HTTP_302_FOUND
            # Session cookie issued.
            assert settings.session_cookie_name in response.cookies

            # TOTP was disabled → user.mfa_enabled = False.
            refreshed_user = await user_repository.get_by_id(user.id)
            assert refreshed_user is not None
            assert refreshed_user.mfa_enabled is False

            # Carry-state cleared on the login session.
            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_pending_user_id is None
            assert refreshed.mfa_attempts_count == 0
            assert refreshed.mfa_locked_until is None
        finally:
            user.mfa_enabled = False

    async def test_post_invalid_recovery_code_increments_attempt_counter(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
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
            cookies = {settings.login_session_cookie_name: login_session.token}
            response = await test_client_auth_csrf.post(
                "/mfa/recover",
                cookies=cookies,
                # Well-formed shape (matches XXXX-XXXX regex) but won't
                # match any stored hash.
                data={"csrf_token": csrf_token, "code": "AAAA-BBBB"},
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            body = _body_json(response)
            assert body["has_form"] is True
            assert any("invalid" in e.lower() for e in body["errors"])

            refreshed = await login_session_repository.get_by_token(
                login_session.token, fresh=False
            )
            assert refreshed is not None
            assert refreshed.mfa_attempts_count == 1
            assert refreshed.mfa_locked_until is None
        finally:
            user.mfa_enabled = False
