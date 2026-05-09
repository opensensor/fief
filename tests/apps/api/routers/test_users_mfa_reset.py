"""Integration tests for the admin MFA reset endpoint (T21).

The route under test:

    POST /users/{id}/mfa/reset

Behaviour spec:

- Requires admin authentication (same dependency as the other admin user
  routes -- ``is_authenticated_admin_api``). Unauthenticated callers get 401.
- Returns 204 on success and the user's ``mfa_enabled`` flag flips to
  ``False``.
- Idempotent: an already-disabled user still returns 204 (no 4xx).
- Returns 404 when the user id doesn't exist.
- Audits both ``USER_MFA_DISABLED`` (emitted by ``TotpService.disable``)
  and ``USER_MFA_FORCE_REENROLLED`` (emitted directly by the route, with
  ``extra`` containing the admin actor reference).
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import status

from fief.apps import api_app
from fief.db import AsyncSession
from fief.dependencies.logger import get_audit_logger
from fief.logger import AuditLogger, logger as loguru_logger
from fief.models import AuditLogMessage
from fief.repositories import UserRepository
from tests.data import TestData
from tests.helpers import HTTPXResponseAssertion


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    """Return a ``MagicMock`` wrapping a real :class:`AuditLogger`.

    The mock is wired into the ``api_app`` via ``dependency_overrides`` so
    the route under test sees this exact instance and we can inspect every
    invocation. We use ``wraps=...`` so the underlying loguru calls still
    fire; assertions go through the mock's ``call_args_list``.
    """

    real = AuditLogger(loguru_logger)
    mock = MagicMock(spec=AuditLogger, wraps=real)
    # ``wraps`` doesn't propagate attribute access by default for non-callable
    # attributes; set them explicitly so the route's optional reads
    # (``audit_logger.admin_user_id``) work transparently.
    mock.admin_user_id = real.admin_user_id
    mock.admin_api_key_id = real.admin_api_key_id
    return mock


@pytest.fixture
def _override_audit_logger(
    captured_audit_logger: MagicMock,
    test_client_api: httpx.AsyncClient,
):
    """Splice the captured logger into ``api_app`` for every test in this
    module.

    Depends on ``test_client_api`` so the override happens *after* the
    test client generator has reset ``api_app.dependency_overrides`` (it
    does so on every test) -- otherwise our override gets wiped before
    the request is actually issued.
    """

    api_app.dependency_overrides[get_audit_logger] = (
        lambda: captured_audit_logger
    )
    try:
        yield
    finally:
        api_app.dependency_overrides.pop(get_audit_logger, None)


def _audit_messages(mock: MagicMock) -> list[AuditLogMessage]:
    """Extract the :class:`AuditLogMessage` from every call to ``mock``."""

    return [
        call.args[0]
        for call in mock.call_args_list
        if call.args and isinstance(call.args[0], AuditLogMessage)
    ]


@pytest.mark.asyncio
class TestForceReenrollMfa:
    async def test_unauthorized(
        self,
        unauthorized_api_assertions: HTTPXResponseAssertion,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
    ):
        """Calls without admin credentials must fail with the API's
        standard 401 (parametrized via ``unauthorized_api_assertions``)."""

        user = test_data["users"]["regular"]
        response = await test_client_api.post(f"/users/{user.id}/mfa/reset")
        unauthorized_api_assertions(response)

    @pytest.mark.authenticated_admin
    async def test_not_existing(
        self,
        test_client_api: httpx.AsyncClient,
        not_existing_uuid: uuid.UUID,
    ):
        """An unknown user id returns 404."""

        response = await test_client_api.post(
            f"/users/{not_existing_uuid}/mfa/reset"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.authenticated_admin
    async def test_resets_enrolled_user(
        self,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
        """A user with ``mfa_enabled=True`` is wiped: 204, flag flips to
        False, both audit messages are emitted."""

        user = test_data["users"]["regular"]
        user_id = user.id  # capture before any potential expiration
        # Flip the flag directly via the test session (no enrolled secret
        # row needed - ``TotpService.disable`` is idempotent).
        user.mfa_enabled = True
        main_session.add(user)
        await main_session.commit()

        response = await test_client_api.post(f"/users/{user_id}/mfa/reset")

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert response.content == b""

        # Re-load the user from the database to confirm persistence.
        # ``expire_all`` discards any cached attribute state on objects
        # already attached to ``main_session`` so the next read goes back
        # to the DB.
        main_session.expire_all()
        user_repository = UserRepository(main_session)
        refreshed = await user_repository.get_by_id(user_id)
        assert refreshed is not None
        assert refreshed.mfa_enabled is False

        messages = _audit_messages(captured_audit_logger)
        assert AuditLogMessage.USER_MFA_DISABLED in messages
        assert AuditLogMessage.USER_MFA_FORCE_REENROLLED in messages

        # Inspect the force-reenroll call's kwargs to confirm the admin
        # actor identifier travels in ``extra``.
        force_reenroll_calls = [
            call
            for call in captured_audit_logger.call_args_list
            if call.args
            and call.args[0] is AuditLogMessage.USER_MFA_FORCE_REENROLLED
        ]
        assert len(force_reenroll_calls) == 1
        kwargs = force_reenroll_calls[0].kwargs
        assert kwargs.get("subject_user_id") == user_id
        assert "extra" in kwargs
        assert "admin_user_id" in kwargs["extra"]

    @pytest.mark.authenticated_admin
    async def test_idempotent_when_disabled(
        self,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
        """A user that is already ``mfa_enabled=False`` still returns 204
        (the operation is idempotent for support workflows)."""

        user = test_data["users"]["regular_secondary"]
        user_id = user.id  # capture before any potential expiration
        # Make sure it's explicitly disabled.
        user.mfa_enabled = False
        main_session.add(user)
        await main_session.commit()

        response = await test_client_api.post(f"/users/{user_id}/mfa/reset")

        assert response.status_code == status.HTTP_204_NO_CONTENT

        main_session.expire_all()
        user_repository = UserRepository(main_session)
        refreshed = await user_repository.get_by_id(user_id)
        assert refreshed is not None
        assert refreshed.mfa_enabled is False

        # Even on idempotent runs, the audit trail still records that an
        # admin force-reenroll was requested.
        messages = _audit_messages(captured_audit_logger)
        assert AuditLogMessage.USER_MFA_FORCE_REENROLLED in messages
