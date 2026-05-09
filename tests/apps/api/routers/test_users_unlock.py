"""Integration tests for the admin unlock-account endpoint (SEC-1 T15).

The route under test:

    POST /users/{id}/unlock

Behaviour spec (mirrors the MFA-1 ``/mfa/reset`` endpoint pattern):

- Requires admin authentication (the ``is_authenticated_admin_api``
  router-level dep). Unauthenticated callers get the standard 401.
- Returns 404 when the user id doesn't exist.
- Returns 204 on success and clears any active lockout row
  (``failed_count`` -> 0, ``locked_until`` -> None).
- Idempotent: calling on a user with no lockout row still returns 204
  and still emits the ``USER_ACCOUNT_ADMIN_UNLOCKED`` audit message.
- The audit call carries ``subject_user_id`` set to the target user and
  ``extra`` containing an ``admin_user_id`` reference for forensic
  attribution.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import status

from fief.apps import api_app
from fief.db import AsyncSession
from fief.dependencies.logger import get_audit_logger
from fief.logger import AuditLogger, logger as loguru_logger
from fief.models import AuditLogMessage
from fief.repositories import UserLockoutRepository
from tests.data import TestData
from tests.helpers import HTTPXResponseAssertion


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    """Return a ``MagicMock`` wrapping a real :class:`AuditLogger`.

    Same pattern as ``test_users_mfa_reset``: ``wraps`` keeps the real
    loguru calls firing while ``call_args_list`` lets us inspect each
    invocation. ``admin_user_id`` / ``admin_api_key_id`` must be set
    explicitly because ``wraps`` doesn't proxy non-callable attribute
    access, and the route reads ``audit_logger.admin_user_id`` directly.
    """

    real = AuditLogger(loguru_logger)
    mock = MagicMock(spec=AuditLogger, wraps=real)
    mock.admin_user_id = real.admin_user_id
    mock.admin_api_key_id = real.admin_api_key_id
    return mock


@pytest.fixture
def _override_audit_logger(
    captured_audit_logger: MagicMock,
    test_client_api: httpx.AsyncClient,
):
    """Splice the captured logger into ``api_app`` for every test in
    this module.

    Depends on ``test_client_api`` so the override happens *after* the
    test client generator has reset ``api_app.dependency_overrides`` —
    otherwise the override is wiped before the request issues.
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
class TestUnlockAccount:
    async def test_unauthorized(
        self,
        unauthorized_api_assertions: HTTPXResponseAssertion,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
    ):
        """Calls without admin credentials must fail with the API's
        standard 401 (parametrized via ``unauthorized_api_assertions``)."""

        user = test_data["users"]["regular"]
        response = await test_client_api.post(f"/users/{user.id}/unlock")
        unauthorized_api_assertions(response)

    @pytest.mark.authenticated_admin
    async def test_not_existing(
        self,
        test_client_api: httpx.AsyncClient,
        not_existing_uuid: uuid.UUID,
    ):
        """An unknown user id returns 404."""

        response = await test_client_api.post(
            f"/users/{not_existing_uuid}/unlock"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.authenticated_admin
    async def test_unlocks_locked_user(
        self,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
        """A user with an active lockout (failed_count=10, locked_until
        in the future) is unlocked: 204, the lockout row is cleared, and
        ``USER_ACCOUNT_ADMIN_UNLOCKED`` is emitted with
        ``subject_user_id`` = target user and ``extra.admin_user_id``."""

        user = test_data["users"]["regular"]
        user_id = user.id  # capture before any potential expiration
        repo = UserLockoutRepository(main_session)
        future = datetime.now(UTC) + timedelta(minutes=15)
        await repo.upsert(
            user_id, failed_count=10, locked_until=future
        )

        try:
            response = await test_client_api.post(
                f"/users/{user_id}/unlock"
            )

            assert response.status_code == status.HTTP_204_NO_CONTENT
            assert response.content == b""

            # Re-load the lockout row to confirm it was cleared (the
            # repo's ``clear`` zeros ``failed_count`` and nulls
            # ``locked_until`` on the existing row rather than deleting).
            main_session.expire_all()
            refreshed = await repo.get_by_user_id(user_id)
            assert refreshed is not None
            assert refreshed.failed_count == 0
            assert refreshed.locked_until is None

            messages = _audit_messages(captured_audit_logger)
            assert AuditLogMessage.USER_ACCOUNT_ADMIN_UNLOCKED in messages

            unlock_calls = [
                call
                for call in captured_audit_logger.call_args_list
                if call.args
                and call.args[0]
                is AuditLogMessage.USER_ACCOUNT_ADMIN_UNLOCKED
            ]
            assert len(unlock_calls) == 1
            kwargs = unlock_calls[0].kwargs
            assert kwargs.get("subject_user_id") == user_id
            assert "extra" in kwargs
            assert "admin_user_id" in kwargs["extra"]
        finally:
            # Clean up so other tests in the broader test session don't
            # see stale lockout state on the shared ``regular`` user.
            await repo.clear(user_id)

    @pytest.mark.authenticated_admin
    async def test_idempotent_when_no_lockout_row(
        self,
        test_client_api: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
        """A user with no lockout row at all still returns 204 and still
        emits the audit message — the operation is idempotent for
        support workflows."""

        user = test_data["users"]["regular_secondary"]
        user_id = user.id

        # Make sure no row exists for this user.
        repo = UserLockoutRepository(main_session)
        await repo.clear(user_id)
        assert await repo.get_by_user_id(user_id) is None

        response = await test_client_api.post(f"/users/{user_id}/unlock")

        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Still no row (the service ``reset`` is a no-op when there's
        # nothing to clear).
        main_session.expire_all()
        assert await repo.get_by_user_id(user_id) is None

        # Audit message still fires.
        messages = _audit_messages(captured_audit_logger)
        assert AuditLogMessage.USER_ACCOUNT_ADMIN_UNLOCKED in messages
