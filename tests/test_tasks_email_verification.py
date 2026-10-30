from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fief.repositories import EmailVerificationRepository
from fief.services.email import EmailProvider
from fief.tasks.email_verification import OnEmailVerificationRequestedTask
from tests.data import TestData, email_verification_codes


@pytest.mark.asyncio
class TestTasksOnEmailVerificationRequestedTask:
    async def test_deleted_verification_is_not_sent(
        self, main_session_manager, test_data: TestData
    ):
        verification = test_data["email_verifications"]["not_verified_email"]
        async with main_session_manager() as session:
            repository = EmailVerificationRepository(session)
            await repository.delete_by_user(verification.user_id)

        provider = MagicMock(spec=EmailProvider)
        task = OnEmailVerificationRequestedTask(main_session_manager, provider)
        # A resend, completed verification, or user deletion can invalidate a
        # queued task. Repeated delivery must also be harmless.
        for _ in range(2):
            await task.run(str(verification.id), "fixture-code")
        provider.send_email.assert_not_called()

    async def test_expired_verification_is_not_sent(
        self, main_session_manager, test_data: TestData
    ):
        verification = test_data["email_verifications"]["not_verified_email"]
        async with main_session_manager() as session:
            repository = EmailVerificationRepository(session)
            row = await repository.get_by_id(verification.id)
            assert row is not None
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            await repository.update(row)

        provider = MagicMock(spec=EmailProvider)
        task = OnEmailVerificationRequestedTask(main_session_manager, provider)
        await task.run(str(verification.id), "fixture-code")
        provider.send_email.assert_not_called()

    async def test_database_failure_still_propagates(
        self, main_session_manager, test_data: TestData
    ):
        verification = test_data["email_verifications"]["not_verified_email"]
        provider = MagicMock(spec=EmailProvider)
        task = OnEmailVerificationRequestedTask(main_session_manager, provider)
        with patch.object(
            EmailVerificationRepository, "get_by_id", new_callable=AsyncMock
        ) as lookup:
            lookup.side_effect = RuntimeError("fixture database unavailable")
            with pytest.raises(RuntimeError, match="fixture database unavailable"):
                await task.run(str(verification.id), "fixture-code")
        provider.send_email.assert_not_called()

    async def test_send_verify_email(self, main_session_manager, test_data: TestData):
        email_provider_mock = MagicMock(spec=EmailProvider)

        on_email_verification_requested = OnEmailVerificationRequestedTask(
            main_session_manager, email_provider_mock
        )

        email_verification = test_data["email_verifications"]["not_verified_email"]
        await on_email_verification_requested.run(
            str(email_verification.id),
            email_verification_codes["not_verified_email"][0],
        )

        email_provider_mock.send_email.assert_called_once()

    async def test_delivery_failure_still_propagates(
        self, main_session_manager, test_data: TestData
    ):
        provider = MagicMock(spec=EmailProvider)
        provider.send_email.side_effect = RuntimeError("fixture delivery unavailable")
        task = OnEmailVerificationRequestedTask(main_session_manager, provider)
        verification = test_data["email_verifications"]["not_verified_email"]
        with pytest.raises(RuntimeError, match="fixture delivery unavailable"):
            await task.run(str(verification.id), "fixture-code")
        provider.send_email.assert_called_once()
