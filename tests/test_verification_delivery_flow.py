from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest
from bs4 import BeautifulSoup

from fief.models import Brand
from fief.repositories import (
    EmailTemplateRepository,
    EmailVerificationRepository,
    UserRepository,
)
from fief.services.email import EmailProvider
from fief.settings import settings
from fief.tasks.email_verification import OnEmailVerificationRequestedTask
from fief.tasks.register import OnAfterRegisterTask
from tests.data import session_token_tokens


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "delivery_order", ["old-first", "new-first", "welcome-first", "welcome-last"]
)
async def test_resend_email_can_complete_verification(
    delivery_order,
    test_client_auth,
    test_client_auth_csrf,
    csrf_token,
    main_session,
    main_session_manager,
    test_data,
    send_task_mock,
):
    user = test_data["users"]["not_verified_email"]
    prefix = "" if user.tenant.default else f"/{user.tenant.slug}"
    cookies = {
        settings.session_cookie_name: session_token_tokens["not_verified_email"][0]
    }
    queued = []
    for _ in range(2):
        response = await test_client_auth.get(
            f"{prefix}/verify-request", cookies=cookies
        )
        assert response.status_code == 302
        queued.append(send_task_mock.call_args.args[1:])

    provider = MagicMock(spec=EmailProvider)
    task = OnEmailVerificationRequestedTask(main_session_manager, provider)
    welcome = OnAfterRegisterTask(main_session_manager, MagicMock(spec=EmailProvider))
    if delivery_order == "welcome-first":
        await welcome.run(str(user.id))
    for args in reversed(queued) if delivery_order == "new-first" else queued:
        await task.run(*args)
    if delivery_order == "welcome-last":
        await welcome.run(str(user.id))

    provider.send_email.assert_called_once()
    email = provider.send_email.call_args.kwargs
    assert email["recipient"][0] == user.email
    # Read the actual rendered email, not the code passed to the queue.
    delivered_code = (
        BeautifulSoup(email["html"], "html.parser")
        .get_text()
        .split("VERIFY_EMAIL ")[1]
        .strip()
    )
    assert delivered_code == queued[-1][1]
    response = await test_client_auth_csrf.post(
        f"{prefix}/verify-link",
        data={"code": delivered_code, "csrf_token": csrf_token},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login?verified=1")
    verified = await UserRepository(main_session).get_by_id(user.id)
    assert verified is not None and verified.email_verified
    assert await EmailVerificationRepository(main_session).get_by_user(user.id) == []
    # A duplicate delivery after successful verification must neither fail nor
    # create a new code or send another email.
    await task.run(*queued[-1])
    provider.send_email.assert_called_once()


@pytest.mark.asyncio
async def test_expired_request_can_be_resent_and_completed(
    test_client_auth,
    test_client_auth_csrf,
    csrf_token,
    main_session,
    main_session_manager,
    test_data,
    send_task_mock,
):
    user = test_data["users"]["not_verified_email"]
    repository = EmailVerificationRepository(main_session)
    row = await repository.get_by_id(
        test_data["email_verifications"]["not_verified_email"].id
    )
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await repository.update(row)
    provider = MagicMock(spec=EmailProvider)
    task = OnEmailVerificationRequestedTask(main_session_manager, provider)
    await task.run(str(row.id), "expired-fixture-code")
    provider.send_email.assert_not_called()
    prefix = "" if user.tenant.default else f"/{user.tenant.slug}"
    response = await test_client_auth.get(
        f"{prefix}/verify-request",
        cookies={
            settings.session_cookie_name: session_token_tokens["not_verified_email"][0],
        },
    )
    assert response.status_code == 302
    await task.run(*send_task_mock.call_args.args[1:])
    provider.send_email.assert_called_once()
    code = (
        BeautifulSoup(provider.send_email.call_args.kwargs["html"], "html.parser")
        .get_text()
        .split("VERIFY_EMAIL ")[1]
        .strip()
    )
    response = await test_client_auth_csrf.post(
        f"{prefix}/verify-link", data={"code": code, "csrf_token": csrf_token}
    )
    assert response.headers["Location"].endswith("/login?verified=1")
    verified = await UserRepository(main_session).get_by_id(user.id)
    assert verified is not None and verified.email_verified


@pytest.mark.asyncio
@pytest.mark.parametrize("attempts,delivered_attempt", [(1, 0), (2, 0), (2, 1)])
async def test_welcome_email_without_pending_request_can_complete_verification(
    attempts,
    delivered_attempt,
    test_client_auth_csrf,
    csrf_token,
    main_session,
    main_session_manager,
    test_data,
):
    user = test_data["users"]["not_verified_email"]
    await EmailVerificationRepository(main_session).delete_by_user(user.id)
    template = test_data["email_templates"]["welcome"]
    template.content = '<a id="verify" href="{{ verify_url }}">Verify email</a>'
    await EmailTemplateRepository(main_session).update(template)
    brand = Brand(
        name="Fixture",
        host="members.example.com",
        application_url="https://app.example.com",
        is_default=True,
        tenant_id=user.tenant_id,
    )
    main_session.add(brand)
    await main_session.commit()
    provider = MagicMock(spec=EmailProvider)
    task = OnAfterRegisterTask(main_session_manager, provider)
    if attempts == 2:
        # SMTP can accept a message before the connection fails. A retry must
        # leave either email's link usable until verification succeeds.
        provider.send_email.side_effect = RuntimeError("fixture delivery interrupted")
        with pytest.raises(RuntimeError, match="fixture delivery interrupted"):
            await task.run(str(user.id), str(brand.id))
        provider.send_email.side_effect = None
    await task.run(str(user.id), str(brand.id))
    assert provider.send_email.call_count == attempts
    html = BeautifulSoup(
        provider.send_email.call_args_list[delivered_attempt].kwargs["html"],
        "html.parser",
    )
    link = urlparse(html.find("a", id="verify")["href"])
    code = parse_qs(link.query)["code"][0]
    response = await test_client_auth_csrf.post(
        link.path, data={"code": code, "csrf_token": csrf_token}
    )
    assert response.headers["Location"].endswith("/login?verified=1")
    verified = await UserRepository(main_session).get_by_id(user.id)
    assert verified.email_verified
    assert await EmailVerificationRepository(main_session).get_by_user(user.id) == []
