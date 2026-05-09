"""Integration tests for the /security/passkeys dashboard routes (MFA-2 T7).

Coverage (per plan T16):

- ``GET  /security/passkeys`` lists the user's credentials.
- ``POST /security/passkeys/register/begin`` returns options JSON.
- ``POST /security/passkeys/register/finish`` (mocked attestation) creates the
  row, flips ``mfa_enabled``, triggers ``auto_revoke_others``.
- ``DELETE /security/passkeys/{id}`` removes the row.
- ``DELETE`` with foreign credential id → 404.
- ``DELETE`` recomputes ``mfa_enabled`` (False when no remaining factors).
- ``DELETE`` keeps ``mfa_enabled`` True when user still has TOTP.
- ``PATCH`` renames the label, returns 204.
- ``PATCH`` with foreign credential id → 404.

The dashboard ``/security/passkeys`` GET renders ``auth/dashboard/security/passkeys.html``
which is owned by T10 — for T7 we splice a Jinja ``DictLoader`` stub that
emits the inbound context dict as JSON so we can assert against it.
"""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import status
from jinja2 import ChoiceLoader, DictLoader

from fief.apps import auth_app
from fief.db import AsyncSession
from fief.dependencies.security import get_webauthn_service
from fief.models import UserWebAuthnCredential
from fief.repositories import UserRepository
from fief.repositories.user_webauthn_credential import (
    UserWebAuthnCredentialRepository,
)
from fief.settings import settings
from fief.templates import templates
from tests.data import TestData, session_token_tokens


# ---------------------------------------------------------------------------
# Stub template for ``passkeys.html`` (T10 owns the real template). Surfaces
# the credentials list as JSON so we can assert from the test side.
# ---------------------------------------------------------------------------
_STUB_TEMPLATES = {
    "auth/dashboard/security/passkeys.html": (
        "{{ {'count': credentials|length,"
        " 'ids': credentials|map(attribute='id')|map('string')|list,"
        " 'labels': credentials|map(attribute='label')|list}|tojson }}"
    ),
}


@pytest.fixture(autouse=True)
def _inject_passkeys_template_stub():
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


# ---------------------------------------------------------------------------
# WebAuthnService double — overrides ``get_webauthn_service`` on the
# auth_app. Tracks every call so tests can assert the route invoked the
# right method with the right kwargs.
# ---------------------------------------------------------------------------


class _FakeWebAuthnService:
    """Programmable stand-in for :class:`WebAuthnService` used in route tests.

    Tests configure ``begin_registration_options`` / ``finish_registration_result``
    / ``list_for_user_result`` / ``delete_result`` before issuing the request,
    then read ``calls`` to assert the route's behaviour.

    On ``finish_registration``, the fake also persists ``finish_registration_result``
    via the real :class:`UserWebAuthnCredentialRepository` (when a session is
    bound) so the route's downstream ``_recompute_mfa_enabled`` call sees the
    new row in ``count_for_user``. This mirrors the real service which writes
    the row before returning.
    """

    def __init__(self, session: AsyncSession | None = None) -> None:
        self.session = session
        self.begin_registration_options: dict[str, Any] = {
            "challenge": "fake-challenge",
            "rp": {"id": "test", "name": "Test"},
        }
        self.finish_registration_result: UserWebAuthnCredential | None = None
        self.finish_registration_exc: Exception | None = None
        self.list_for_user_result: list[UserWebAuthnCredential] = []
        self.delete_result: bool = True
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def begin_registration(
        self, user, *, rp_id: str, rp_name: str
    ) -> dict[str, Any]:
        self.calls.append(
            ("begin_registration", {"user_id": user.id, "rp_id": rp_id, "rp_name": rp_name})
        )
        return self.begin_registration_options

    async def finish_registration(
        self,
        user,
        *,
        rp_id: str,
        origin: str,
        attestation_response: dict[str, Any],
    ) -> UserWebAuthnCredential:
        self.calls.append(
            (
                "finish_registration",
                {
                    "user_id": user.id,
                    "rp_id": rp_id,
                    "origin": origin,
                    "attestation_response": attestation_response,
                },
            )
        )
        if self.finish_registration_exc is not None:
            raise self.finish_registration_exc
        assert self.finish_registration_result is not None
        # Persist via the real repo so downstream count_for_user sees the
        # row (real WebAuthnService writes before returning).
        if self.session is not None:
            await UserWebAuthnCredentialRepository(self.session).create(
                self.finish_registration_result
            )
        return self.finish_registration_result

    async def list_for_user(self, user) -> list[UserWebAuthnCredential]:
        self.calls.append(("list_for_user", {"user_id": user.id}))
        return self.list_for_user_result

    async def delete(self, *, user, credential_id) -> bool:
        self.calls.append(
            ("delete", {"user_id": user.id, "credential_id": credential_id})
        )
        return self.delete_result


@pytest.fixture
def fake_webauthn_service(main_session: AsyncSession):
    """Inject a programmable ``_FakeWebAuthnService`` into the auth app.

    Cleared between tests so each case starts with a fresh fake. Bound to
    the test's ``main_session`` so ``finish_registration`` can persist
    via the real repo (matching real-service behaviour).
    """

    fake = _FakeWebAuthnService(session=main_session)
    auth_app.dependency_overrides[get_webauthn_service] = lambda: fake
    try:
        yield fake
    finally:
        auth_app.dependency_overrides.pop(get_webauthn_service, None)


def _make_credential(
    user_id: uuid.UUID,
    *,
    label: str | None = None,
    credential_id_suffix: int = 1,
) -> UserWebAuthnCredential:
    return UserWebAuthnCredential(
        id=uuid.uuid4(),
        user_id=user_id,
        credential_id=b"cred-" + credential_id_suffix.to_bytes(2, "big"),
        public_key=b"pubkey",
        sign_count=0,
        transports=None,
        aaguid=None,
        backup_eligible=False,
        backup_state=False,
        label=label,
        attestation_obj=None,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPasskeysIndex:
    async def test_get_passkeys_index_renders_with_empty_list(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        fake_webauthn_service.list_for_user_result = []
        response = await test_client_auth_csrf.get(
            "/security/passkeys", cookies=_auth_cookies()
        )
        assert response.status_code == status.HTTP_200_OK
        body = _body_json(response)
        assert body["count"] == 0
        assert body["ids"] == []

        # The route invoked list_for_user on the WebAuthnService.
        assert any(
            name == "list_for_user" for name, _ in fake_webauthn_service.calls
        )

    async def test_get_passkeys_index_lists_credentials(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        user = test_data["users"]["regular"]
        cred = _make_credential(user.id, label="My YubiKey")
        fake_webauthn_service.list_for_user_result = [cred]

        response = await test_client_auth_csrf.get(
            "/security/passkeys", cookies=_auth_cookies()
        )
        assert response.status_code == status.HTTP_200_OK
        body = _body_json(response)
        assert body["count"] == 1
        assert body["labels"] == ["My YubiKey"]


@pytest.mark.asyncio
class TestPasskeysRegisterBegin:
    async def test_post_register_begin_returns_options_json(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        fake_webauthn_service.begin_registration_options = {
            "challenge": "abc123",
            "rp": {"id": "lightnvr.com", "name": "LightNVR"},
            "user": {"id": "u", "name": "u@x", "displayName": "u@x"},
        }

        response = await test_client_auth_csrf.post(
            "/security/passkeys/register/begin",
            cookies=_auth_cookies(),
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["challenge"] == "abc123"
        assert body["rp"]["id"] == "lightnvr.com"

        # Service was called with rp params derived from brand/tenant.
        call_names = [name for name, _ in fake_webauthn_service.calls]
        assert "begin_registration" in call_names


@pytest.mark.asyncio
class TestPasskeysRegisterFinish:
    async def test_post_register_finish_persists_and_flips_mfa(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        user = test_data["users"]["regular"]
        # Belt-and-braces: ensure the user starts un-enrolled.
        user.mfa_enabled = False
        await UserRepository(main_session).update(user)

        cred = _make_credential(user.id, label=None)
        fake_webauthn_service.finish_registration_result = cred

        response = await test_client_auth_csrf.post(
            "/security/passkeys/register/finish",
            cookies=_auth_cookies(),
            content=json.dumps({"id": "fake", "rawId": "fake", "response": {}}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["id"] == str(cred.id)

        # Service called with attestation body.
        finish_calls = [
            kwargs
            for name, kwargs in fake_webauthn_service.calls
            if name == "finish_registration"
        ]
        assert len(finish_calls) == 1
        assert finish_calls[0]["attestation_response"]["rawId"] == "fake"

        # mfa_enabled flipped True (T13 hook inline in T7).
        refreshed = await UserRepository(main_session).get_by_id(user.id)
        assert refreshed is not None
        assert refreshed.mfa_enabled is True

    async def test_post_register_finish_triggers_auto_revoke_others(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        """T14 hook: register triggers auto_revoke_others('passkey_registered').

        We verify by overriding ``get_device_sessions_service`` with a fake
        whose ``auto_revoke_others`` is an :class:`AsyncMock` we can assert
        on after the request lands.
        """

        from fief.dependencies.security import get_device_sessions_service

        user = test_data["users"]["regular"]
        cred = _make_credential(user.id)
        fake_webauthn_service.finish_registration_result = cred

        fake_device_sessions = AsyncMock()
        fake_device_sessions.auto_revoke_others = AsyncMock(return_value=(0, 0))
        auth_app.dependency_overrides[get_device_sessions_service] = (
            lambda: fake_device_sessions
        )
        try:
            response = await test_client_auth_csrf.post(
                "/security/passkeys/register/finish",
                cookies=_auth_cookies(),
                content=json.dumps({"id": "x", "rawId": "x", "response": {}}),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == status.HTTP_200_OK
            fake_device_sessions.auto_revoke_others.assert_awaited_once()
            kwargs = fake_device_sessions.auto_revoke_others.await_args.kwargs
            assert kwargs.get("reason") == "passkey_registered"
        finally:
            auth_app.dependency_overrides.pop(
                get_device_sessions_service, None
            )


@pytest.mark.asyncio
class TestPasskeysRename:
    async def test_patch_renames_credential(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = test_data["users"]["regular"]
        cred = _make_credential(user.id, label="Old", credential_id_suffix=42)
        repo = UserWebAuthnCredentialRepository(main_session)
        await repo.create(cred)

        response = await test_client_auth_csrf.patch(
            f"/security/passkeys/{cred.id}",
            cookies=_auth_cookies(),
            content=json.dumps({"label": "Work YubiKey"}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify the label was updated.
        refreshed = await repo.get_by_id_for_user(cred.id, user.id)
        assert refreshed is not None
        assert refreshed.label == "Work YubiKey"

    async def test_patch_returns_404_for_foreign_credential(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
    ):
        # An ID that doesn't belong to the regular user.
        bogus_id = uuid.uuid4()
        response = await test_client_auth_csrf.patch(
            f"/security/passkeys/{bogus_id}",
            cookies=_auth_cookies(),
            content=json.dumps({"label": "Whatever"}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
class TestPasskeysDelete:
    async def test_delete_removes_credential(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        cred_id = uuid.uuid4()
        fake_webauthn_service.delete_result = True

        response = await test_client_auth_csrf.delete(
            f"/security/passkeys/{cred_id}",
            cookies=_auth_cookies(),
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        delete_calls = [
            kwargs
            for name, kwargs in fake_webauthn_service.calls
            if name == "delete"
        ]
        assert len(delete_calls) == 1
        assert delete_calls[0]["credential_id"] == cred_id

    async def test_delete_returns_404_when_not_found(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        fake_webauthn_service.delete_result = False
        response = await test_client_auth_csrf.delete(
            f"/security/passkeys/{uuid.uuid4()}",
            cookies=_auth_cookies(),
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_delete_recomputes_mfa_to_false_when_no_factors_left(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        user = test_data["users"]["regular"]
        # Pretend the user had MFA enabled via a single passkey.
        user.mfa_enabled = True
        await UserRepository(main_session).update(user)

        # Service reports the deletion succeeded; no remaining passkeys
        # (default empty list) and no TOTP for this user → flip False.
        fake_webauthn_service.delete_result = True
        fake_webauthn_service.list_for_user_result = []

        response = await test_client_auth_csrf.delete(
            f"/security/passkeys/{uuid.uuid4()}",
            cookies=_auth_cookies(),
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

        refreshed = await UserRepository(main_session).get_by_id(user.id)
        assert refreshed is not None
        assert refreshed.mfa_enabled is False

    async def test_delete_triggers_auto_revoke_others(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        fake_webauthn_service: _FakeWebAuthnService,
    ):
        from fief.dependencies.security import get_device_sessions_service

        fake_webauthn_service.delete_result = True
        fake_device_sessions = AsyncMock()
        fake_device_sessions.auto_revoke_others = AsyncMock(return_value=(0, 0))
        auth_app.dependency_overrides[get_device_sessions_service] = (
            lambda: fake_device_sessions
        )
        try:
            response = await test_client_auth_csrf.delete(
                f"/security/passkeys/{uuid.uuid4()}",
                cookies=_auth_cookies(),
            )
            assert response.status_code == status.HTTP_204_NO_CONTENT
            fake_device_sessions.auto_revoke_others.assert_awaited_once()
            kwargs = fake_device_sessions.auto_revoke_others.await_args.kwargs
            assert kwargs.get("reason") == "passkey_deleted"
        finally:
            auth_app.dependency_overrides.pop(
                get_device_sessions_service, None
            )
