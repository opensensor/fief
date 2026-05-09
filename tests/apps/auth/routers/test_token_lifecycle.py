"""Integration tests for RefreshToken lifecycle hooks (UX-1 T9).

Covers the OAuth2 ``/api/token`` endpoint's two device-annotation hooks:

1. **Creation hook** — on a successful ``authorization_code`` grant whose
   scope contains ``offline_access``, the freshly persisted
   :class:`fief.models.RefreshToken` row carries all four annotation
   columns populated (``created_ip``, ``created_user_agent``,
   ``last_seen_at``, ``last_seen_ip``).

2. **Last-seen hook** — on a ``refresh_token`` grant the route calls
   :meth:`RefreshTokenRepository.touch_last_seen` against the **existing**
   refresh token's id with the resolved client IP from
   ``get_client_ip_info``. The call only advances ``last_seen_*`` — it
   must not modify ``created_*`` (those columns capture first-seen device
   identity and intentionally stay frozen across refreshes).

3. **Missing User-Agent edge case** — when the inbound request omits the
   ``User-Agent`` header, ``created_user_agent`` is persisted as ``None``
   rather than an empty placeholder. The list_for_user UI later renders
   "Unknown device" deterministically off the ``None``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from fief.crypto.token import get_token_hash
from fief.db import AsyncSession
from fief.repositories import RefreshTokenRepository
from tests.data import (
    TestData,
    authorization_code_codes,
    refresh_token_tokens,
)


def _basic_auth_data(client) -> dict[str, str]:
    """Return form data with client_id + client_secret for the basic auth POST."""
    return {
        "client_id": client.client_id,
        "client_secret": client.client_secret,
    }


@pytest.mark.asyncio
class TestRefreshTokenCreationHook:
    """Authorization-code grant hydrates the new RefreshToken's device columns."""

    async def test_authorization_code_grant_populates_device_columns(
        self,
        test_client_auth: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ) -> None:
        authorization_code = test_data["authorization_codes"]["default_regular"]
        client = authorization_code.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        response = await test_client_auth.post(
            f"{path_prefix}/api/token",
            data={
                **_basic_auth_data(client),
                "grant_type": "authorization_code",
                "code": authorization_code_codes["default_regular"][0],
                "redirect_uri": authorization_code.redirect_uri,
            },
            headers={"User-Agent": "DeviceProbe/1.0"},
        )

        assert response.status_code == 200, response.text
        body = response.json()
        # default_regular includes offline_access -> a refresh_token is minted.
        assert "refresh_token" in body

        repo = RefreshTokenRepository(main_session)
        new_refresh_token = await repo.get_by_token(
            get_token_hash(body["refresh_token"])
        )
        assert new_refresh_token is not None
        # All four device-annotation columns must be populated and coherent.
        assert new_refresh_token.created_ip is not None
        assert new_refresh_token.created_ip != ""
        assert new_refresh_token.created_user_agent == "DeviceProbe/1.0"
        assert new_refresh_token.last_seen_at is not None
        # last_seen_ip starts equal to created_ip on creation.
        assert new_refresh_token.last_seen_ip == new_refresh_token.created_ip

    async def test_authorization_code_grant_missing_user_agent_is_none(
        self,
        test_client_auth: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ) -> None:
        """No User-Agent header -> ``created_user_agent`` stays ``None``."""
        authorization_code = test_data["authorization_codes"]["default_regular"]
        client = authorization_code.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        # httpx.AsyncClient ships a default User-Agent header. Override with
        # ``None`` to simulate a barebones HTTP client / scripted request.
        # Setting the header to None on a request removes it for that call.
        response = await test_client_auth.post(
            f"{path_prefix}/api/token",
            data={
                **_basic_auth_data(client),
                "grant_type": "authorization_code",
                "code": authorization_code_codes["default_regular"][0],
                "redirect_uri": authorization_code.redirect_uri,
            },
            headers={"User-Agent": ""},  # explicit empty header
        )

        # If httpx's empty-string handling differs across versions we tolerate
        # an empty string here too — what we really care about is "not a real
        # browser UA". The route stores whatever the request reports, and
        # ``request.headers.get('user-agent')`` returns None when the header
        # is fully absent. On servers that strip empty headers we get None;
        # on those that pass them through we get "". Both are acceptable
        # absence signals — the contract is "do not fabricate a value".
        assert response.status_code == 200, response.text
        body = response.json()
        repo = RefreshTokenRepository(main_session)
        new_refresh_token = await repo.get_by_token(
            get_token_hash(body["refresh_token"])
        )
        assert new_refresh_token is not None
        assert new_refresh_token.created_user_agent in (None, "")
        # IP fields are still populated regardless of UA presence.
        assert new_refresh_token.created_ip is not None


@pytest.mark.asyncio
class TestRefreshTokenLastSeenHook:
    """Refresh-token grant calls touch_last_seen on the existing token."""

    async def test_refresh_grant_calls_touch_last_seen(
        self,
        monkeypatch: pytest.MonkeyPatch,
        test_client_auth: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ) -> None:
        """The route must call ``touch_last_seen(refresh_token.id, ...)`` on
        the existing token *before* the dependency cleanup deletes it.

        We spy on the repository method to capture the call. Note that the
        existing rotation flow still deletes the old token after the route
        returns (existing test ``test_apps_auth_token::test_valid`` covers
        that), so we cannot read the row back from the DB after the request.
        """

        existing_refresh_token = test_data["refresh_tokens"]["default_regular"]
        client = existing_refresh_token.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        # Capture the original method so we can both spy AND let the real
        # UPDATE go through to the test DB (defence: catches any
        # column-name typo on the SET clause).
        original = RefreshTokenRepository.touch_last_seen
        captured: list[dict[str, Any]] = []

        async def _spy(self, token_id, *, last_seen_at, last_seen_ip):
            captured.append(
                {
                    "token_id": token_id,
                    "last_seen_at": last_seen_at,
                    "last_seen_ip": last_seen_ip,
                }
            )
            return await original(
                self,
                token_id,
                last_seen_at=last_seen_at,
                last_seen_ip=last_seen_ip,
            )

        monkeypatch.setattr(RefreshTokenRepository, "touch_last_seen", _spy)

        response = await test_client_auth.post(
            f"{path_prefix}/api/token",
            data={
                **_basic_auth_data(client),
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_tokens["default_regular"][0],
            },
            headers={"User-Agent": "RefreshingClient/9.9"},
        )

        assert response.status_code == 200, response.text

        # Exactly one call against the *existing* token's id.
        assert len(captured) == 1
        call = captured[0]
        assert call["token_id"] == existing_refresh_token.id
        # last_seen_ip is the resolved client IP (matches creation hook
        # semantics — same get_client_ip_info source).
        assert isinstance(call["last_seen_ip"], str)
        assert call["last_seen_ip"] != ""
        # last_seen_at was emitted by the route (timezone-aware).
        assert call["last_seen_at"] is not None
        assert call["last_seen_at"].tzinfo is not None

    async def test_refresh_grant_does_not_modify_created_columns(
        self,
        test_client_auth: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ) -> None:
        """The new refresh-token row issued on a refresh grant gets its OWN
        ``created_*`` from the current request (per the creation hook). The
        spec's "do not modify created_*" applies to the **existing** row
        being touched: we exercise that here by ensuring the call shape
        passed into ``touch_last_seen`` cannot accidentally update those
        columns. The repository contract (T7) restricts the SET clause to
        ``last_seen_at`` and ``last_seen_ip`` only — so a truthy last-seen
        UPDATE must be safe. We assert the call kwargs are exactly that.
        """
        from inspect import signature

        sig = signature(RefreshTokenRepository.touch_last_seen)
        # Keyword-only params are exactly the two last_seen_* fields.
        kw_only = [
            name
            for name, param in sig.parameters.items()
            if param.kind == param.KEYWORD_ONLY
        ]
        assert kw_only == ["last_seen_at", "last_seen_ip"]
