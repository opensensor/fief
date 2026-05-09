"""Integration coverage for ``GET /authorize`` honouring signed
``branding_origin`` (T46).

Complements :mod:`tests.services.test_branding_origin_verifier` by
exercising the wiring on the actual FastAPI handler:

* When the token validates, the resulting :class:`LoginSession` row
  carries the verified origin in ``branding_origin``.
* When the token is missing / tampered / expired / unauthorized origin /
  the client has no signing key, the handler still completes (silent
  fallback) and the persisted :class:`LoginSession` has
  ``branding_origin == None``.
* Cross-client replay: a token signed with a different key and presented
  to a client whose key won't validate it is ignored (silent fallback
  again).

Together with the unit-level coverage these satisfy the eight cases the
audit doc § 4.7 lists.
"""

from __future__ import annotations

import hashlib
import hmac
import time

import httpx
import pytest
import pytest_asyncio
from fastapi import status

from fief.db import AsyncSession
from fief.repositories import ClientRepository, LoginSessionRepository
from tests.data import TestData

SIGNING_KEY = "k" * 64
OTHER_KEY = "x" * 64
ORIGIN = "https://nantes.city"  # matches the redirect_uri host in test data


def _sign(secret: str, origin: str, nonce: str, expiry: int) -> str:
    """Replicate the T15 signer's token shape."""
    msg = f"{origin}.{nonce}.{expiry}".encode()
    sig = hmac.new(
        secret.encode("utf-8"), msg=msg, digestmod=hashlib.sha256
    ).hexdigest()
    return f"{origin}.{nonce}.{expiry}.{sig}"


@pytest.mark.asyncio
class TestAuthAuthorizeBrandingOrigin:
    """Each test seeds a per-case ``branding_signing_key`` on the default
    test client so we don't perturb the rest of the suite."""

    @pytest_asyncio.fixture
    async def client_with_signing_key(
        self, test_data: TestData, main_session: AsyncSession
    ):
        """Set ``branding_signing_key`` on the default-tenant test
        client and return the same client instance. The fixture rolls
        back at teardown via the ``main_session`` transaction reset."""
        client = test_data["clients"]["default_tenant"]
        client.branding_signing_key = SIGNING_KEY
        repo = ClientRepository(main_session)
        await repo.update(client)
        return client

    async def _build_params(self, client_id: str) -> dict[str, str]:
        return {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://nantes.city/callback",
            "scope": "openid",
        }

    async def _last_login_session(
        self, response: httpx.Response, main_session: AsyncSession
    ):
        from fief.settings import settings

        token = response.cookies[settings.login_session_cookie_name]
        repo = LoginSessionRepository(main_session)
        return await repo.get_by_token(token)

    # ---- happy path -------------------------------------------------------

    async def test_signed_origin_persisted_on_login_session(
        self,
        test_client_auth: httpx.AsyncClient,
        client_with_signing_key,
        main_session: AsyncSession,
    ) -> None:
        expiry = int(time.time()) + 60
        token = _sign(SIGNING_KEY, ORIGIN, "nonce-happy", expiry)

        params = {
            **(await self._build_params(client_with_signing_key.client_id)),
            "branding_origin": token,
        }
        response = await test_client_auth.get("/authorize", params=params)

        assert response.status_code == status.HTTP_302_FOUND
        ls = await self._last_login_session(response, main_session)
        assert ls is not None
        assert ls.branding_origin == ORIGIN

    # ---- no token (default brand silently) --------------------------------

    async def test_no_token_leaves_branding_origin_null(
        self,
        test_client_auth: httpx.AsyncClient,
        client_with_signing_key,
        main_session: AsyncSession,
    ) -> None:
        params = await self._build_params(client_with_signing_key.client_id)
        response = await test_client_auth.get("/authorize", params=params)

        assert response.status_code == status.HTTP_302_FOUND
        ls = await self._last_login_session(response, main_session)
        assert ls is not None
        assert ls.branding_origin is None

    # ---- tampered token (silent fallback) ---------------------------------

    async def test_tampered_token_silent_fallback(
        self,
        test_client_auth: httpx.AsyncClient,
        client_with_signing_key,
        main_session: AsyncSession,
    ) -> None:
        expiry = int(time.time()) + 60
        good = _sign(SIGNING_KEY, ORIGIN, "nonce-tamper", expiry)
        head, _sig = good.rsplit(".", 1)
        tampered = f"{head}.{'0' * 64}"

        params = {
            **(await self._build_params(client_with_signing_key.client_id)),
            "branding_origin": tampered,
        }
        response = await test_client_auth.get("/authorize", params=params)

        # The handler MUST still complete (silent fallback) -- a bad
        # branding_origin is never a fatal authorize-time error.
        assert response.status_code == status.HTTP_302_FOUND
        ls = await self._last_login_session(response, main_session)
        assert ls is not None
        assert ls.branding_origin is None

    # ---- expired token (silent fallback) ----------------------------------

    async def test_expired_token_silent_fallback(
        self,
        test_client_auth: httpx.AsyncClient,
        client_with_signing_key,
        main_session: AsyncSession,
    ) -> None:
        expiry = int(time.time()) - 6 * 60
        token = _sign(SIGNING_KEY, ORIGIN, "nonce-expired", expiry)

        params = {
            **(await self._build_params(client_with_signing_key.client_id)),
            "branding_origin": token,
        }
        response = await test_client_auth.get("/authorize", params=params)

        assert response.status_code == status.HTTP_302_FOUND
        ls = await self._last_login_session(response, main_session)
        assert ls is not None
        assert ls.branding_origin is None

    # ---- unknown origin (silent fallback) ---------------------------------

    async def test_unknown_origin_silent_fallback(
        self,
        test_client_auth: httpx.AsyncClient,
        client_with_signing_key,
        main_session: AsyncSession,
    ) -> None:
        expiry = int(time.time()) + 60
        # Origin host (``shop-evil.example.com``) is NOT in the client's
        # redirect_uris (which lists ``https://nantes.city/callback``).
        token = _sign(
            SIGNING_KEY, "https://shop-evil.example.com", "nonce-unknown", expiry
        )

        params = {
            **(await self._build_params(client_with_signing_key.client_id)),
            "branding_origin": token,
        }
        response = await test_client_auth.get("/authorize", params=params)

        assert response.status_code == status.HTTP_302_FOUND
        ls = await self._last_login_session(response, main_session)
        assert ls is not None
        assert ls.branding_origin is None

    # ---- null signing key (any token ignored) -----------------------------

    async def test_null_signing_key_ignores_token(
        self,
        test_client_auth: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ) -> None:
        # Use a client WITHOUT a signing key -- the default-tenant client
        # in the bare test_data has ``branding_signing_key == None``.
        client = test_data["clients"]["public_default_tenant"]
        # Defensive: ensure no key is set even if a sibling test mutated.
        if client.branding_signing_key is not None:
            client.branding_signing_key = None
            repo = ClientRepository(main_session)
            await repo.update(client)

        expiry = int(time.time()) + 60
        token = _sign(SIGNING_KEY, ORIGIN, "nonce-no-key", expiry)
        params = {
            **(await self._build_params(client.client_id)),
            "branding_origin": token,
        }
        response = await test_client_auth.get("/authorize", params=params)

        assert response.status_code == status.HTTP_302_FOUND
        ls = await self._last_login_session(response, main_session)
        assert ls is not None
        assert ls.branding_origin is None

    # ---- cross-client replay ----------------------------------------------

    async def test_cross_client_replay_silent_fallback(
        self,
        test_client_auth: httpx.AsyncClient,
        client_with_signing_key,
        main_session: AsyncSession,
    ) -> None:
        expiry = int(time.time()) + 60
        # Token signed with OTHER_KEY -- the client on the request has
        # SIGNING_KEY -> HMAC mismatch -> silent fallback.
        token_signed_by_other = _sign(OTHER_KEY, ORIGIN, "nonce-replay", expiry)

        params = {
            **(await self._build_params(client_with_signing_key.client_id)),
            "branding_origin": token_signed_by_other,
        }
        response = await test_client_auth.get("/authorize", params=params)

        assert response.status_code == status.HTTP_302_FOUND
        ls = await self._last_login_session(response, main_session)
        assert ls is not None
        assert ls.branding_origin is None
