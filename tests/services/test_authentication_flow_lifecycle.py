"""Unit tests for SessionToken lifecycle hooks (UX-1 T8).

Covers:

- ``AuthenticationFlow.create_session_token`` populates ``created_ip``,
  ``created_user_agent``, ``last_seen_at``, ``last_seen_ip`` on the new
  ``SessionToken`` from the injected ``Request``.
- A missing ``User-Agent`` header leaves ``created_user_agent`` as ``None``
  (the column is nullable; we don't synthesize a placeholder).
- The ``get_session_token`` dependency calls
  ``SessionTokenRepository.touch_last_seen`` after a successful load, with
  the resolved IP from ``get_client_ip_info``. It must NOT touch_last_seen
  when no token row was found.

These are pure unit tests over fakes — no DB / FastAPI app fixture needed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.responses import RedirectResponse
from starlette.requests import Request

from fief.crypto.token import get_token_hash
from fief.models import SessionToken
from fief.services.authentication_flow import AuthenticationFlow


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeSessionTokenRepository:
    """Minimal in-memory SessionTokenRepository capturing the calls under test."""

    def __init__(self) -> None:
        self.created: list[SessionToken] = []
        self.deleted: list[SessionToken] = []
        self.touch_calls: list[dict[str, Any]] = []
        # By default, get_by_token returns None — tests override this when
        # they want to drive the touch_last_seen branch.
        self._token_lookup: dict[str, SessionToken] = {}

    async def create(self, session_token: SessionToken) -> SessionToken:
        # Mirror the real repo: assign an id if absent so callers see a
        # persisted-looking row.
        if getattr(session_token, "id", None) is None:
            session_token.id = uuid.uuid4()
        self.created.append(session_token)
        return session_token

    async def delete(self, session_token: SessionToken) -> None:
        self.deleted.append(session_token)

    async def get_by_token(
        self, token_hash: str, *, fresh: bool = True
    ) -> SessionToken | None:
        return self._token_lookup.get(token_hash)

    async def touch_last_seen(
        self,
        token_id: uuid.UUID,
        *,
        last_seen_at: datetime,
        last_seen_ip: str,
    ) -> None:
        self.touch_calls.append(
            {
                "token_id": token_id,
                "last_seen_at": last_seen_at,
                "last_seen_ip": last_seen_ip,
            }
        )


def _make_request(
    *,
    client_host: str | None = "203.0.113.7",
    user_agent: str | None = "Mozilla/5.0 (Macintosh) Safari/605",
    xff: str | None = None,
) -> Request:
    """Build a minimal Starlette ``Request`` for unit tests."""

    headers: list[tuple[bytes, bytes]] = []
    if user_agent is not None:
        headers.append((b"user-agent", user_agent.encode("latin-1")))
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode("latin-1")))

    scope: dict = {
        "type": "http",
        "headers": headers,
        "client": (client_host, 12345) if client_host is not None else None,
    }
    return Request(scope)


def _make_flow(
    session_token_repository: _FakeSessionTokenRepository,
) -> AuthenticationFlow:
    return AuthenticationFlow(
        authorization_code_repository=MagicMock(),
        login_session_repository=MagicMock(),
        session_token_repository=session_token_repository,
        grant_repository=MagicMock(),
        get_user_permissions=MagicMock(),
    )


# ---------------------------------------------------------------------------
# create_session_token: device-annotation columns populated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_session_token_populates_device_annotation_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All four device columns start populated and coherent."""

    from fief import settings as settings_module

    # Force the simple, no-XFF resolution path so the test does not depend on
    # whatever ``trusted_proxy_count`` happens to be in the test config.
    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 0)

    repo = _FakeSessionTokenRepository()
    flow = _make_flow(repo)

    user_id = uuid.uuid4()
    response = RedirectResponse("/", status_code=302)
    request = _make_request(
        client_host="198.51.100.42",
        user_agent="MyDevice/1.0",
    )

    before = datetime.now(UTC)
    await flow.create_session_token(response, user_id, request)
    after = datetime.now(UTC)

    assert len(repo.created) == 1
    created = repo.created[0]
    assert created.user_id == user_id
    assert created.created_ip == "198.51.100.42"
    assert created.created_user_agent == "MyDevice/1.0"
    assert created.last_seen_ip == "198.51.100.42"
    # last_seen_at is bracketed by the call window.
    assert created.last_seen_at is not None
    assert before <= created.last_seen_at <= after


@pytest.mark.asyncio
async def test_create_session_token_missing_user_agent_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``created_user_agent`` stays ``None`` when the header is absent.

    The column is nullable on purpose; we don't synthesize a placeholder so
    the device-list UI can render an "Unknown device" label deterministically.
    """

    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 0)

    repo = _FakeSessionTokenRepository()
    flow = _make_flow(repo)

    response = RedirectResponse("/", status_code=302)
    request = _make_request(
        client_host="198.51.100.42",
        user_agent=None,
    )

    await flow.create_session_token(response, uuid.uuid4(), request)

    assert len(repo.created) == 1
    assert repo.created[0].created_user_agent is None
    # IP fields are still populated (only UA is missing).
    assert repo.created[0].created_ip == "198.51.100.42"
    assert repo.created[0].last_seen_ip == "198.51.100.42"


# ---------------------------------------------------------------------------
# rotate_session_token + complete_login_after_mfa forward request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotate_session_token_forwards_request_into_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``rotate_session_token`` must forward ``request`` into the new row."""

    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 0)

    repo = _FakeSessionTokenRepository()
    flow = _make_flow(repo)

    response = RedirectResponse("/", status_code=302)
    request = _make_request(
        client_host="203.0.113.99",
        user_agent="RotatingDevice/2.0",
    )

    await flow.rotate_session_token(
        response,
        uuid.uuid4(),
        request,
        session_token=None,
    )

    assert len(repo.created) == 1
    assert repo.created[0].created_ip == "203.0.113.99"
    assert repo.created[0].created_user_agent == "RotatingDevice/2.0"


# ---------------------------------------------------------------------------
# get_session_token: touch_last_seen called on successful load
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_session_token_calls_touch_last_seen_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the cookie resolves to a row, ``touch_last_seen`` must run with
    the IP resolved from the SEC-1 dependency."""

    from fief import settings as settings_module
    from fief.dependencies.client_ip import ClientIpInfo
    from fief.dependencies.session_token import get_session_token

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 0)

    raw_token = "raw-cookie-value"
    token_hash = get_token_hash(raw_token)

    persisted = SessionToken(token=token_hash, user_id=uuid.uuid4())
    persisted.id = uuid.uuid4()

    repo = _FakeSessionTokenRepository()
    repo._token_lookup[token_hash] = persisted

    request = _make_request(client_host="192.0.2.55")
    ip_info = ClientIpInfo(raw="192.0.2.55", rate_limit_key="192.0.2.55")

    before = datetime.now(UTC)
    result = await get_session_token(
        request=request,
        token=raw_token,
        repository=repo,
        ip_info=ip_info,
    )
    after = datetime.now(UTC)

    assert result is persisted
    assert len(repo.touch_calls) == 1
    call = repo.touch_calls[0]
    assert call["token_id"] == persisted.id
    assert call["last_seen_ip"] == "192.0.2.55"
    assert before <= call["last_seen_at"] <= after


@pytest.mark.asyncio
async def test_get_session_token_no_cookie_skips_touch_last_seen() -> None:
    """When no cookie is supplied, ``touch_last_seen`` must not be called
    (there is no row to touch)."""

    from fief.dependencies.client_ip import ClientIpInfo
    from fief.dependencies.session_token import get_session_token

    repo = _FakeSessionTokenRepository()
    request = _make_request(client_host="192.0.2.55")
    ip_info = ClientIpInfo(raw="192.0.2.55", rate_limit_key="192.0.2.55")

    result = await get_session_token(
        request=request,
        token=None,
        repository=repo,
        ip_info=ip_info,
    )

    assert result is None
    assert repo.touch_calls == []


@pytest.mark.asyncio
async def test_get_session_token_unknown_cookie_skips_touch_last_seen() -> None:
    """An unrecognised cookie (e.g. expired token) must not touch a row."""

    from fief.dependencies.client_ip import ClientIpInfo
    from fief.dependencies.session_token import get_session_token

    repo = _FakeSessionTokenRepository()
    # Empty lookup -> get_by_token returns None.
    request = _make_request(client_host="192.0.2.55")
    ip_info = ClientIpInfo(raw="192.0.2.55", rate_limit_key="192.0.2.55")

    result = await get_session_token(
        request=request,
        token="orphan-token-value",
        repository=repo,
        ip_info=ip_info,
    )

    assert result is None
    assert repo.touch_calls == []
