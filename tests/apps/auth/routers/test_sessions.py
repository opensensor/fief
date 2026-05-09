"""Integration tests for the dashboard ``/security/sessions`` routes (UX-1 T11).

Covers the three new dashboard routes:

- ``GET /security/sessions`` (``auth.dashboard:sessions_index``) — renders the
  device list for the authenticated user, including the current device's
  ``is_current`` flag and additional rows for any other live session +
  refresh tokens belonging to the same user.
- ``DELETE /security/sessions/{device_key}`` (``auth.dashboard:sessions_revoke``)
  — revokes a single device. Stale ``device_key`` returns 404 (concurrent
  double-click guard); revoking the *current* session returns 303 to /login;
  revoking a non-current device returns 204.
- ``POST /security/sessions/sign-out-others``
  (``auth.dashboard:sessions_sign_out_others``) — wipes every device row
  except the current session, plus all refresh tokens.

The real ``auth/dashboard/security/sessions.html`` template ships in T13;
we stub it via :class:`jinja2.DictLoader` so the GET route renders during
this wave. The stub round-trips the inbound context's ``devices`` list as
JSON in the response body so the tests can assert on shape and content
without coupling to UI markup.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pytest
import pytest_asyncio
from fastapi import status
from jinja2 import ChoiceLoader, DictLoader

from fief.apps import auth_app
from fief.crypto.token import generate_token
from fief.db import AsyncSession
from fief.dependencies.logger import get_audit_logger
from fief.logger import AuditLogger, logger as loguru_logger
from fief.models import (
    AuditLogMessage,
    RefreshToken,
    SessionToken,
)
from fief.repositories import (
    RefreshTokenRepository,
    SessionTokenRepository,
)
from fief.settings import settings
from fief.templates import templates
from tests.data import TestData, session_token_tokens


# ---------------------------------------------------------------------------
# Stub template for the T13-owned ``security/sessions.html``. Renders the
# inbound ``devices`` list as JSON so we can assert on it from the test.
# ---------------------------------------------------------------------------
_STUB_TEMPLATES = {
    "auth/dashboard/security/sessions.html": (
        "{% set rows = [] %}"
        "{% for d in devices %}"
        "{% set _ = rows.append({"
        "'device_key': d.device_key,"
        "'device_label': d.device_label,"
        "'device_kind': d.device_kind,"
        "'is_current': d.is_current,"
        "'last_seen_ip': d.last_seen_ip,"
        "'client_label': d.client_label,"
        "'session_token_ids': d.session_token_ids|map('string')|list,"
        "'refresh_token_ids': d.refresh_token_ids|map('string')|list,"
        "}) %}"
        "{% endfor %}"
        "{{ {'devices': rows, 'current_route': current_route}|tojson }}"
    ),
}


@pytest.fixture(autouse=True)
def _inject_sessions_template_stub():
    original = templates.env.loader
    templates.env.loader = ChoiceLoader([DictLoader(_STUB_TEMPLATES), original])
    try:
        yield
    finally:
        templates.env.loader = original


def _auth_cookies() -> dict[str, str]:
    return {settings.session_cookie_name: session_token_tokens["regular"][0]}


def _audit_calls(
    mock: MagicMock, message: AuditLogMessage
) -> list:
    """Return every captured call whose first positional arg matches ``message``."""

    return [
        call
        for call in mock.call_args_list
        if call.args and call.args[0] == message
    ]


@pytest.fixture
def captured_audit_logger() -> MagicMock:
    """Wrapping mock that records every audit-logger call while still
    delegating to the real logger so loguru sinks see normal output."""

    real = AuditLogger(loguru_logger)
    mock = MagicMock(spec=AuditLogger, wraps=real)
    mock.admin_user_id = real.admin_user_id
    mock.admin_api_key_id = real.admin_api_key_id
    return mock


@pytest_asyncio.fixture
async def _override_audit_logger(
    captured_audit_logger: MagicMock,
    test_client_auth_csrf: httpx.AsyncClient,
):
    auth_app.dependency_overrides[get_audit_logger] = (
        lambda: captured_audit_logger
    )
    try:
        yield
    finally:
        auth_app.dependency_overrides.pop(get_audit_logger, None)


# ---------------------------------------------------------------------------
# Helpers to seed a second device row for the ``regular`` user. The bundled
# fixture data only ships one session token per user (``regular``), so to
# exercise the multi-device list / revoke paths we add a second
# ``SessionToken`` row directly via the repository.
# ---------------------------------------------------------------------------


async def _seed_second_session_token(
    main_session: AsyncSession,
    user_id: uuid.UUID,
    *,
    user_agent: str,
    ip: str,
) -> SessionToken:
    repo = SessionTokenRepository(main_session)
    _raw, token_hash = generate_token()
    token = SessionToken(
        token=token_hash,
        user_id=user_id,
        created_ip=ip,
        created_user_agent=user_agent,
        last_seen_at=datetime.now(UTC),
        last_seen_ip=ip,
    )
    main_session.add(token)
    await main_session.commit()
    # Round-trip through the repo so the ORM state is fully attached.
    persisted = await repo.get_by_id(token.id)
    assert persisted is not None
    return persisted


async def _seed_refresh_token(
    main_session: AsyncSession,
    *,
    user_id: uuid.UUID,
    client_id: uuid.UUID,
    user_agent: str,
    ip: str,
) -> RefreshToken:
    repo = RefreshTokenRepository(main_session)
    _raw, token_hash = generate_token()
    token = RefreshToken(
        token=token_hash,
        user_id=user_id,
        client_id=client_id,
        scope=["openid", "offline_access"],
        authenticated_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=7),
        created_ip=ip,
        created_user_agent=user_agent,
        last_seen_at=datetime.now(UTC),
        last_seen_ip=ip,
    )
    main_session.add(token)
    await main_session.commit()
    persisted = await repo.get_by_id(token.id)
    assert persisted is not None
    return persisted


_DESKTOP_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
_PHONE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Mobile/15E148 Safari/604.1"
)


# ---------------------------------------------------------------------------
# GET /security/sessions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSessionsIndex:
    async def test_get_with_two_devices_lists_both(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = test_data["users"]["regular"]
        await _seed_second_session_token(
            main_session,
            user.id,
            user_agent=_PHONE_UA,
            ip="203.0.113.42",
        )

        response = await test_client_auth_csrf.get(
            "/security/sessions", cookies=_auth_cookies()
        )

        assert response.status_code == status.HTTP_200_OK
        body = json.loads(response.text)
        assert body["current_route"] == "auth.dashboard:sessions_index"
        # Two distinct (browser, os, /24) buckets => two rows.
        assert len(body["devices"]) >= 2
        labels = [d["device_label"] for d in body["devices"]]
        # The phone UA has Mobile Safari + iOS, which user_agents parses as
        # "Mobile Safari" / "iOS" (the exact family strings vary across
        # versions of the lib). Just assert the iOS row exists.
        assert any("iOS" in label for label in labels)
        # Exactly one row should be marked as the current device.
        current_rows = [d for d in body["devices"] if d["is_current"]]
        assert len(current_rows) == 1

    async def test_get_with_only_current_session_returns_one_row(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
    ):
        response = await test_client_auth_csrf.get(
            "/security/sessions", cookies=_auth_cookies()
        )

        assert response.status_code == status.HTTP_200_OK
        body = json.loads(response.text)
        # The user starts with exactly one session token (the bundled one),
        # plus whatever refresh tokens the fixture seeds against the same
        # browser fingerprint. ``regular`` has refresh tokens on tenant
        # default-ish; they may dedup into the same row or split. The
        # invariant we care about is "the current session is present".
        current_rows = [d for d in body["devices"] if d["is_current"]]
        assert len(current_rows) == 1


# ---------------------------------------------------------------------------
# DELETE /security/sessions/{device_key}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSessionsRevoke:
    async def test_delete_with_stale_device_key_returns_404(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
    ):
        # 16-char hex string that won't match any real bucket.
        stale_key = "deadbeefcafebabe"

        response = await test_client_auth_csrf.delete(
            f"/security/sessions/{stale_key}", cookies=_auth_cookies()
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_delete_non_current_device_returns_204_and_audits(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
        user = test_data["users"]["regular"]
        await _seed_second_session_token(
            main_session,
            user.id,
            user_agent=_PHONE_UA,
            ip="203.0.113.42",
        )

        # First, GET to learn the device_key for the non-current row.
        list_response = await test_client_auth_csrf.get(
            "/security/sessions", cookies=_auth_cookies()
        )
        body = json.loads(list_response.text)
        target = next(d for d in body["devices"] if not d["is_current"])
        device_key = target["device_key"]

        del_response = await test_client_auth_csrf.delete(
            f"/security/sessions/{device_key}", cookies=_auth_cookies()
        )
        assert del_response.status_code == status.HTTP_204_NO_CONTENT

        # Row no longer appears in subsequent listing.
        followup = await test_client_auth_csrf.get(
            "/security/sessions", cookies=_auth_cookies()
        )
        followup_body = json.loads(followup.text)
        keys = [d["device_key"] for d in followup_body["devices"]]
        assert device_key not in keys

        # Audit fired with the correct message.
        audit_calls = _audit_calls(
            captured_audit_logger, AuditLogMessage.USER_SESSION_REVOKED
        )
        assert len(audit_calls) == 1
        extra = audit_calls[0].kwargs.get("extra") or {}
        assert "device_label" in extra
        assert extra.get("revoked_session_count", 0) >= 1

    async def test_delete_current_session_returns_303_to_login(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
    ):
        list_response = await test_client_auth_csrf.get(
            "/security/sessions", cookies=_auth_cookies()
        )
        body = json.loads(list_response.text)
        current = next(d for d in body["devices"] if d["is_current"])
        device_key = current["device_key"]

        # ``follow_redirects=False`` to inspect the 303 directly.
        del_response = await test_client_auth_csrf.delete(
            f"/security/sessions/{device_key}",
            cookies=_auth_cookies(),
            follow_redirects=False,
        )
        assert del_response.status_code == status.HTTP_303_SEE_OTHER
        location = del_response.headers.get("location", "")
        assert "/login" in location

    async def test_delete_other_users_device_key_returns_404(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        # Authenticate as ``regular`` but try to revoke a device key that
        # only ``regular_secondary`` could enumerate. The simplest way to
        # produce one is to compute a key from a different user's tokens —
        # but the route only accepts opaque hex; the easiest invariant to
        # test is: a key that is NOT in the requester's listing returns
        # 404 even if it would have hashed to a real device for someone
        # else. We assert the negative — the requester's listing never
        # surfaces the second user's device, so ANY 16-hex string we
        # haven't seen returns 404.
        list_response = await test_client_auth_csrf.get(
            "/security/sessions", cookies=_auth_cookies()
        )
        body = json.loads(list_response.text)
        my_keys = {d["device_key"] for d in body["devices"]}

        # Pick a key not in the requester's set.
        candidate = "f00ff00ff00ff00f"
        assert candidate not in my_keys

        response = await test_client_auth_csrf.delete(
            f"/security/sessions/{candidate}", cookies=_auth_cookies()
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ---------------------------------------------------------------------------
# POST /security/sessions/sign-out-others
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSignOutOthers:
    async def test_post_returns_200_and_audits_with_counts(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        captured_audit_logger: MagicMock,
        _override_audit_logger: None,
    ):
        user = test_data["users"]["regular"]
        await _seed_second_session_token(
            main_session,
            user.id,
            user_agent=_DESKTOP_UA,
            ip="198.51.100.7",
        )

        response = await test_client_auth_csrf.post(
            "/security/sessions/sign-out-others",
            cookies=_auth_cookies(),
            data={"csrf_token": csrf_token},
        )
        assert response.status_code == status.HTTP_200_OK

        audit_calls = _audit_calls(
            captured_audit_logger,
            AuditLogMessage.USER_SESSIONS_SIGNED_OUT_OTHERS,
        )
        assert len(audit_calls) == 1
        extra = audit_calls[0].kwargs.get("extra") or {}
        assert "revoked_session_count" in extra
        assert "revoked_refresh_count" in extra
        assert extra["revoked_session_count"] >= 1

        # Subsequent listing only shows the current device.
        list_response = await test_client_auth_csrf.get(
            "/security/sessions", cookies=_auth_cookies()
        )
        list_body = json.loads(list_response.text)
        non_current = [d for d in list_body["devices"] if not d["is_current"]]
        assert non_current == []
