"""Unit tests for :class:`WebAuthnService` (MFA-2 T6 / T15).

These tests exercise the service's contract end-to-end against a real
``fakeredis.aioredis.FakeRedis`` for challenge persistence and a fake
in-memory credential repository. The two heavy hitters from py_webauthn
— ``verify_registration_response`` and ``verify_authentication_response``
— are monkey-patched so we don't need real authenticator outputs; we
test our integration glue (challenge round-trip, sign-count rollback
detection, audit emissions, user-scoped lookups) rather than re-testing
the upstream library.

Coverage:

- ``begin_registration`` populates ``excludeCredentials`` from existing.
- ``finish_registration`` happy path persists + audits.
- ``finish_registration`` with expired challenge raises ``ChallengeExpired``.
- ``finish_registration`` is one-shot — second use raises ``ChallengeExpired``.
- ``finish_registration`` with bad attestation raises ``InvalidAssertion``.
- ``begin_assertion`` populates ``allowCredentials`` from user's set.
- ``verify_assertion`` happy path bumps ``sign_count`` + ``last_used_at``.
- ``verify_assertion`` with unknown ``rawId`` raises ``CredentialNotFound``.
- ``verify_assertion`` with sign_count regression raises ``SignCountRollback``.
- ``verify_assertion`` accepts ``new_sign_count == 0`` (Apple/Google sync).
- ``verify_assertion`` with stored ``sign_count == 0`` accepts any new value.
- ``verify_assertion`` invalid signature raises ``InvalidAssertion``.
- ``delete`` returns True + audits on real removal, False on miss.
- ``derive_rp_params`` brand path + tenant fallback.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock

import fakeredis.aioredis
import pytest

from fief.models import AuditLogMessage, UserWebAuthnCredential
from fief.services.security import webauthn as webauthn_module
from fief.services.security.webauthn import (
    ChallengeExpired,
    CredentialNotFound,
    InvalidAssertion,
    SignCountRollback,
    WebAuthnService,
    derive_rp_params,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeUser:
    def __init__(
        self, email: str = "user@example.com", *, mfa_enabled: bool = False
    ) -> None:
        self.id = uuid.uuid4()
        self.email = email
        self.mfa_enabled = mfa_enabled


class _FakeCredentialRepo:
    """In-memory stand-in for :class:`UserWebAuthnCredentialRepository`."""

    def __init__(self) -> None:
        self.rows: list[UserWebAuthnCredential] = []
        self.calls: list[tuple[str, Any]] = []

    async def list_by_user_id(
        self, user_id: uuid.UUID
    ) -> list[UserWebAuthnCredential]:
        self.calls.append(("list_by_user_id", user_id))
        return [r for r in self.rows if r.user_id == user_id]

    async def get_by_credential_id(
        self, credential_id: bytes
    ) -> UserWebAuthnCredential | None:
        self.calls.append(("get_by_credential_id", credential_id))
        for r in self.rows:
            if r.credential_id == credential_id:
                return r
        return None

    async def create(
        self, row: UserWebAuthnCredential
    ) -> UserWebAuthnCredential:
        self.calls.append(("create", row))
        self.rows.append(row)
        return row

    async def delete_by_id_for_user(
        self, id: uuid.UUID, user_id: uuid.UUID
    ) -> int:
        self.calls.append(("delete_by_id_for_user", (id, user_id)))
        before = len(self.rows)
        self.rows = [
            r for r in self.rows if not (r.id == id and r.user_id == user_id)
        ]
        return before - len(self.rows)

    async def count_for_user(self, user_id: uuid.UUID) -> int:
        self.calls.append(("count_for_user", user_id))
        return sum(1 for r in self.rows if r.user_id == user_id)

    async def update_after_assertion(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        last_used_at: datetime,
    ) -> None:
        self.calls.append(
            (
                "update_after_assertion",
                {
                    "credential_id": credential_id,
                    "sign_count": sign_count,
                    "last_used_at": last_used_at,
                },
            )
        )
        for r in self.rows:
            if r.credential_id == credential_id:
                r.sign_count = sign_count
                r.last_used_at = last_used_at


@dataclass
class _FakeVerifiedRegistration:
    credential_id: bytes
    credential_public_key: bytes
    sign_count: int
    aaguid: str
    credential_device_type: str
    credential_backed_up: bool
    attestation_object: bytes = b""


@dataclass
class _FakeVerifiedAuthentication:
    credential_id: bytes
    new_sign_count: int
    credential_device_type: str = "single_device"
    credential_backed_up: bool = False
    user_verified: bool = True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def credential_repo() -> _FakeCredentialRepo:
    return _FakeCredentialRepo()


@pytest.fixture
def fake_redis() -> fakeredis.aioredis.FakeRedis:
    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def audit_logger() -> MagicMock:
    return MagicMock()


class _FakeTotpRepo:
    """Stand-in for :class:`UserTotpSecretRepository`.

    Only ``get_confirmed_by_user_id`` is consulted by
    :func:`recompute_mfa_enabled` (called from
    ``WebAuthnService.finish_registration`` and ``.delete``). Default
    "no TOTP" — tests that need to assert "passkey delete keeps
    mfa_enabled=True because TOTP exists" override ``has_totp=True``.
    """

    def __init__(self, *, has_totp: bool = False) -> None:
        self.has_totp = has_totp

    async def get_confirmed_by_user_id(self, user_id: uuid.UUID) -> Any:
        return object() if self.has_totp else None


class _FakeUserRepo:
    """Stand-in for :class:`UserRepository`. Tracks ``update`` calls so
    tests can assert when ``mfa_enabled`` was actually flipped."""

    def __init__(self) -> None:
        self.updated: list[Any] = []

    async def update(self, user: Any) -> None:
        self.updated.append(user)


@pytest.fixture
def totp_repo() -> _FakeTotpRepo:
    return _FakeTotpRepo()


@pytest.fixture
def user_repo() -> _FakeUserRepo:
    return _FakeUserRepo()


@pytest.fixture
def service(
    credential_repo: _FakeCredentialRepo,
    fake_redis: fakeredis.aioredis.FakeRedis,
    audit_logger: MagicMock,
    totp_repo: _FakeTotpRepo,
    user_repo: _FakeUserRepo,
) -> WebAuthnService:
    return WebAuthnService(
        credential_repo,
        fake_redis,
        audit_logger,
        totp_repo=totp_repo,
        user_repo=user_repo,
    )


@pytest.fixture
def user() -> _FakeUser:
    return _FakeUser()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_existing_credential(
    user_id: uuid.UUID,
    *,
    credential_id: bytes,
    sign_count: int = 0,
    transports: str | None = None,
) -> UserWebAuthnCredential:
    """Build a UserWebAuthnCredential with all required fields populated."""
    return UserWebAuthnCredential(
        id=uuid.uuid4(),
        user_id=user_id,
        credential_id=credential_id,
        public_key=b"pubkey-" + credential_id,
        sign_count=sign_count,
        transports=transports,
        aaguid=None,
        backup_eligible=False,
        backup_state=False,
        label=None,
        attestation_obj=None,
        last_used_at=None,
    )


# ---------------------------------------------------------------------------
# begin_registration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_begin_registration_returns_options_and_persists_challenge(
    service: WebAuthnService,
    user: _FakeUser,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    options = await service.begin_registration(
        user, rp_id="members.example.com", rp_name="Example"
    )

    # Options carry the server-side context.
    assert options["rp"]["id"] == "members.example.com"
    assert options["rp"]["name"] == "Example"
    assert options["user"]["name"] == user.email
    assert options["user"]["displayName"] == user.email
    # Challenge is base64url-encoded in the JSON.
    assert isinstance(options["challenge"], str)
    assert len(options["challenge"]) > 0
    # userVerification = preferred, attestation = none (locked-in defaults).
    assert options["authenticatorSelection"]["userVerification"] == "preferred"
    assert options["attestation"] == "none"

    # Challenge persisted in Redis under the per-user key.
    key = f"webauthn:reg:{user.id}"
    raw = await fake_redis.get(key)
    assert raw is not None
    # TTL is set (positive), max 300 s.
    ttl = await fake_redis.ttl(key)
    assert 0 < ttl <= 300


@pytest.mark.asyncio
async def test_begin_registration_excludes_existing_credentials(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
) -> None:
    cred1 = _make_existing_credential(
        user.id, credential_id=b"cred-id-1", transports="usb,nfc"
    )
    cred2 = _make_existing_credential(
        user.id, credential_id=b"cred-id-2", transports=None
    )
    credential_repo.rows = [cred1, cred2]

    options = await service.begin_registration(
        user, rp_id="members.example.com", rp_name="Example"
    )

    excluded = options.get("excludeCredentials", [])
    assert len(excluded) == 2
    excluded_ids_b64 = {e["id"] for e in excluded}
    assert _b64url(b"cred-id-1") in excluded_ids_b64
    assert _b64url(b"cred-id-2") in excluded_ids_b64
    # cred1 had transports; cred2 did not.
    by_id = {e["id"]: e for e in excluded}
    assert by_id[_b64url(b"cred-id-1")]["transports"] == ["usb", "nfc"]
    assert "transports" not in by_id[_b64url(b"cred-id-2")]


# ---------------------------------------------------------------------------
# finish_registration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finish_registration_happy_path(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    audit_logger: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Seed a challenge.
    await service.begin_registration(
        user, rp_id="members.example.com", rp_name="Example"
    )

    fake_verified = _FakeVerifiedRegistration(
        credential_id=b"new-credential-id",
        credential_public_key=b"new-public-key",
        sign_count=0,
        aaguid="adce0002-35bc-c60a-648b-0b25f1f05503",  # Touch ID
        credential_device_type="multi_device",
        credential_backed_up=True,
        attestation_object=b"raw-att-obj",
    )
    monkeypatch.setattr(
        webauthn_module,
        "verify_registration_response",
        lambda **kwargs: fake_verified,
    )

    attestation_response = {
        "id": "x",
        "rawId": "x",
        "response": {"transports": ["internal", "hybrid"]},
        "type": "public-key",
    }
    cred = await service.finish_registration(
        user,
        rp_id="members.example.com",
        origin="https://members.example.com",
        attestation_response=attestation_response,
    )

    # Persisted with mapped fields.
    assert cred.user_id == user.id
    assert cred.credential_id == b"new-credential-id"
    assert cred.public_key == b"new-public-key"
    assert cred.sign_count == 0
    assert cred.aaguid is not None
    assert str(cred.aaguid) == "adce0002-35bc-c60a-648b-0b25f1f05503"
    assert cred.backup_eligible is True
    assert cred.backup_state is True
    assert cred.transports == "internal,hybrid"
    assert cred.attestation_obj == b"raw-att-obj"

    # Repo received a create call.
    assert any(c[0] == "create" for c in credential_repo.calls)

    # Audit fired.
    audit_logger.assert_any_call(
        AuditLogMessage.USER_PASSKEY_REGISTERED,
        subject_user_id=user.id,
        extra={"credential_id_hex": b"new-credential-id".hex()[:32]},
    )


@pytest.mark.asyncio
async def test_finish_registration_collapses_null_aaguid_to_none(
    service: WebAuthnService,
    user: _FakeUser,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await service.begin_registration(
        user, rp_id="members.example.com", rp_name="Example"
    )
    fake_verified = _FakeVerifiedRegistration(
        credential_id=b"x",
        credential_public_key=b"y",
        sign_count=0,
        aaguid="00000000-0000-0000-0000-000000000000",
        credential_device_type="single_device",
        credential_backed_up=False,
    )
    monkeypatch.setattr(
        webauthn_module,
        "verify_registration_response",
        lambda **kwargs: fake_verified,
    )

    cred = await service.finish_registration(
        user,
        rp_id="members.example.com",
        origin="https://members.example.com",
        attestation_response={"id": "x", "rawId": "x", "response": {}},
    )

    assert cred.aaguid is None
    assert cred.backup_eligible is False


@pytest.mark.asyncio
async def test_finish_registration_no_challenge_raises_expired(
    service: WebAuthnService,
    user: _FakeUser,
) -> None:
    # No begin_registration call -> no challenge.
    with pytest.raises(ChallengeExpired):
        await service.finish_registration(
            user,
            rp_id="members.example.com",
            origin="https://members.example.com",
            attestation_response={"id": "x", "rawId": "x", "response": {}},
        )


@pytest.mark.asyncio
async def test_finish_registration_is_one_shot(
    service: WebAuthnService,
    user: _FakeUser,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await service.begin_registration(
        user, rp_id="members.example.com", rp_name="Example"
    )
    fake_verified = _FakeVerifiedRegistration(
        credential_id=b"a",
        credential_public_key=b"b",
        sign_count=0,
        aaguid="",
        credential_device_type="single_device",
        credential_backed_up=False,
    )
    monkeypatch.setattr(
        webauthn_module,
        "verify_registration_response",
        lambda **kwargs: fake_verified,
    )

    # First call succeeds.
    await service.finish_registration(
        user,
        rp_id="members.example.com",
        origin="https://members.example.com",
        attestation_response={"id": "a", "rawId": "a", "response": {}},
    )

    # Second call: challenge already consumed.
    with pytest.raises(ChallengeExpired):
        await service.finish_registration(
            user,
            rp_id="members.example.com",
            origin="https://members.example.com",
            attestation_response={"id": "a", "rawId": "a", "response": {}},
        )


@pytest.mark.asyncio
async def test_finish_registration_invalid_response_raises(
    service: WebAuthnService,
    user: _FakeUser,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from webauthn.helpers.exceptions import InvalidRegistrationResponse

    await service.begin_registration(
        user, rp_id="members.example.com", rp_name="Example"
    )

    def _raise(**kwargs):
        raise InvalidRegistrationResponse("bad clientData")

    monkeypatch.setattr(
        webauthn_module, "verify_registration_response", _raise
    )

    with pytest.raises(InvalidAssertion):
        await service.finish_registration(
            user,
            rp_id="members.example.com",
            origin="https://members.example.com",
            attestation_response={"id": "z", "rawId": "z", "response": {}},
        )


# ---------------------------------------------------------------------------
# begin_assertion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_begin_assertion_returns_options_and_persists_challenge(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    cred1 = _make_existing_credential(
        user.id, credential_id=b"a", transports="internal"
    )
    credential_repo.rows = [cred1]

    login_session_id = uuid.uuid4()
    options = await service.begin_assertion(
        user, rp_id="members.example.com", login_session_id=login_session_id
    )

    assert options["rpId"] == "members.example.com"
    assert options["userVerification"] == "preferred"
    allowed = options.get("allowCredentials", [])
    assert len(allowed) == 1
    assert allowed[0]["id"] == _b64url(b"a")
    assert allowed[0]["transports"] == ["internal"]

    # Challenge stored under the login-session-scoped key.
    key = f"webauthn:auth:{login_session_id}"
    assert await fake_redis.get(key) is not None


# ---------------------------------------------------------------------------
# verify_assertion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_assertion_happy_path(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    audit_logger: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cred = _make_existing_credential(
        user.id, credential_id=b"cred-x", sign_count=5
    )
    credential_repo.rows = [cred]

    login_session_id = uuid.uuid4()
    await service.begin_assertion(
        user, rp_id="members.example.com", login_session_id=login_session_id
    )

    monkeypatch.setattr(
        webauthn_module,
        "verify_authentication_response",
        lambda **kwargs: _FakeVerifiedAuthentication(
            credential_id=b"cred-x", new_sign_count=10
        ),
    )

    assertion_response = {
        "id": _b64url(b"cred-x"),
        "rawId": _b64url(b"cred-x"),
        "response": {},
        "type": "public-key",
    }
    returned = await service.verify_assertion(
        user,
        rp_id="members.example.com",
        origin="https://members.example.com",
        login_session_id=login_session_id,
        assertion_response=assertion_response,
    )

    assert returned.credential_id == b"cred-x"
    # sign_count + last_used_at were persisted via update_after_assertion.
    update_call = next(
        (c for c in credential_repo.calls if c[0] == "update_after_assertion"),
        None,
    )
    assert update_call is not None
    payload = update_call[1]
    assert payload["credential_id"] == b"cred-x"
    assert payload["sign_count"] == 10
    assert isinstance(payload["last_used_at"], datetime)

    audit_logger.assert_any_call(
        AuditLogMessage.USER_PASSKEY_VERIFIED,
        subject_user_id=user.id,
        extra={"credential_id_hex": b"cred-x".hex()[:32]},
    )


@pytest.mark.asyncio
async def test_verify_assertion_unknown_credential_raises_not_found(
    service: WebAuthnService,
    user: _FakeUser,
    audit_logger: MagicMock,
) -> None:
    login_session_id = uuid.uuid4()
    await service.begin_assertion(
        user, rp_id="members.example.com", login_session_id=login_session_id
    )

    assertion_response = {
        "id": _b64url(b"unknown-cred"),
        "rawId": _b64url(b"unknown-cred"),
        "response": {},
    }
    with pytest.raises(CredentialNotFound):
        await service.verify_assertion(
            user,
            rp_id="members.example.com",
            origin="https://members.example.com",
            login_session_id=login_session_id,
            assertion_response=assertion_response,
        )

    audit_logger.assert_any_call(
        AuditLogMessage.USER_PASSKEY_VERIFY_FAILED,
        subject_user_id=user.id,
        extra={"reason": "credential_not_found"},
    )


@pytest.mark.asyncio
async def test_verify_assertion_no_challenge_raises_expired(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
) -> None:
    cred = _make_existing_credential(
        user.id, credential_id=b"x", sign_count=0
    )
    credential_repo.rows = [cred]

    with pytest.raises(ChallengeExpired):
        await service.verify_assertion(
            user,
            rp_id="members.example.com",
            origin="https://members.example.com",
            login_session_id=uuid.uuid4(),
            assertion_response={
                "id": _b64url(b"x"),
                "rawId": _b64url(b"x"),
                "response": {},
            },
        )


@pytest.mark.asyncio
async def test_verify_assertion_sign_count_rollback_raises(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    audit_logger: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cred = _make_existing_credential(
        user.id, credential_id=b"clone-me", sign_count=42
    )
    credential_repo.rows = [cred]

    login_session_id = uuid.uuid4()
    await service.begin_assertion(
        user, rp_id="members.example.com", login_session_id=login_session_id
    )

    # new_sign_count <= stored AND stored > 0 AND new != 0 -> rollback.
    monkeypatch.setattr(
        webauthn_module,
        "verify_authentication_response",
        lambda **kwargs: _FakeVerifiedAuthentication(
            credential_id=b"clone-me", new_sign_count=10
        ),
    )

    with pytest.raises(SignCountRollback):
        await service.verify_assertion(
            user,
            rp_id="members.example.com",
            origin="https://members.example.com",
            login_session_id=login_session_id,
            assertion_response={
                "id": _b64url(b"clone-me"),
                "rawId": _b64url(b"clone-me"),
                "response": {},
            },
        )

    audit_logger.assert_any_call(
        AuditLogMessage.USER_PASSKEY_SIGN_COUNT_ROLLBACK,
        subject_user_id=user.id,
        extra={
            "credential_id_hex": b"clone-me".hex()[:32],
            "stored": 42,
            "received": 10,
        },
    )

    # update_after_assertion was NOT called — we never bumped a suspect cred.
    assert not any(
        c[0] == "update_after_assertion" for c in credential_repo.calls
    )


@pytest.mark.asyncio
async def test_verify_assertion_apple_google_zero_sign_count_accepted(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Apple iCloud Keychain / Google Password Manager always report 0.

    Stored sign_count > 0 + new_sign_count == 0 must NOT trip the
    rollback check or every platform-keychain user gets locked out.
    """
    cred = _make_existing_credential(
        user.id, credential_id=b"icloud", sign_count=99
    )
    credential_repo.rows = [cred]

    login_session_id = uuid.uuid4()
    await service.begin_assertion(
        user, rp_id="members.example.com", login_session_id=login_session_id
    )

    monkeypatch.setattr(
        webauthn_module,
        "verify_authentication_response",
        lambda **kwargs: _FakeVerifiedAuthentication(
            credential_id=b"icloud", new_sign_count=0
        ),
    )

    # No SignCountRollback raised — service treats new_sign_count==0 as OK.
    await service.verify_assertion(
        user,
        rp_id="members.example.com",
        origin="https://members.example.com",
        login_session_id=login_session_id,
        assertion_response={
            "id": _b64url(b"icloud"),
            "rawId": _b64url(b"icloud"),
            "response": {},
        },
    )

    update_call = next(
        c for c in credential_repo.calls if c[0] == "update_after_assertion"
    )
    assert update_call[1]["sign_count"] == 0


@pytest.mark.asyncio
async def test_verify_assertion_first_use_zero_stored_accepts(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stored sign_count == 0 should accept any new value.

    The rollback check is only meaningful AFTER we've seen at least one
    real counter value. Otherwise every first use of a new credential
    would trip the rule.
    """
    cred = _make_existing_credential(
        user.id, credential_id=b"firstuse", sign_count=0
    )
    credential_repo.rows = [cred]

    login_session_id = uuid.uuid4()
    await service.begin_assertion(
        user, rp_id="members.example.com", login_session_id=login_session_id
    )

    monkeypatch.setattr(
        webauthn_module,
        "verify_authentication_response",
        lambda **kwargs: _FakeVerifiedAuthentication(
            credential_id=b"firstuse", new_sign_count=0
        ),
    )

    await service.verify_assertion(
        user,
        rp_id="members.example.com",
        origin="https://members.example.com",
        login_session_id=login_session_id,
        assertion_response={
            "id": _b64url(b"firstuse"),
            "rawId": _b64url(b"firstuse"),
            "response": {},
        },
    )


@pytest.mark.asyncio
async def test_verify_assertion_invalid_signature_raises_invalid_assertion(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    audit_logger: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from webauthn.helpers.exceptions import InvalidAuthenticationResponse

    cred = _make_existing_credential(
        user.id, credential_id=b"y", sign_count=1
    )
    credential_repo.rows = [cred]

    login_session_id = uuid.uuid4()
    await service.begin_assertion(
        user, rp_id="members.example.com", login_session_id=login_session_id
    )

    def _raise(**kwargs):
        raise InvalidAuthenticationResponse("bad signature")

    monkeypatch.setattr(
        webauthn_module, "verify_authentication_response", _raise
    )

    with pytest.raises(InvalidAssertion):
        await service.verify_assertion(
            user,
            rp_id="members.example.com",
            origin="https://members.example.com",
            login_session_id=login_session_id,
            assertion_response={
                "id": _b64url(b"y"),
                "rawId": _b64url(b"y"),
                "response": {},
            },
        )

    audit_logger.assert_any_call(
        AuditLogMessage.USER_PASSKEY_VERIFY_FAILED,
        subject_user_id=user.id,
        extra={"reason": "invalid_signature"},
    )


# ---------------------------------------------------------------------------
# list_for_user / delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_for_user_proxies_to_repo(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
) -> None:
    cred = _make_existing_credential(user.id, credential_id=b"a")
    credential_repo.rows = [cred]

    rows = await service.list_for_user(user)
    assert rows == [cred]


@pytest.mark.asyncio
async def test_delete_removes_row_and_audits(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    audit_logger: MagicMock,
) -> None:
    cred = _make_existing_credential(user.id, credential_id=b"a")
    credential_repo.rows = [cred]

    deleted = await service.delete(user=user, credential_id=cred.id)

    assert deleted is True
    assert credential_repo.rows == []
    audit_logger.assert_any_call(
        AuditLogMessage.USER_PASSKEY_DELETED,
        subject_user_id=user.id,
        extra={"credential_id": str(cred.id)},
    )


@pytest.mark.asyncio
async def test_delete_missing_returns_false_no_audit(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
    audit_logger: MagicMock,
) -> None:
    deleted = await service.delete(
        user=user, credential_id=uuid.uuid4()
    )

    assert deleted is False
    # No DELETED audit when no row was actually removed.
    delete_calls = [
        c
        for c in audit_logger.call_args_list
        if c.args and c.args[0] == AuditLogMessage.USER_PASSKEY_DELETED
    ]
    assert delete_calls == []


@pytest.mark.asyncio
async def test_delete_foreign_credential_returns_false(
    service: WebAuthnService,
    user: _FakeUser,
    credential_repo: _FakeCredentialRepo,
) -> None:
    other_user_id = uuid.uuid4()
    foreign_cred = _make_existing_credential(
        other_user_id, credential_id=b"foreign"
    )
    credential_repo.rows = [foreign_cred]

    # Trying to delete by foreign cred's id but for OUR user.
    deleted = await service.delete(
        user=user, credential_id=foreign_cred.id
    )
    assert deleted is False
    # Foreign cred still in place.
    assert credential_repo.rows == [foreign_cred]


# ---------------------------------------------------------------------------
# derive_rp_params
# ---------------------------------------------------------------------------


def test_derive_rp_params_brand_path() -> None:
    brand = MagicMock()
    brand.host = "members.lightnvr.com"
    brand.name = "LightNVR"
    tenant = MagicMock()

    rp_id, rp_name, origin = derive_rp_params(brand, tenant)

    assert rp_id == "members.lightnvr.com"
    assert rp_name == "LightNVR"
    assert origin == "https://members.lightnvr.com"


def test_derive_rp_params_tenant_fallback_strips_scheme_and_path() -> None:
    tenant = MagicMock()
    tenant.get_host.return_value = "https://example.com:8000/myslug"
    tenant.name = "Default Tenant"

    rp_id, rp_name, origin = derive_rp_params(None, tenant)

    assert rp_id == "example.com"
    assert rp_name == "Default Tenant"
    assert origin == "https://example.com"


def test_derive_rp_params_tenant_fallback_no_brand_host() -> None:
    """If brand.host is empty/None we still fall through to the tenant."""
    brand = MagicMock()
    brand.host = ""
    tenant = MagicMock()
    tenant.get_host.return_value = "https://members.opensensor.io"
    tenant.name = "OpenSensor"

    rp_id, rp_name, origin = derive_rp_params(brand, tenant)

    assert rp_id == "members.opensensor.io"
    assert origin == "https://members.opensensor.io"
