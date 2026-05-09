"""WebAuthn / passkey orchestration for the MFA-2 epic.

This service encapsulates :mod:`webauthn` (the Duo Labs ``py_webauthn``
library) so routes never touch the library directly. The contract:

- :meth:`begin_registration` / :meth:`finish_registration` drive the
  ``navigator.credentials.create()`` ceremony from the dashboard.
- :meth:`begin_assertion` / :meth:`verify_assertion` drive
  ``navigator.credentials.get()`` for the ``/mfa/passkey`` 2FA challenge.
- :meth:`list_for_user` / :meth:`delete` back the dashboard management UI.

Challenge persistence
---------------------
WebAuthn ceremonies are two-step: the RP (us) issues a random challenge
in step 1, the authenticator signs it in step 2. We MUST verify the
returned ``clientDataJSON.challenge`` matches the one we issued. We
persist challenges in Redis under ``webauthn:{kind}:{key}`` with a 300 s
TTL — short enough that a leaked challenge log can't be replayed, long
enough for slow authenticator UX.

Sign-count rollback
-------------------
Authenticators report a ``sign_count`` that monotonically increases with
each use. A response whose ``new_sign_count`` is ``<= stored`` is the
canonical "cloned authenticator" signal in the WebAuthn spec. We reject
those with :class:`SignCountRollback` and audit
``USER_PASSKEY_SIGN_COUNT_ROLLBACK``. The exception: many platform
authenticators (Apple iCloud Keychain, Google Password Manager) report
``new_sign_count = 0`` always — they don't track usage. We accept those
unconditionally to avoid lock-out false positives.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

import redis.asyncio
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json_dict
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from fief.logger import AuditLogger
from fief.models import AuditLogMessage, UserWebAuthnCredential
from fief.repositories.user import UserRepository
from fief.repositories.user_totp_secret import UserTotpSecretRepository
from fief.repositories.user_webauthn_credential import (
    UserWebAuthnCredentialRepository,
)
from fief.services.security.mfa_state import recompute_mfa_enabled

if TYPE_CHECKING:
    from fief.models import Brand, Tenant, User

__all__ = [
    "ChallengeExpired",
    "CredentialNotFound",
    "InvalidAssertion",
    "SignCountRollback",
    "WebAuthnError",
    "WebAuthnService",
    "derive_rp_params",
]


class WebAuthnError(Exception):
    """Base class for service-level WebAuthn failures."""


class CredentialNotFound(WebAuthnError):
    """Raised when an assertion's ``credential_id`` is not registered."""


class SignCountRollback(WebAuthnError):
    """Raised when an assertion's ``new_sign_count`` is <= the stored value.

    The authenticator either has been cloned, or its counter was reset.
    Either way we reject the assertion and surface the event for forensic
    review via :data:`AuditLogMessage.USER_PASSKEY_SIGN_COUNT_ROLLBACK`.
    """


class ChallengeExpired(WebAuthnError):
    """Raised when no challenge is found in Redis for the given key.

    Either the TTL elapsed, the user double-submitted (we delete the
    challenge after the first verify so it can't be replayed), or Redis
    blipped between begin and finish. The route should reply 400 with a
    "please reload and try again" message.
    """


class InvalidAssertion(WebAuthnError):
    """Raised when ``verify_authentication_response`` rejects the response.

    Wraps :class:`webauthn.helpers.exceptions.InvalidAuthenticationResponse`
    so callers don't need to import the upstream exception type.
    """


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Apple/Google sync-fabric passkeys report this AAGUID. py_webauthn returns
# the all-zero UUID as a string when no AAGUID is present; we collapse it
# to None in the persisted row so downstream queries can ``WHERE aaguid IS
# NOT NULL`` to filter platform-keychain credentials cleanly.
_NULL_AAGUID = "00000000-0000-0000-0000-000000000000"


def _b64url_encode(data: bytes) -> str:
    """Base64URL-encode bytes with padding stripped (str output)."""

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64URL-decode a (possibly unpadded) string back to bytes."""

    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def derive_rp_params(
    brand: "Brand | None", tenant: "Tenant"
) -> tuple[str, str, str]:
    """Return ``(rp_id, rp_name, origin)`` for a request context.

    Per-brand RP scope is the v1 design: a user's passkey set on
    ``lightnvr.com`` is intentionally distinct from their set on
    ``owlbooks.ai``. When a brand context is present we use its host and
    name; the fallback path serves admin / non-branded surfaces and
    derives a best-effort host from the tenant.
    """

    if brand is not None and brand.host:
        return brand.host, brand.name, f"https://{brand.host}"

    # Fallback: strip scheme from tenant.get_host() (which returns
    # "https://<fief_domain>[/<slug>]") and use just the host portion as
    # rp_id. WebAuthn rp_id is a domain string with no scheme, no port,
    # no path.
    raw = tenant.get_host()
    # Strip scheme.
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    # Strip path / port.
    host = raw.split("/", 1)[0].split(":", 1)[0]
    return host, tenant.name, f"https://{host}"


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class WebAuthnService:
    """Encapsulates py_webauthn so routes never touch the library directly.

    Stateless apart from its three dependency handles (credential repo,
    Redis, audit logger), so a fresh instance per request is fine — see
    :func:`fief.dependencies.security.get_webauthn_service`.
    """

    CHALLENGE_TTL_SECONDS = 300
    CHALLENGE_KEY_PREFIX = "webauthn"

    def __init__(
        self,
        credential_repo: UserWebAuthnCredentialRepository,
        redis: redis.asyncio.Redis,
        audit_logger: AuditLogger,
        totp_repo: UserTotpSecretRepository,
        user_repo: UserRepository,
    ) -> None:
        self.credential_repo = credential_repo
        self.redis = redis
        self.audit_logger = audit_logger
        # ``totp_repo`` + ``user_repo`` are required by the MFA-2 T13
        # recompute path in :meth:`finish_registration` and :meth:`delete`:
        # the service owns the ``users.mfa_enabled`` flip so routes don't
        # have to thread the same logic per call-site.
        self.totp_repo = totp_repo
        self.user_repo = user_repo

    # ------------------------------------------------------------------
    # Registration ceremony
    # ------------------------------------------------------------------

    async def begin_registration(
        self,
        user: "User",
        *,
        rp_id: str,
        rp_name: str,
    ) -> dict[str, Any]:
        """Issue a ``PublicKeyCredentialCreationOptions`` payload.

        Stores the challenge in Redis at ``webauthn:reg:{user.id}`` with
        a 300 s TTL. ``excludeCredentials`` is populated from the user's
        currently-registered credentials so the same authenticator can't
        be registered twice. ``userVerification`` is ``preferred`` (so a
        YubiKey-without-PIN still works) and ``attestation`` is
        ``none`` (FIDO MDS validation is out of scope).
        """

        existing = await self.credential_repo.list_by_user_id(user.id)
        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                id=cred.credential_id,
                transports=(
                    [AuthenticatorTransport(t) for t in cred.transports_list]
                    if cred.transports
                    else None
                ),
            )
            for cred in existing
        ]

        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=str(user.id).encode("utf-8"),
            user_name=user.email,
            user_display_name=user.email,
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            attestation=AttestationConveyancePreference.NONE,
        )

        # Persist challenge as Base64URL-encoded str. The verify call later
        # decodes it back to bytes and compares against the
        # clientDataJSON.challenge from the authenticator response.
        await self.redis.set(
            self._reg_key(user.id),
            _b64url_encode(options.challenge),
            ex=self.CHALLENGE_TTL_SECONDS,
        )

        return options_to_json_dict(options)

    async def finish_registration(
        self,
        user: "User",
        *,
        rp_id: str,
        origin: str,
        attestation_response: dict[str, Any],
    ) -> UserWebAuthnCredential:
        """Verify the attestation response and persist the credential.

        Pops the challenge from Redis (one-shot — preventing replay).
        Raises :class:`ChallengeExpired` when the challenge has aged out
        or was already consumed. Raises :class:`InvalidAssertion` when
        py_webauthn rejects the response. Audits
        :data:`AuditLogMessage.USER_PASSKEY_REGISTERED` on success.
        """

        key = self._reg_key(user.id)
        b64 = await self.redis.get(key)
        if b64 is None:
            raise ChallengeExpired(
                f"No registration challenge found for user {user.id}"
            )
        # One-shot: delete before verify so a parallel re-submit can't
        # replay. The decoded bytes survive in local scope for the verify
        # call regardless.
        await self.redis.delete(key)

        if isinstance(b64, bytes):
            b64 = b64.decode("ascii")
        expected_challenge = _b64url_decode(b64)

        try:
            verified = verify_registration_response(
                credential=attestation_response,
                expected_challenge=expected_challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
                # PREFERRED on the options side; matching here would
                # exclude PREFERRED-but-not-actually-verified responses.
                require_user_verification=False,
            )
        except InvalidRegistrationResponse as exc:
            raise InvalidAssertion(str(exc)) from exc

        # Map VerifiedRegistration -> UserWebAuthnCredential row.
        aaguid: UUID | None = None
        if verified.aaguid and verified.aaguid != _NULL_AAGUID:
            try:
                aaguid = UUID(verified.aaguid)
            except (ValueError, AttributeError):
                aaguid = None

        # Transports come from the authenticator's hint in the
        # attestationResponse JSON, NOT from the verified result — the lib
        # doesn't surface them. Comma-joined to match the column type.
        raw_transports = (
            attestation_response.get("response", {}).get("transports") or []
        )
        transports = ",".join(raw_transports) if raw_transports else None

        # py_webauthn returns credential_device_type as a CredentialDeviceType
        # enum or its string value depending on version. Compare against the
        # canonical "multi_device" string both ways.
        device_type = verified.credential_device_type
        device_type_value = getattr(device_type, "value", device_type)
        backup_eligible = device_type_value == "multi_device"

        credential = UserWebAuthnCredential(
            user_id=user.id,
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            transports=transports,
            aaguid=aaguid,
            backup_eligible=backup_eligible,
            backup_state=bool(verified.credential_backed_up),
            attestation_obj=verified.attestation_object,
        )
        await self.credential_repo.create(credential)

        # MFA-2 T13: registering a passkey transitions the user to
        # MFA-enrolled if they weren't already (the helper is a no-op
        # when the flag is already True). This is the canonical
        # ``mfa_enabled=False -> True`` flip on first-passkey enrollment.
        await recompute_mfa_enabled(
            user,
            totp_repo=self.totp_repo,
            webauthn_repo=self.credential_repo,
            user_repo=self.user_repo,
        )

        self.audit_logger(
            AuditLogMessage.USER_PASSKEY_REGISTERED,
            subject_user_id=user.id,
            extra={"credential_id_hex": verified.credential_id.hex()[:32]},
        )

        return credential

    # ------------------------------------------------------------------
    # Assertion ceremony
    # ------------------------------------------------------------------

    async def begin_assertion(
        self,
        user: "User",
        *,
        rp_id: str,
        login_session_id: UUID,
    ) -> dict[str, Any]:
        """Issue a ``PublicKeyCredentialRequestOptions`` payload.

        Stores the challenge at ``webauthn:auth:{login_session_id}`` so a
        compromised LoginSession can't replay an assertion across
        sessions. ``allowCredentials`` is populated with the user's
        registered credentials.
        """

        existing = await self.credential_repo.list_by_user_id(user.id)
        allow_credentials = [
            PublicKeyCredentialDescriptor(
                id=cred.credential_id,
                transports=(
                    [AuthenticatorTransport(t) for t in cred.transports_list]
                    if cred.transports
                    else None
                ),
            )
            for cred in existing
        ]

        options = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        await self.redis.set(
            self._auth_key(login_session_id),
            _b64url_encode(options.challenge),
            ex=self.CHALLENGE_TTL_SECONDS,
        )

        return options_to_json_dict(options)

    async def verify_assertion(
        self,
        user: "User",
        *,
        rp_id: str,
        origin: str,
        login_session_id: UUID,
        assertion_response: dict[str, Any],
    ) -> UserWebAuthnCredential:
        """Verify the assertion response and bump the credential's counters.

        Failure modes (each raises a distinct typed exception so the
        route can map them to HTTP statuses):

        - :class:`ChallengeExpired` — no challenge in Redis (TTL or replay).
        - :class:`CredentialNotFound` — ``rawId`` doesn't match any row.
        - :class:`InvalidAssertion` — py_webauthn signature check failed.
        - :class:`SignCountRollback` — counter regressed (cloned authenticator).

        On success: updates ``sign_count`` + ``last_used_at`` and audits
        :data:`AuditLogMessage.USER_PASSKEY_VERIFIED`.
        """

        key = self._auth_key(login_session_id)
        b64 = await self.redis.get(key)
        if b64 is None:
            raise ChallengeExpired(
                f"No authentication challenge for session {login_session_id}"
            )
        await self.redis.delete(key)

        if isinstance(b64, bytes):
            b64 = b64.decode("ascii")
        expected_challenge = _b64url_decode(b64)

        # Decode rawId to look up the credential before invoking verify so
        # we can give a "this credential isn't registered" diagnostic
        # without burning the user's lockout counter on a transport-level
        # mismatch.
        raw_id_b64 = assertion_response.get("rawId") or assertion_response.get(
            "id"
        )
        if not raw_id_b64:
            self.audit_logger(
                AuditLogMessage.USER_PASSKEY_VERIFY_FAILED,
                subject_user_id=user.id,
                extra={"reason": "credential_not_found"},
            )
            raise CredentialNotFound("Assertion response missing rawId/id")

        try:
            credential_id_bytes = _b64url_decode(raw_id_b64)
        except (ValueError, TypeError) as exc:
            self.audit_logger(
                AuditLogMessage.USER_PASSKEY_VERIFY_FAILED,
                subject_user_id=user.id,
                extra={"reason": "credential_not_found"},
            )
            raise CredentialNotFound(
                f"Could not decode rawId: {exc}"
            ) from exc

        cred = await self.credential_repo.get_by_credential_id(
            credential_id_bytes
        )
        if cred is None:
            self.audit_logger(
                AuditLogMessage.USER_PASSKEY_VERIFY_FAILED,
                subject_user_id=user.id,
                extra={"reason": "credential_not_found"},
            )
            raise CredentialNotFound(
                f"No credential matches rawId for user {user.id}"
            )

        try:
            verified = verify_authentication_response(
                credential=assertion_response,
                expected_challenge=expected_challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
                credential_public_key=cred.public_key,
                credential_current_sign_count=cred.sign_count,
                require_user_verification=False,
            )
        except InvalidAuthenticationResponse as exc:
            self.audit_logger(
                AuditLogMessage.USER_PASSKEY_VERIFY_FAILED,
                subject_user_id=user.id,
                extra={"reason": "invalid_signature"},
            )
            raise InvalidAssertion(str(exc)) from exc

        # Sign-count rollback: monotonic counter regressed.
        # Special-case `new_sign_count == 0`: Apple iCloud Keychain and
        # Google Password Manager passkeys never increment, so they
        # always report 0. Treating that as rollback would lock out
        # every platform-keychain user.
        if (
            verified.new_sign_count <= cred.sign_count
            and cred.sign_count > 0
            and verified.new_sign_count != 0
        ):
            self.audit_logger(
                AuditLogMessage.USER_PASSKEY_SIGN_COUNT_ROLLBACK,
                subject_user_id=user.id,
                extra={
                    "credential_id_hex": cred.credential_id.hex()[:32],
                    "stored": cred.sign_count,
                    "received": verified.new_sign_count,
                },
            )
            raise SignCountRollback(
                f"sign_count rollback: stored={cred.sign_count}, "
                f"received={verified.new_sign_count}"
            )

        await self.credential_repo.update_after_assertion(
            cred.credential_id,
            sign_count=verified.new_sign_count,
            last_used_at=datetime.now(UTC),
        )

        self.audit_logger(
            AuditLogMessage.USER_PASSKEY_VERIFIED,
            subject_user_id=user.id,
            extra={"credential_id_hex": cred.credential_id.hex()[:32]},
        )

        return cred

    # ------------------------------------------------------------------
    # Dashboard management surface
    # ------------------------------------------------------------------

    async def list_for_user(
        self, user: "User"
    ) -> list[UserWebAuthnCredential]:
        """Return the user's credentials in newest-first order."""

        return await self.credential_repo.list_by_user_id(user.id)

    async def delete(
        self,
        *,
        user: "User",
        credential_id: UUID,
    ) -> bool:
        """User-scoped credential delete.

        Returns ``True`` iff a row was actually removed (so the route can
        return 404 on a missing/foreign id without an extra round-trip).
        Audits :data:`AuditLogMessage.USER_PASSKEY_DELETED` only on a real
        deletion — silent 404s do NOT fire an audit event.
        """

        rowcount = await self.credential_repo.delete_by_id_for_user(
            credential_id, user.id
        )
        if rowcount > 0:
            # MFA-2 T13: removing a passkey may have left the user with
            # no remaining factors — recompute ``mfa_enabled`` from the
            # authoritative DB state. If they still have a confirmed
            # TOTP secret OR another passkey, the flag stays True; only
            # when no factor remains does it flip False.
            await recompute_mfa_enabled(
                user,
                totp_repo=self.totp_repo,
                webauthn_repo=self.credential_repo,
                user_repo=self.user_repo,
            )
            self.audit_logger(
                AuditLogMessage.USER_PASSKEY_DELETED,
                subject_user_id=user.id,
                extra={"credential_id": str(credential_id)},
            )
        return rowcount > 0

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _reg_key(self, user_id: UUID) -> str:
        return f"{self.CHALLENGE_KEY_PREFIX}:reg:{user_id}"

    def _auth_key(self, login_session_id: UUID) -> str:
        return f"{self.CHALLENGE_KEY_PREFIX}:auth:{login_session_id}"
