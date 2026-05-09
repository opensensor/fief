"""Dependency factories for the MFA-1 security services.

These mirror the wiring style used elsewhere in :mod:`fief.dependencies` —
each service is instantiated per-request from the matching repository
dependencies and the request-scoped :class:`AuditLogger`. Routes consume
them via :func:`fastapi.Depends`; tests can override them through
``app.dependency_overrides`` like any other dependency.
"""

from __future__ import annotations

import httpx
import redis.asyncio
from fastapi import HTTPException, Request, status
from fastapi import Depends

from fief.dependencies.logger import get_audit_logger
from fief.dependencies.redis import get_redis
from fief.dependencies.repositories import get_repository
from fief.logger import AuditLogger
from fief.models import Tenant, User
from fief.repositories import (
    RefreshTokenRepository,
    SessionTokenRepository,
    UserLockoutRepository,
    UserMfaRecoveryCodeRepository,
    UserRepository,
    UserTotpSecretRepository,
)
from fief.repositories.user_webauthn_credential import (
    UserWebAuthnCredentialRepository,
)
from fief.services.security.account_lockout import AccountLockoutService
from fief.services.security.breached_passwords import BreachedPasswordChecker
from fief.services.security.device_sessions import DeviceSessionsService
from fief.services.security.rate_limiter import RateLimiter
from fief.services.security.recovery_codes import RecoveryCodeService
from fief.services.security.totp import TotpService
from fief.services.security.webauthn import WebAuthnService
from fief.settings import settings

__all__ = [
    "close_http_client",
    "enforce_tenant_mfa_required",
    "get_account_lockout_service",
    "get_breached_password_checker",
    "get_device_sessions_service",
    "get_http_client",
    "get_rate_limiter",
    "get_recovery_code_service",
    "get_totp_service",
    "get_webauthn_service",
]


async def get_totp_service(
    totp_repo: UserTotpSecretRepository = Depends(
        get_repository(UserTotpSecretRepository)
    ),
    recovery_repo: UserMfaRecoveryCodeRepository = Depends(
        get_repository(UserMfaRecoveryCodeRepository)
    ),
    user_repo: UserRepository = Depends(get_repository(UserRepository)),
    audit_logger: AuditLogger = Depends(get_audit_logger),
    webauthn_repo: UserWebAuthnCredentialRepository = Depends(
        get_repository(UserWebAuthnCredentialRepository)
    ),
) -> TotpService:
    return TotpService(
        totp_repo=totp_repo,
        recovery_repo=recovery_repo,
        user_repo=user_repo,
        audit_logger=audit_logger,
        webauthn_repo=webauthn_repo,
    )


async def get_recovery_code_service(
    recovery_repo: UserMfaRecoveryCodeRepository = Depends(
        get_repository(UserMfaRecoveryCodeRepository)
    ),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> RecoveryCodeService:
    return RecoveryCodeService(
        recovery_repo=recovery_repo,
        audit_logger=audit_logger,
    )


async def get_rate_limiter(
    redis_client: redis.asyncio.Redis = Depends(get_redis),
) -> RateLimiter:
    """Per-request :class:`RateLimiter` bound to the singleton async
    Redis client. Tests override either this factory or
    :func:`fief.dependencies.redis.get_redis` to inject ``fakeredis``."""

    return RateLimiter(redis_client)


async def get_account_lockout_service(
    user_lockout_repo: UserLockoutRepository = Depends(
        get_repository(UserLockoutRepository)
    ),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> AccountLockoutService:
    """Per-request :class:`AccountLockoutService` (SEC-1 T10).

    Wired into ``/login`` (T11) and the admin unlock endpoint (T15). The
    service is stateless apart from its repo + audit-logger handles, so a
    fresh instance per request is the simplest correct model and matches
    the MFA-1 service factories above.
    """

    return AccountLockoutService(user_lockout_repo, audit_logger)


# ---------------------------------------------------------------------------
# SEC-2 T6: HIBP breached-password checker
# ---------------------------------------------------------------------------
#
# Process-wide singleton ``httpx.AsyncClient`` so we share a connection
# pool across requests instead of doing TCP/TLS handshakes per
# password-set. The lifespan teardown closes it via :func:`close_http_client`.

_http_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Return the shared :class:`httpx.AsyncClient` for outbound HTTP.

    Built lazily on first use; pool is reused across requests so HIBP
    keep-alive amortises the TLS handshake. Tests can either override
    this dependency or close + replace the singleton between cases.
    """

    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                settings.breached_password_timeout_ms / 1000.0
            )
        )
    return _http_client


async def close_http_client() -> None:
    """Close the shared HTTP client on app shutdown.

    Safe to call when the client was never built (e.g. shutdown after a
    failed startup). Mirrors :func:`fief.dependencies.redis.close_redis`
    in style: clear the singleton *before* awaiting close so a
    concurrent ``get_http_client()`` cannot hand out an in-flight-closing
    instance.
    """

    global _http_client
    if _http_client is None:
        return
    client = _http_client
    _http_client = None
    await client.aclose()


async def get_breached_password_checker(
    redis_client: redis.asyncio.Redis = Depends(get_redis),
    http_client: httpx.AsyncClient = Depends(get_http_client),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> BreachedPasswordChecker:
    """Per-request :class:`BreachedPasswordChecker` (SEC-2 T6).

    The service is stateless apart from its three dependency handles, so
    a fresh instance per request is cheaper than maintaining a service
    singleton and trivial to override in tests.
    """

    return BreachedPasswordChecker(redis_client, http_client, audit_logger)


# ---------------------------------------------------------------------------
# UX-1 T10: combined device-sessions service
# ---------------------------------------------------------------------------


async def get_device_sessions_service(
    session_repo: SessionTokenRepository = Depends(
        get_repository(SessionTokenRepository)
    ),
    refresh_repo: RefreshTokenRepository = Depends(
        get_repository(RefreshTokenRepository)
    ),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> DeviceSessionsService:
    """Per-request :class:`DeviceSessionsService` (UX-1 T10).

    Wired into the dashboard's ``/security/sessions`` routes (T11) and
    invoked from other services on auto-revoke triggers (password
    change, MFA state change, recovery-code use). Stateless apart from
    its repo + audit-logger handles, so a fresh instance per request
    matches the rest of the security service factories above.
    """

    return DeviceSessionsService(session_repo, refresh_repo, audit_logger)


# ---------------------------------------------------------------------------
# MFA-2 T6: WebAuthn / passkey service
# ---------------------------------------------------------------------------


async def get_webauthn_service(
    cred_repo: UserWebAuthnCredentialRepository = Depends(
        get_repository(UserWebAuthnCredentialRepository)
    ),
    redis_client: redis.asyncio.Redis = Depends(get_redis),
    audit_logger: AuditLogger = Depends(get_audit_logger),
    totp_repo: UserTotpSecretRepository = Depends(
        get_repository(UserTotpSecretRepository)
    ),
    user_repo: UserRepository = Depends(get_repository(UserRepository)),
) -> WebAuthnService:
    """Per-request :class:`WebAuthnService` (MFA-2 T6).

    Wired into the ``/security/passkeys`` dashboard routes (T7) and the
    ``/mfa/passkey`` 2FA challenge (T9). Stateless apart from its
    dependency handles (credential repo + Redis + audit logger + the
    TOTP / user repos used by the MFA-2 T13 ``recompute_mfa_enabled``
    helper) — fresh instance per request matches the rest of the
    security service factories above.
    """

    return WebAuthnService(
        cred_repo,
        redis_client,
        audit_logger,
        totp_repo=totp_repo,
        user_repo=user_repo,
    )


# ---------------------------------------------------------------------------
# T16: tenant-level MFA enforcement gate
# ---------------------------------------------------------------------------
#
# When ``tenant.mfa_required`` is true, users without ``mfa_enabled`` must
# be funneled to the dashboard enrollment landing (``/security/mfa``)
# before they can use any other dashboard feature. The gate is wired into
# ``get_base_context`` so every dashboard route inherits it; a path
# allow-list lets the enrollment flow itself pass through (otherwise the
# user could never enroll).


def _is_mfa_setup_path(path: str) -> bool:
    """Return ``True`` if ``path`` is part of the MFA enrollment flow.

    Both the landing page and its sub-routes (begin / confirm / disable /
    recovery-codes) live under ``/security/mfa``. We allow that whole
    subtree through the enforcement gate so the user can actually enroll.
    Any tenant slug prefix is stripped before comparison.
    """

    # The current tenant's URL prefix (``/{slug}``) was already stripped
    # by FastAPI's mount before the request reaches dashboard routes, so
    # ``request.url.path`` here is already relative to the dashboard
    # router. We test both shapes defensively.
    return "/security/mfa" in path


def enforce_tenant_mfa_required(
    request: Request,
    user: User,
    tenant: Tenant,
) -> bool:
    """Enforce ``tenant.mfa_required`` on dashboard requests.

    Returns ``True`` when the gate is active for this user (so the
    template can show a banner). Raises a 307 redirect to the
    enrollment landing when the user is on a non-allow-listed path.

    When the gate is not active (tenant doesn't require MFA, or the
    user is already enrolled), this is a no-op returning ``False``.
    """

    if not (tenant.mfa_required and not user.mfa_enabled):
        return False

    if _is_mfa_setup_path(request.url.path):
        # User is already on the enrollment flow — let them through and
        # signal "enforcement active" so the layout renders the banner.
        return True

    # Otherwise, redirect them to the enrollment landing with a flag the
    # template can use to render a banner.
    target = str(tenant.url_for(request, "auth.dashboard:mfa_index"))
    sep = "&" if "?" in target else "?"
    raise HTTPException(
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={"Location": f"{target}{sep}mfa_required=1"},
    )
