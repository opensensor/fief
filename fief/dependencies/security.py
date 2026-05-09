"""Dependency factories for the MFA-1 security services.

These mirror the wiring style used elsewhere in :mod:`fief.dependencies` —
each service is instantiated per-request from the matching repository
dependencies and the request-scoped :class:`AuditLogger`. Routes consume
them via :func:`fastapi.Depends`; tests can override them through
``app.dependency_overrides`` like any other dependency.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status
from fastapi import Depends

from fief.dependencies.logger import get_audit_logger
from fief.dependencies.repositories import get_repository
from fief.logger import AuditLogger
from fief.models import Tenant, User
from fief.repositories import (
    UserMfaRecoveryCodeRepository,
    UserRepository,
    UserTotpSecretRepository,
)
from fief.services.security.recovery_codes import RecoveryCodeService
from fief.services.security.totp import TotpService

__all__ = [
    "enforce_tenant_mfa_required",
    "get_recovery_code_service",
    "get_totp_service",
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
) -> TotpService:
    return TotpService(
        totp_repo=totp_repo,
        recovery_repo=recovery_repo,
        user_repo=user_repo,
        audit_logger=audit_logger,
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
