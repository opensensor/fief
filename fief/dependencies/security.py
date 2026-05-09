"""Dependency factories for the MFA-1 security services.

These mirror the wiring style used elsewhere in :mod:`fief.dependencies` —
each service is instantiated per-request from the matching repository
dependencies and the request-scoped :class:`AuditLogger`. Routes consume
them via :func:`fastapi.Depends`; tests can override them through
``app.dependency_overrides`` like any other dependency.
"""

from __future__ import annotations

from fastapi import Depends

from fief.dependencies.logger import get_audit_logger
from fief.dependencies.repositories import get_repository
from fief.logger import AuditLogger
from fief.repositories import (
    UserMfaRecoveryCodeRepository,
    UserRepository,
    UserTotpSecretRepository,
)
from fief.services.security.recovery_codes import RecoveryCodeService
from fief.services.security.totp import TotpService

__all__ = ["get_recovery_code_service", "get_totp_service"]


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
