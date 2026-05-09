"""Single-use MFA recovery codes — generation, storage, consumption.

This module owns the entire lifecycle of a user's recovery codes:

- Format: 10 codes per generation, each 8 chars from RFC 4648 base32 (no
  ``0/1/8/9`` to avoid visual ambiguity), displayed as ``XXXX-XXXX``.
- Storage: per-code bcrypt hash in ``user_mfa_recovery_codes.code_hash``.
- Hashing is performed via ``passlib.hash.bcrypt`` directly — **not** via
  the project ``password_helper`` — so recovery-code hashing is decoupled
  from any future migration of the user-password hash scheme.
- Generation uses :func:`secrets.choice`; never :mod:`random`.

The service does no DB session management or transaction control of its
own; it delegates to :class:`UserMfaRecoveryCodeRepository` and assumes
the caller's unit-of-work boundary.
"""

from __future__ import annotations

import secrets

from passlib.hash import bcrypt

from fief.logger import AuditLogger
from fief.models import AuditLogMessage, User, UserMfaRecoveryCode
from fief.repositories.user_mfa_recovery_code import (
    UserMfaRecoveryCodeRepository,
)

__all__ = ["RecoveryCodeService"]


# Base32 alphabet (RFC 4648) without ``0/1/8/9`` so codes read aloud cleanly.
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_CODE_LEN = 8  # total chars before formatting (split 4-4)


def _generate_code() -> str:
    """Return a single ``XXXX-XXXX`` recovery code."""

    half1 = "".join(secrets.choice(_ALPHABET) for _ in range(4))
    half2 = "".join(secrets.choice(_ALPHABET) for _ in range(4))
    return f"{half1}-{half2}"


def _normalize(code: str) -> str:
    """Strip dashes/whitespace and uppercase the input.

    Returns the canonical 8-character form a user typed, regardless of
    whether they reproduced the displayed dash exactly.
    """

    return code.replace("-", "").replace(" ", "").strip().upper()


def _is_well_formed(normalized: str) -> bool:
    """``True`` if ``normalized`` is exactly 8 chars from the alphabet.

    This is the cheap pre-check that lets us reject obviously malformed
    input before doing any bcrypt verifications. Real codes always pass.
    """

    if len(normalized) != _CODE_LEN:
        return False
    return all(ch in _ALPHABET for ch in normalized)


class RecoveryCodeService:
    """Generate and consume single-use MFA recovery codes."""

    NUM_CODES = 10

    def __init__(
        self,
        recovery_repo: UserMfaRecoveryCodeRepository,
        audit_logger: AuditLogger,
    ) -> None:
        self.recovery_repo = recovery_repo
        self.audit_logger = audit_logger

    async def generate_for(self, user: User) -> list[str]:
        """Replace the user's recovery codes with a fresh set of 10.

        Returns the *plaintext* formatted codes; the caller MUST display
        them once and never persist them. The DB only stores bcrypt
        hashes — losing this list means the user must regenerate.
        """

        # One-shot regenerate: wipe any prior rows first so the previous
        # set (used or unused) cannot satisfy a future ``consume`` call.
        await self.recovery_repo.delete_by_user_id(user.id)

        codes: list[str] = []
        seen: set[str] = set()
        # Cap retries defensively — collisions across 32^8 are astronomically
        # unlikely, but we still don't want an infinite loop on a degenerate
        # PRNG.
        attempts = 0
        while len(codes) < self.NUM_CODES and attempts < self.NUM_CODES * 5:
            attempts += 1
            code = _generate_code()
            if code in seen:
                continue
            seen.add(code)
            codes.append(code)

            normalized = _normalize(code)
            row = UserMfaRecoveryCode(
                user_id=user.id,
                code_hash=bcrypt.hash(normalized),
            )
            await self.recovery_repo.create(row)

        self.audit_logger(
            AuditLogMessage.USER_MFA_RECOVERY_CODES_REGENERATED,
            subject_user_id=user.id,
        )

        return codes

    async def consume(self, user: User, code: str) -> bool:
        """Mark a recovery code as used if it matches an unused row.

        Returns ``True`` if the code was accepted and consumed, ``False``
        otherwise. The False branch is identical regardless of whether
        the input was malformed, didn't match, or the user has no codes
        left — by design, we don't want to leak which case fired.

        Iteration runs through every unused row even after a match so
        the timing profile doesn't trivially leak how many valid codes
        remain. (bcrypt.verify is intrinsically O(N) per row, so total
        cost is already O(N) regardless.)
        """

        normalized = _normalize(code)
        if not _is_well_formed(normalized):
            return False

        rows = await self.recovery_repo.list_by_user_id(
            user.id, only_unused=True
        )

        matched: UserMfaRecoveryCode | None = None
        for row in rows:
            try:
                ok = bcrypt.verify(normalized, row.code_hash)
            except (ValueError, TypeError):
                # Defensive: a malformed stored hash should not crash the
                # whole verify pass. Treat as a non-match for this row.
                ok = False
            if ok and matched is None:
                matched = row
            # Intentionally no ``break`` — keep iterating so timing is
            # tied to total stored rows rather than match position.

        if matched is None:
            return False

        await self.recovery_repo.mark_used(matched)
        self.audit_logger(
            AuditLogMessage.USER_MFA_RECOVERY_CODE_USED,
            subject_user_id=user.id,
        )
        return True
