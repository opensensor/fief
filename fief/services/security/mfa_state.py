"""Shared helper for keeping ``users.mfa_enabled`` coherent (MFA-2 T13).

A user's "MFA enrolled" state is derivable: True iff at least one second
factor is registered (a confirmed TOTP secret OR at least one WebAuthn
credential). Rather than scatter this calculation across every route /
service that mutates one of those factors, every caller funnels through
:func:`recompute_mfa_enabled` after the underlying mutation.

Callers
-------
- :class:`fief.services.security.totp.TotpService.disable` — TOTP
  teardown no longer unconditionally flips ``mfa_enabled=False``; if the
  user still has a passkey registered, the flag must stay True.
- :class:`fief.services.security.webauthn.WebAuthnService.finish_registration`
  — first passkey registered flips ``mfa_enabled=True``.
- :class:`fief.services.security.webauthn.WebAuthnService.delete` —
  removing the last passkey AND no TOTP flips ``mfa_enabled=False``.

Concurrency caveat
------------------
The read-then-write on ``user.mfa_enabled`` is **not** transactional:
two concurrent requests (e.g. a user registering a passkey in one tab
and deleting one in another) could leave a stale value — for example
``mfa_enabled=False`` while a passkey actually exists. Acceptable in v1
because the user can self-heal by toggling once more (the next
register / delete recomputes from authoritative DB state). Revisit this
if support reports inconsistency in production; the fix would be to
wrap the read+write in a serializable transaction or use a row-level
lock on the ``users`` row.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fief.models.user import User
    from fief.repositories.user import UserRepository
    from fief.repositories.user_totp_secret import UserTotpSecretRepository
    from fief.repositories.user_webauthn_credential import (
        UserWebAuthnCredentialRepository,
    )

__all__ = ["recompute_mfa_enabled"]


async def recompute_mfa_enabled(
    user: "User",
    *,
    totp_repo: "UserTotpSecretRepository",
    webauthn_repo: "UserWebAuthnCredentialRepository",
    user_repo: "UserRepository",
) -> None:
    """Re-derive ``users.mfa_enabled`` from the user's enrolled factors.

    Sets ``user.mfa_enabled`` to ``True`` iff the user has either a
    confirmed TOTP row OR at least one WebAuthn credential. Issues a
    ``UPDATE users SET mfa_enabled = ?`` only when the in-memory value
    differs from the desired value, so calling this on every passkey
    register / delete (even when the flag wouldn't change) is cheap
    enough to be unconditional.

    Note: see module docstring for the v1 concurrency caveat — the
    read-then-write is not transactional.
    """

    has_totp = await totp_repo.get_confirmed_by_user_id(user.id) is not None
    passkey_count = await webauthn_repo.count_for_user(user.id)
    desired = has_totp or passkey_count > 0
    if user.mfa_enabled != desired:
        user.mfa_enabled = desired
        await user_repo.update(user)
