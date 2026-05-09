"""Per-account lockout with progressive ladder (SEC-1 T10).

Lockout state lives in :class:`fief.models.UserLockout` (table
``fief_user_lockouts``). The schema, the ladder logic, and the
read-then-write race tolerance all live in
:class:`fief.repositories.user_lockout.UserLockoutRepository`; this
service is the orchestration layer that the auth routes call.

Call sites
~~~~~~~~~~
- ``/login`` (T11): :meth:`check_locked` before authenticate;
  :meth:`record_failed` on bad credentials; :meth:`reset` on success.
- ``/api/users/{id}/unlock`` (T15): :meth:`reset` from the admin route.
- Password-reset success (T17): :meth:`reset`.

Audit messages emitted here:

- :data:`AuditLogMessage.USER_ACCOUNT_LOCKED` — fires once per ladder
  threshold cross (5 / 10 / 20 / 50). Subsequent failures inside an
  active lockout still increment the counter but do **not** re-audit.
- :data:`AuditLogMessage.USER_ACCOUNT_AUTO_UNLOCKED` — fires when an
  expired ``locked_until`` is observed on the next attempt. We clear the
  timestamp but **keep ``failed_count``** so successive failures keep
  climbing the ladder; only a successful login (:meth:`reset`) zeros it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fief.logger import AuditLogger
from fief.models import AuditLogMessage, User
from fief.repositories import UserLockoutRepository

__all__ = ["AccountLocked", "AccountLockoutService"]


class AccountLocked(Exception):
    """Raised by :meth:`AccountLockoutService.check_locked` when the user
    has an active (future-dated) lockout.

    ``retry_after_seconds`` is a positive integer; callers wire it into
    the HTTP ``Retry-After`` header for clients that respect it.
    """

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Account locked; retry in {retry_after_seconds}s"
        )


class AccountLockoutService:
    """Per-account lockout with progressive ladder.

    SEC-1 lockout state lives in ``fief_user_lockouts``. The service is
    invoked from ``/login`` (T11) on credential success/failure and from
    the admin unlock endpoint (T15).
    """

    # Ladder thresholds duplicated from the repository's private ``_LADDER``
    # so this class is a self-contained spec of the lockout policy. Both
    # must agree on the values; the repo applies the duration on the write
    # path, this service uses the threshold counts to decide when to audit.
    LADDER: list[tuple[int, timedelta]] = [
        (5, timedelta(minutes=1)),
        (10, timedelta(minutes=5)),
        (20, timedelta(minutes=15)),
        (50, timedelta(hours=24)),
    ]

    def __init__(
        self,
        repo: UserLockoutRepository,
        audit_logger: AuditLogger,
    ) -> None:
        self.repo = repo
        self.audit_logger = audit_logger

    async def check_locked(self, user: User) -> None:
        """Raise :class:`AccountLocked` if ``user`` has an active lockout.

        If ``locked_until`` has elapsed, auto-unlock by clearing
        ``locked_until`` (keeping ``failed_count`` intact) and audit
        :data:`AuditLogMessage.USER_ACCOUNT_AUTO_UNLOCKED`. The next
        failed attempt will then continue from the existing
        ``failed_count`` rather than start over at 1.
        """

        row = await self.repo.get_by_user_id(user.id)
        if row is None or row.locked_until is None:
            return

        now = datetime.now(UTC)
        if row.locked_until <= now:
            # Lockout window has elapsed. Clear ``locked_until`` but KEEP
            # ``failed_count`` — successive failures should still climb
            # the ladder; only a successful login (``reset``) zeros the
            # counter.
            await self.repo.upsert(
                user.id,
                failed_count=row.failed_count,
                locked_until=None,
            )
            self.audit_logger(
                AuditLogMessage.USER_ACCOUNT_AUTO_UNLOCKED,
                subject_user_id=user.id,
                extra={"failed_count": row.failed_count},
            )
            return

        retry_after = max(1, int((row.locked_until - now).total_seconds()))
        raise AccountLocked(retry_after)

    async def record_failed(self, user: User) -> None:
        """Increment ``failed_count`` and apply the ladder.

        If the new count crosses a ladder threshold, the repository
        sets ``locked_until``; we then emit
        :data:`AuditLogMessage.USER_ACCOUNT_LOCKED` exactly once per
        rung. Counts that fall between thresholds (e.g. a 6th failure
        while a 5-rung lockout is still active) increment silently.
        """

        row = await self.repo.increment_and_apply_ladder(user.id)
        # Detect a ladder cross — ``locked_until`` was just set/extended
        # by the repo because ``failed_count`` matched a rung.
        crossed = any(row.failed_count == n for n, _dur in self.LADDER)
        if crossed and row.locked_until is not None:
            self.audit_logger(
                AuditLogMessage.USER_ACCOUNT_LOCKED,
                subject_user_id=user.id,
                extra={
                    "failed_count": row.failed_count,
                    "locked_until": row.locked_until.isoformat(),
                },
            )

    async def reset(self, user: User) -> None:
        """Clear ``failed_count`` and ``locked_until``.

        Called on successful login (T11) and on password reset (T17). Also
        used by the admin unlock endpoint (T15), which audits
        :data:`AuditLogMessage.USER_ACCOUNT_ADMIN_UNLOCKED` separately at
        the route level.
        """

        await self.repo.clear(user.id)
