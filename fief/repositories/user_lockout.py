from datetime import datetime, timedelta, timezone

from pydantic import UUID4
from sqlalchemy import select

from fief.models import UserLockout
from fief.repositories.base import BaseRepository


# SEC-1 lockout ladder: failed_count threshold -> additional lockout duration.
# Any other count value leaves ``locked_until`` untouched (so an existing
# future lockout stays pending instead of being shortened or reset).
_LADDER: dict[int, timedelta] = {
    5: timedelta(minutes=1),
    10: timedelta(minutes=5),
    20: timedelta(minutes=15),
    50: timedelta(hours=24),
}


class UserLockoutRepository(BaseRepository[UserLockout]):
    model = UserLockout

    async def get_by_user_id(self, user_id: UUID4) -> UserLockout | None:
        statement = select(UserLockout).where(UserLockout.user_id == user_id)
        return await self.get_one_or_none(statement)

    async def upsert(
        self,
        user_id: UUID4,
        *,
        failed_count: int,
        locked_until: datetime | None,
    ) -> UserLockout:
        existing = await self.get_by_user_id(user_id)
        if existing is None:
            lockout = UserLockout(
                user_id=user_id,
                failed_count=failed_count,
                locked_until=locked_until,
            )
            return await self.create(lockout)
        existing.failed_count = failed_count
        existing.locked_until = locked_until
        await self.update(existing)
        return existing

    async def increment_and_apply_ladder(self, user_id: UUID4) -> UserLockout:
        """Increment failed counter and apply the ladder.

        Race tolerance per SEC-1 plan T8: read-then-write inside a single
        transaction. Concurrent failed-login bursts may double-increment;
        the result (account locks slightly faster) is in the correct
        direction and avoiding it would require a row-level lock for
        negligible benefit.
        """
        existing = await self.get_by_user_id(user_id)
        now = datetime.now(timezone.utc)

        if existing is None:
            new_count = 1
            new_locked_until: datetime | None = None
            if new_count in _LADDER:
                new_locked_until = now + _LADDER[new_count]
            lockout = UserLockout(
                user_id=user_id,
                failed_count=new_count,
                locked_until=new_locked_until,
            )
            return await self.create(lockout)

        new_count = existing.failed_count + 1
        existing.failed_count = new_count
        if new_count in _LADDER:
            existing.locked_until = now + _LADDER[new_count]
        # else: leave existing.locked_until AS IS — an in-flight lockout
        # should not be reset just because another failure landed between
        # ladder rungs.
        await self.update(existing)
        return existing

    async def clear(self, user_id: UUID4) -> None:
        existing = await self.get_by_user_id(user_id)
        if existing is None:
            return
        existing.failed_count = 0
        existing.locked_until = None
        await self.update(existing)
