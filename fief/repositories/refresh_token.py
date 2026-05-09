from datetime import datetime, timezone

from pydantic import UUID4
from sqlalchemy import delete, select, update

from fief.models import RefreshToken
from fief.repositories.base import BaseRepository, ExpiresAtMixin, UUIDRepositoryMixin


class RefreshTokenRepository(
    BaseRepository[RefreshToken],
    UUIDRepositoryMixin[RefreshToken],
    ExpiresAtMixin[RefreshToken],
):
    model = RefreshToken

    async def get_by_token(
        self, token: str, *, fresh: bool = True
    ) -> RefreshToken | None:
        statement = select(RefreshToken).where(RefreshToken.token == token)
        if fresh:
            statement = statement.where(RefreshToken.is_expired.is_(False))

        return await self.get_one_or_none(statement)

    async def list_by_user_id(self, user_id: UUID4) -> list[RefreshToken]:
        """Return non-expired refresh tokens for a user, newest first."""
        now = datetime.now(timezone.utc)
        statement = (
            select(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .where(RefreshToken.expires_at > now)
            .order_by(RefreshToken.created_at.desc())
        )
        return await self.list(statement)

    async def delete_by_id_for_user(
        self, token_id: UUID4, user_id: UUID4
    ) -> int:
        """Delete a single refresh token, scoped to a user.

        The ``user_id`` scope prevents one user from deleting another
        user's refresh token. Returns the affected rowcount (0 or 1).
        """
        statement = (
            delete(RefreshToken)
            .where(RefreshToken.id == token_id)
            .where(RefreshToken.user_id == user_id)
        )
        result = await self._execute_statement(statement)
        return result.rowcount

    async def delete_all_except_for_user(
        self, user_id: UUID4, except_ids: list[UUID4]
    ) -> int:
        """Delete every refresh token for ``user_id`` except those listed.

        Pass ``except_ids=[]`` to revoke ALL refresh tokens (the
        auto-revoke trigger path — refresh tokens have no concept of
        "the current session"). Returns the rowcount.
        """
        statement = delete(RefreshToken).where(RefreshToken.user_id == user_id)
        if except_ids:
            statement = statement.where(RefreshToken.id.notin_(except_ids))
        result = await self._execute_statement(statement)
        return result.rowcount

    async def touch_last_seen(
        self,
        token_id: UUID4,
        *,
        last_seen_at: datetime,
        last_seen_ip: str,
    ) -> None:
        """Cheap UPDATE bumping ``last_seen_at`` / ``last_seen_ip``.

        Called per refresh-token grant. We deliberately do not update
        ``created_user_agent`` — first-seen UA is the device identity.
        """
        statement = (
            update(RefreshToken)
            .where(RefreshToken.id == token_id)
            .values(last_seen_at=last_seen_at, last_seen_ip=last_seen_ip)
        )
        await self._execute_statement(statement)
