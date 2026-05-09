from datetime import datetime

from pydantic import UUID4
from sqlalchemy import delete, select, update

from fief.models import SessionToken
from fief.repositories.base import BaseRepository, ExpiresAtMixin, UUIDRepositoryMixin


class SessionTokenRepository(
    BaseRepository[SessionToken],
    UUIDRepositoryMixin[SessionToken],
    ExpiresAtMixin[SessionToken],
):
    model = SessionToken

    async def get_by_token(
        self, token: str, *, fresh: bool = True
    ) -> SessionToken | None:
        statement = select(SessionToken).where(SessionToken.token == token)
        if fresh:
            statement = statement.where(SessionToken.is_expired.is_(False))

        return await self.get_one_or_none(statement)

    async def list_by_user_id(self, user_id: UUID4) -> list[SessionToken]:
        """List a user's non-expired session tokens, newest first.

        Filters out expired rows so the device list never surfaces zombie
        sessions even if the periodic ``delete_expired`` sweep hasn't run
        yet.
        """
        statement = (
            select(SessionToken)
            .where(SessionToken.user_id == user_id)
            .where(SessionToken.is_expired.is_(False))
            .order_by(SessionToken.created_at.desc())
        )
        return await self.list(statement)

    async def delete_by_id_for_user(
        self, token_id: UUID4, user_id: UUID4
    ) -> int:
        """Delete a single session token, scoped to the owning user.

        The ``user_id`` predicate is the authorization defence — without
        it, knowing a token id would be enough to revoke another user's
        session. Returns the number of rows deleted (0 if the token did
        not exist or did not belong to ``user_id``).
        """
        statement = delete(SessionToken).where(
            SessionToken.id == token_id,
            SessionToken.user_id == user_id,
        )
        result = await self._execute_statement(statement)
        return result.rowcount

    async def delete_all_except_for_user(
        self, user_id: UUID4, except_ids: list[UUID4]
    ) -> int:
        """Delete every session token for ``user_id`` except those in ``except_ids``.

        - Pass ``[current_session_id]`` to revoke all OTHER sessions
          (the "Sign out everywhere else" button and auto-revoke
          triggers).
        - Pass ``[]`` to revoke EVERYTHING for the user.
        Returns the number of rows deleted.
        """
        statement = delete(SessionToken).where(SessionToken.user_id == user_id)
        if except_ids:
            statement = statement.where(SessionToken.id.notin_(except_ids))
        result = await self._execute_statement(statement)
        return result.rowcount

    async def touch_last_seen(
        self,
        token_id: UUID4,
        *,
        last_seen_at: datetime,
        last_seen_ip: str,
    ) -> None:
        """Update the ``last_seen_at`` / ``last_seen_ip`` columns.

        Kept as a small UPDATE (no SELECT round-trip) so the per-request
        dependency that calls it stays cheap.
        """
        statement = (
            update(SessionToken)
            .where(SessionToken.id == token_id)
            .values(last_seen_at=last_seen_at, last_seen_ip=last_seen_ip)
        )
        await self._execute_statement(statement)
