from pydantic import UUID4
from sqlalchemy import delete, select

from fief.models import UserTotpSecret
from fief.repositories.base import BaseRepository, UUIDRepositoryMixin


class UserTotpSecretRepository(
    BaseRepository[UserTotpSecret], UUIDRepositoryMixin[UserTotpSecret]
):
    model = UserTotpSecret

    async def get_by_user_id(self, user_id: UUID4) -> UserTotpSecret | None:
        statement = select(UserTotpSecret).where(UserTotpSecret.user_id == user_id)
        return await self.get_one_or_none(statement)

    async def get_confirmed_by_user_id(
        self, user_id: UUID4
    ) -> UserTotpSecret | None:
        statement = select(UserTotpSecret).where(
            UserTotpSecret.user_id == user_id,
            UserTotpSecret.confirmed_at.is_not(None),
        )
        return await self.get_one_or_none(statement)

    async def delete_by_user_id(self, user_id: UUID4) -> None:
        statement = delete(UserTotpSecret).where(UserTotpSecret.user_id == user_id)
        await self._execute_statement(statement)
