from datetime import datetime, timezone

from pydantic import UUID4
from sqlalchemy import delete, select

from fief.models import UserMfaRecoveryCode
from fief.repositories.base import BaseRepository, UUIDRepositoryMixin


class UserMfaRecoveryCodeRepository(
    BaseRepository[UserMfaRecoveryCode], UUIDRepositoryMixin[UserMfaRecoveryCode]
):
    model = UserMfaRecoveryCode

    async def list_by_user_id(
        self, user_id: UUID4, *, only_unused: bool = False
    ) -> list[UserMfaRecoveryCode]:
        statement = select(UserMfaRecoveryCode).where(
            UserMfaRecoveryCode.user_id == user_id
        )
        if only_unused:
            statement = statement.where(UserMfaRecoveryCode.used_at.is_(None))
        return await self.list(statement)

    async def delete_by_user_id(self, user_id: UUID4) -> None:
        statement = delete(UserMfaRecoveryCode).where(
            UserMfaRecoveryCode.user_id == user_id
        )
        await self._execute_statement(statement)

    async def mark_used(self, code: UserMfaRecoveryCode) -> UserMfaRecoveryCode:
        code.used_at = datetime.now(timezone.utc)
        await self.update(code)
        return code
