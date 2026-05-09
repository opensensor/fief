from datetime import datetime

from pydantic import UUID4
from sqlalchemy import delete, func, select, update

from fief.models import UserWebAuthnCredential
from fief.repositories.base import BaseRepository, UUIDRepositoryMixin


class UserWebAuthnCredentialRepository(
    BaseRepository[UserWebAuthnCredential],
    UUIDRepositoryMixin[UserWebAuthnCredential],
):
    model = UserWebAuthnCredential

    async def list_by_user_id(
        self, user_id: UUID4
    ) -> list[UserWebAuthnCredential]:
        statement = (
            select(UserWebAuthnCredential)
            .where(UserWebAuthnCredential.user_id == user_id)
            .order_by(UserWebAuthnCredential.created_at.desc())
        )
        return await self.list(statement)

    async def get_by_credential_id(
        self, credential_id: bytes
    ) -> UserWebAuthnCredential | None:
        statement = select(UserWebAuthnCredential).where(
            UserWebAuthnCredential.credential_id == credential_id
        )
        return await self.get_one_or_none(statement)

    async def get_by_id_for_user(
        self, id: UUID4, user_id: UUID4
    ) -> UserWebAuthnCredential | None:
        statement = select(UserWebAuthnCredential).where(
            UserWebAuthnCredential.id == id,
            UserWebAuthnCredential.user_id == user_id,
        )
        return await self.get_one_or_none(statement)

    async def delete_by_id_for_user(self, id: UUID4, user_id: UUID4) -> int:
        statement = delete(UserWebAuthnCredential).where(
            UserWebAuthnCredential.id == id,
            UserWebAuthnCredential.user_id == user_id,
        )
        result = await self._execute_statement(statement)
        return result.rowcount or 0

    async def count_for_user(self, user_id: UUID4) -> int:
        statement = (
            select(func.count())
            .select_from(UserWebAuthnCredential)
            .where(UserWebAuthnCredential.user_id == user_id)
        )
        result = await self._execute_query(statement)
        return result.scalar_one()

    async def update_after_assertion(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        last_used_at: datetime,
    ) -> None:
        statement = (
            update(UserWebAuthnCredential)
            .where(UserWebAuthnCredential.credential_id == credential_id)
            .values(sign_count=sign_count, last_used_at=last_used_at)
        )
        await self._execute_statement(statement)

    async def rename_by_id_for_user(
        self, id: UUID4, user_id: UUID4, label: str
    ) -> int:
        statement = (
            update(UserWebAuthnCredential)
            .where(
                UserWebAuthnCredential.id == id,
                UserWebAuthnCredential.user_id == user_id,
            )
            .values(label=label)
        )
        result = await self._execute_statement(statement)
        return result.rowcount or 0
