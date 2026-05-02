from sqlalchemy import select

from fief.models import Brand
from fief.repositories.base import BaseRepository, UUIDRepositoryMixin


class BrandRepository(BaseRepository[Brand], UUIDRepositoryMixin[Brand]):
    model = Brand

    async def get_by_host(self, host: str) -> Brand | None:
        statement = select(Brand).where(Brand.host == host)
        return await self.get_one_or_none(statement)

    async def get_default(self) -> Brand | None:
        statement = select(Brand).where(Brand.is_default == True)  # noqa: E712
        return await self.get_one_or_none(statement)
