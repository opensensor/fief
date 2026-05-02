from fastapi import Depends, Request

from fief.models import Brand
from fief.repositories import BrandRepository


async def get_current_brand(
    request: Request,
    repository: BrandRepository = Depends(BrandRepository),
) -> Brand | None:
    host = request.url.hostname
    if host:
        brand = await repository.get_by_host(host)
        if brand is not None:
            return brand

    return await repository.get_default()
