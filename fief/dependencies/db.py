from collections.abc import AsyncGenerator

from fastapi import HTTPException, Request, status
from sqlalchemy.exc import SQLAlchemyError

from fief.db import AsyncSession
from fief.errors import APIErrorCode
from fief.logger import logger


async def get_main_async_session(
    request: Request,
) -> AsyncGenerator[AsyncSession, None]:
    async with request.state.main_async_session_maker() as session:
        try:
            yield session
        except ConnectionRefusedError as e:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=APIErrorCode.SERVER_DATABASE_NOT_AVAILABLE,
            ) from e
        except SQLAlchemyError as e:
            logger.error("Database error, rolling back session", error=str(e))
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=APIErrorCode.SERVER_DATABASE_NOT_AVAILABLE,
            ) from e
