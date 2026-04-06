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
        except Exception as e:
            try:
                await session.rollback()
            except Exception:
                logger.error(
                    "Failed to rollback session during error handling",
                    exc_info=True,
                )
            if isinstance(e, (ConnectionRefusedError, SQLAlchemyError)):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=APIErrorCode.SERVER_DATABASE_NOT_AVAILABLE,
                ) from e
            raise
