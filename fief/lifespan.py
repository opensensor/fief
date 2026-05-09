import contextlib
from collections.abc import AsyncGenerator
from typing import Any, TypedDict

from fastapi import FastAPI

from fief import __version__, tasks
from fief.db.main import create_main_async_session_maker, create_main_engine
from fief.dependencies.redis import close_redis
from fief.logger import init_logger, logger
from fief.services.posthog import get_server_id
from fief.settings import settings


class LifespanState(TypedDict):
    main_async_session_maker: Any
    server_id: str


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[LifespanState, None]:
    init_logger()

    # T4 (MFA-1): require a Fernet key for the TOTP secret column at boot.
    # The MFA routes (T13/T14) ship unconditionally once merged, so this
    # check runs unconditionally — there is no "is MFA wired up?" flag to
    # gate it on.
    if settings.mfa_secret_encryption_keys:
        n_keys = len(settings.mfa_secret_encryption_keys)
    elif settings.mfa_secret_encryption_key:
        n_keys = 1
    else:
        raise EnvironmentError("MFA_SECRET_ENCRYPTION_KEY must be set")
    logger.info("MFA encryption: %d active key(s)", n_keys)

    main_engine = create_main_engine()

    logger.info("Fief Server started", version=__version__)

    if settings.telemetry_enabled:
        logger.warning(
            "Telemetry is enabled.\n"
            "We will collect data to better understand how Fief is used and improve the project.\n"
            "You can opt-out by setting the environment variable `TELEMETRY_ENABLED=false`.\n"
            "Read more about Fief's telemetry here: https://docs.fief.dev/telemetry"
        )
        tasks.send_task(tasks.heartbeat)

    yield {
        "main_async_session_maker": create_main_async_session_maker(main_engine),
        "server_id": get_server_id(),
    }

    await main_engine.dispose()

    # SEC-1 T6: return the async Redis pool's connections cleanly. This
    # runs after the SQL engine dispose so any in-flight request that
    # was draining still has Redis available; if the pool was never
    # built (e.g. startup aborted), close_redis() is a no-op.
    await close_redis()

    logger.info("Fief Server stopped")
