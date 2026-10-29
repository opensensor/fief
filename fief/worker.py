import sentry_sdk
from sentry_sdk.integrations.dramatiq import DramatiqIntegration
from sentry_sdk.integrations.redis import RedisIntegration

from fief import __version__
from fief.logger import init_logger, logger
from fief.settings import settings

sentry_sdk.init(
    dsn=settings.sentry_dsn_worker,
    environment=settings.environment.value,
    traces_sample_rate=0.1,
    release=settings.sentry_release or __version__,
    send_default_pii=False,
    max_request_body_size="never",
    include_local_variables=False,
    integrations=[DramatiqIntegration(), RedisIntegration()],
)

from fief import tasks  # noqa: E402

init_logger()
logger.info("Fief Worker started", version=__version__)

__all__ = ["tasks"]
