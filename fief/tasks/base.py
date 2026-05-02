import asyncio
import contextlib
import uuid
from collections.abc import AsyncGenerator, Callable
from typing import ClassVar
from urllib.parse import urlparse

import dramatiq
import jinja2
from dramatiq.brokers.redis import RedisBroker
from dramatiq.middleware import CurrentMessage
from pydantic import UUID4
from sqlalchemy.orm import selectinload

from fief.db import AsyncSession
from fief.db.main import get_single_main_async_session
from fief.logger import logger
from fief.middlewares.locale import BabelMiddleware, get_babel_middleware_kwargs
from fief.models import Brand, Tenant, User
from fief.models.generics import BaseModel
from fief.paths import EMAIL_TEMPLATES_DIRECTORY
from fief.repositories import (
    BrandRepository,
    EmailTemplateRepository,
    TenantRepository,
    UserRepository,
)
from fief.services.email import EmailProvider
from fief.services.email_template.renderers import (
    EmailSubjectRenderer,
    EmailTemplateRenderer,
)
from fief.settings import settings

redis_parameters = urlparse(settings.redis_url)
redis_broker = RedisBroker(
    host=redis_parameters.hostname,
    port=redis_parameters.port,
    username=redis_parameters.username,
    password=redis_parameters.password,
    # Heroku Redis with TLS use self-signed certs, so we need to tinker a bit
    ssl=redis_parameters.scheme == "rediss",
    ssl_cert_reqs=None,
)
redis_broker.add_middleware(CurrentMessage())
dramatiq.set_broker(redis_broker)


SendTask = Callable[..., None]


def send_task(task: dramatiq.Actor, *args, **kwargs):
    logger.debug("Send task", task=task.actor_name)
    task.send(*args, **kwargs)


email_provider = settings.get_email_provider()


class TaskError(Exception):
    pass


class ObjectDoesNotExistTaskError(TaskError):
    def __init__(self, object_type: type[BaseModel], id: str):
        super().__init__(f"{object_type.__name__} with id {id} does not exist.")


class TaskBase:
    __name__: ClassVar[str]

    def __init__(
        self,
        get_main_session: Callable[
            ..., contextlib.AbstractAsyncContextManager[AsyncSession]
        ] = get_single_main_async_session,
        email_provider: EmailProvider = email_provider,
        send_task: SendTask = send_task,
    ) -> None:
        self.get_main_session = get_main_session
        self.email_provider = email_provider
        self.send_task = send_task

        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(EMAIL_TEMPLATES_DIRECTORY), autoescape=True
        )
        self.jinja_env.add_extension("jinja2.ext.i18n")

    def __call__(self, *args, **kwargs):
        with asyncio.Runner() as runner:
            BabelMiddleware(app=None, **get_babel_middleware_kwargs())
            logger.info("Start task", task=self.__name__)
            result = runner.run(self.run(*args, **kwargs))
            logger.info("Done task", task=self.__name__)
            return result

    async def _get_user(self, user_id: UUID4) -> User:
        async with self.get_main_session() as session:
            repository = UserRepository(session)
            user = await repository.get_by_id(user_id)
            if user is None:
                raise TaskError()
            return user

    async def _get_tenant(self, tenant_id: UUID4) -> Tenant:
        async with self.get_main_session() as session:
            repository = TenantRepository(session)
            tenant = await repository.get_by_id(
                tenant_id, (selectinload(Tenant.email_domain),)
            )
            if tenant is None:
                raise TaskError()
            return tenant

    async def _get_brand(self, brand_id: UUID4) -> Brand | None:
        async with self.get_main_session() as session:
            repository = BrandRepository(session)
            return await repository.get_by_id(
                brand_id, (selectinload(Brand.email_domain),)
            )

    async def _resolve_email_sender(
        self, tenant: Tenant, brand_id: str | None
    ) -> tuple[str, str | None]:
        if brand_id is None:
            return tenant.get_email_sender()
        brand = await self._get_brand(uuid.UUID(brand_id))
        if brand is None:
            return tenant.get_email_sender()
        return brand.get_email_sender(fallback_tenant=tenant)

    @contextlib.asynccontextmanager
    async def _get_email_template_renderer(
        self,
    ) -> AsyncGenerator[EmailTemplateRenderer, None]:
        async with self.get_main_session() as session:
            repository = EmailTemplateRepository(session)
            yield EmailTemplateRenderer(repository)

    @contextlib.asynccontextmanager
    async def _get_email_subject_renderer(
        self,
    ) -> AsyncGenerator[EmailSubjectRenderer, None]:
        async with self.get_main_session() as session:
            repository = EmailTemplateRepository(session)
            yield EmailSubjectRenderer(repository)
