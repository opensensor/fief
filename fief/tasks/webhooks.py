import uuid

import dramatiq
from dramatiq.middleware import CurrentMessage

from fief.models import Webhook
from fief.repositories import WebhookLogRepository, WebhookRepository
from fief.services.webhooks.delivery import WebhookDelivery, WebhookDeliveryError
from fief.services.webhooks.models import WebhookEvent
from fief.settings import settings
from fief.tasks.base import ObjectDoesNotExistTaskError, TaskBase


class DeliverWebhookTask(TaskBase):
    __name__ = "deliver_webhook"

    async def run(self, webhook_id: str, event: str):
        # Phase 1: Fetch webhook data (short-lived session)
        async with self.get_main_session() as session:
            webhook_repository = WebhookRepository(session)
            webhook = await webhook_repository.get_by_id(uuid.UUID(webhook_id))

            if webhook is None:
                raise ObjectDoesNotExistTaskError(Webhook, webhook_id)

            # Extract what we need before closing the session
            webhook_url = webhook.url
            webhook_secret = webhook.secret
            webhook_obj_id = webhook.id

        retries = 0
        if (message := CurrentMessage.get_current_message()) is not None:
            retries = message.options.get("retries", 0)

        parsed_event = WebhookEvent.model_validate_json(event)

        # Phase 2: HTTP delivery (no DB session held)
        webhook_log = await WebhookDelivery.execute_delivery(
            url=webhook_url,
            secret=webhook_secret,
            webhook_id=webhook_obj_id,
            event=parsed_event,
            attempt=retries + 1,
        )

        # Phase 3: Log result (short-lived session)
        async with self.get_main_session() as session:
            webhook_log_repository = WebhookLogRepository(session)
            await webhook_log_repository.create(webhook_log)

        if not webhook_log.success:
            raise WebhookDeliveryError(webhook_log.error_message or "Delivery failed")


def should_retry_deliver_webhook(retries_so_far, exception):
    return retries_so_far < settings.webhooks_max_attempts and isinstance(
        exception, WebhookDeliveryError
    )


deliver_webhook = dramatiq.actor(
    DeliverWebhookTask(), retry_when=should_retry_deliver_webhook
)


class TriggerWebhooksTask(TaskBase):
    __name__ = "trigger_webhooks"

    async def run(self, event: str):
        async with self.get_main_session() as session:
            webhook_repository = WebhookRepository(session)
            webhooks = await webhook_repository.all()
            parsed_event = WebhookEvent.model_validate_json(event)
            for webhook in webhooks:
                if parsed_event.type in webhook.events:
                    self.send_task(
                        deliver_webhook, webhook_id=str(webhook.id), event=event
                    )


trigger_webhooks = dramatiq.actor(TriggerWebhooksTask())
