"""Brand-aware notification emails for MFA state changes (T22).

Sends a short transactional email when TOTP-based two-factor authentication
is enabled or disabled on a user's account. The email is rendered through
the existing brand-aware template + sender pipeline, so it goes out from
the brand's mailing address (LightNVR / OwlBooks / etc.) when the change
was initiated from a request bound to that brand's host. Admin-driven
changes (where no brand is in scope) fall back to the tenant default.
"""

from __future__ import annotations

import uuid

import dramatiq

from fief import schemas
from fief.logger import logger
from fief.services.email_template.contexts import EmailContext
from fief.services.email_template.types import EmailTemplateType
from fief.tasks.base import TaskBase


_STATE_TO_TEMPLATE: dict[str, EmailTemplateType] = {
    "enabled": EmailTemplateType.MFA_ENABLED,
    "disabled": EmailTemplateType.MFA_DISABLED,
}


class OnMfaStateChangedTask(TaskBase):
    __name__ = "on_mfa_state_changed"

    async def run(
        self,
        user_id: str,
        state: str,
        brand_id: str | None = None,
    ) -> None:
        try:
            template_type = _STATE_TO_TEMPLATE[state]
        except KeyError:
            logger.warning(
                "on_mfa_state_changed: unknown state, dropping",
                user_id=user_id,
                state=state,
            )
            return

        user = await self._get_user(uuid.UUID(user_id))
        tenant = await self._get_tenant(user.tenant_id)
        brand = await self._get_brand(brand_id)

        context = EmailContext(
            tenant=schemas.tenant.Tenant.model_validate(tenant),
            user=schemas.user.UserEmailContext.model_validate(user),
            brand=schemas.brand.BrandEmailContext.model_validate(brand)
            if brand is not None
            else None,
        )

        async with self._get_email_subject_renderer() as email_subject_renderer:
            subject = await email_subject_renderer.render(template_type, context)

        async with self._get_email_template_renderer() as email_template_renderer:
            html = await email_template_renderer.render(template_type, context)

        self.email_provider.send_email(
            sender=self._resolve_email_sender(tenant, brand),
            recipient=(user.email, None),
            subject=subject,
            html=html,
        )


on_mfa_state_changed = dramatiq.actor(OnMfaStateChangedTask())
