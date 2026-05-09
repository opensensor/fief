import hashlib

from fastapi import APIRouter, Depends, Header, Query, Request, status
from fastapi.responses import RedirectResponse

from fief.apps.auth.forms.reset import ForgotPasswordForm, ResetPasswordForm
from fief.dependencies.auth import (
    BaseContext,
    get_base_context,
    get_optional_login_session,
)
from fief.dependencies.client_ip import ClientIpInfo, get_client_ip_info
from fief.dependencies.logger import get_audit_logger
from fief.dependencies.security import get_rate_limiter
from fief.dependencies.tenant import get_current_tenant
from fief.dependencies.users import get_user_manager
from fief.forms import FormHelper
from fief.locale import gettext_lazy as _
from fief.logger import AuditLogger
from fief.models import AuditLogMessage, LoginSession, Tenant
from fief.services.security.rate_limiter import (
    RateLimitExceeded,
    RateLimiter,
    RateLimitWindow,
)
from fief.services.user_manager import (
    InvalidResetPasswordTokenError,
    UserDoesNotExistError,
    UserInactiveError,
    UserManager,
)
from fief.settings import settings

router = APIRouter()


def _hash_key(key: str) -> str:
    """Truncated SHA-256 fingerprint of a rate-limit bucket key.

    Used in audit-log ``extra.key_hash`` so support engineers can correlate
    two log lines reporting the same bucket without ever seeing the raw
    email or IP. T11/T17 will likely consolidate this into a shared helper
    once /login is wired; until then the helper is local to this module
    so T12 does not block on T11's landing.
    """

    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


@router.api_route("/forgot", methods=["GET", "POST"], name="reset:forgot")
async def forgot_password(
    request: Request,
    user_manager: UserManager = Depends(get_user_manager),
    tenant: Tenant = Depends(get_current_tenant),
    context: BaseContext = Depends(get_base_context),
    ip_info: ClientIpInfo = Depends(get_client_ip_info),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    audit_logger: AuditLogger = Depends(get_audit_logger),
):
    form_helper = FormHelper(
        ForgotPasswordForm,
        "auth/forgot_password.html",
        request=request,
        context={**context},
    )
    form = await form_helper.get_form()

    if await form_helper.is_submitted_and_valid():
        # SEC-1 T12: rate limit BEFORE doing any DB work.
        #
        # Two sliding-window gates:
        # * per-IP throttle so a single attacker IP cannot enumerate or
        #   spam reset emails at scale,
        # * per-email throttle so a known target cannot be bombed with
        #   reset emails from rotating IPs.
        #
        # On breach we audit ``USER_RATE_LIMIT_EXCEEDED`` and then fall
        # through to the SAME success page the existing handler returns
        # for both known and unknown emails — parity beats a strict 429
        # here because surfacing "you are rate-limited" would be an
        # attacker oracle. The kill switch ``rate_limit_enabled`` lets
        # ops disable the gate entirely (e.g. during a Redis outage they
        # want to short-circuit even though the limiter already
        # fails-open on RedisError).
        email_normalized = form.email.data.strip().lower()
        breach_key: str | None = None

        if settings.rate_limit_enabled:
            # Each gate gets its own try/except so the audit log can
            # record exactly which bucket breached. The IP gate runs
            # first; if it passes we run the email gate.
            try:
                await rate_limiter.check(
                    scope="forgot_ip",
                    key=ip_info.rate_limit_key,
                    window=RateLimitWindow(
                        settings.rate_limit_forgot_per_ip_per_min, 60
                    ),
                )
            except RateLimitExceeded:
                breach_key = ip_info.rate_limit_key

            if breach_key is None:
                try:
                    await rate_limiter.check(
                        scope="forgot_email",
                        key=email_normalized,
                        window=RateLimitWindow(
                            settings.rate_limit_forgot_per_email_per_hour,
                            3600,
                        ),
                    )
                except RateLimitExceeded:
                    breach_key = email_normalized

        if breach_key is not None:
            audit_logger(
                AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                extra={
                    "scope": "forgot",
                    "key_hash": _hash_key(breach_key),
                    "endpoint": "/forgot-password",
                    "client_ip": ip_info.raw,
                },
            )
            # Render the SAME page the existing handler renders on
            # success — do NOT reveal that we are throttling.
            form_helper.context["success"] = _(
                "Check your inbox! If an account associated with this email address exists in our system, you'll receive a link to reset your password."
            )
            return await form_helper.get_response()

        try:
            user = await user_manager.get_by_email(form.email.data, tenant.id)
            await user_manager.forgot_password(user, request=request)
        except (UserDoesNotExistError, UserInactiveError):
            pass

        form_helper.context["success"] = _(
            "Check your inbox! If an account associated with this email address exists in our system, you'll receive a link to reset your password."
        )

    return await form_helper.get_response()


@router.api_route("/reset", methods=["GET", "POST"], name="reset:reset")
async def reset_password(
    request: Request,
    hx_trigger: str | None = Header(None),
    token: str | None = Query(None),
    user_manager: UserManager = Depends(get_user_manager),
    login_session: LoginSession | None = Depends(get_optional_login_session),
    tenant: Tenant = Depends(get_current_tenant),
    context: BaseContext = Depends(get_base_context),
):
    form_helper = FormHelper(
        ResetPasswordForm,
        "auth/reset_password.html",
        request=request,
        context={**context},
    )
    form = await form_helper.get_form()

    if request.method == "GET":
        if token is None:
            return await form_helper.get_error_response(
                _("The reset password token is missing."), "missing_token", fatal=True
            )
        else:
            form.token.data = token

    if await form_helper.is_submitted_and_valid() and hx_trigger is None:
        try:
            await user_manager.reset_password(
                form.token.data, form.password.data, tenant, request=request
            )
        except (
            InvalidResetPasswordTokenError,
            UserDoesNotExistError,
            UserInactiveError,
        ):
            return await form_helper.get_error_response(
                _("The reset password token is invalid or expired."),
                "invalid_token",
                fatal=True,
            )
        else:
            if login_session is not None:
                redirection = tenant.url_path_for(request, "auth:login")
                return RedirectResponse(
                    url=redirection, status_code=status.HTTP_302_FOUND
                )
            else:
                redirection = tenant.url_path_for(request, "auth.dashboard:profile")
                return RedirectResponse(
                    url=redirection, status_code=status.HTTP_302_FOUND
                )

    return await form_helper.get_response()
