import hashlib

from fastapi import APIRouter, Depends, Header, Request, Response, status
from fastapi.responses import RedirectResponse

from fief.apps.auth.forms.register import RF, get_register_form_class
from fief.dependencies.auth import (
    BaseContext,
    get_base_context,
    get_optional_login_session,
)
from fief.dependencies.authentication_flow import get_authentication_flow
from fief.dependencies.client_ip import ClientIpInfo, get_client_ip_info
from fief.dependencies.logger import get_audit_logger
from fief.dependencies.oauth_provider import get_oauth_providers
from fief.dependencies.register import (
    get_optional_registration_session,
    get_registration_flow,
)
from fief.dependencies.security import get_rate_limiter
from fief.dependencies.tenant import get_current_tenant
from fief.exceptions import LoginException
from fief.forms import FormHelper
from fief.locale import gettext_lazy as _
from fief.logger import AuditLogger
from fief.models import (
    AuditLogMessage,
    OAuthProvider,
    RegistrationSession,
    RegistrationSessionFlow,
    Tenant,
)
from fief.schemas.auth import LoginError
from fief.services.authentication_flow import AuthenticationFlow
from fief.services.registration_flow import RegistrationFlow
from fief.services.security.rate_limiter import (
    RateLimiter,
    RateLimitExceeded,
    RateLimitWindow,
)
from fief.services.user_manager import UserAlreadyExistsError
from fief.settings import settings


def _hash_key(key: str) -> str:
    """Truncated SHA-256 of a rate-limit key, used in audit-log ``extra``.

    SEC-1 T17 mandates that ``USER_RATE_LIMIT_EXCEEDED`` records the
    ``key_hash`` (deterministic 16-char prefix) instead of the raw key
    so audit consumers can correlate hits without the audit log itself
    storing PII (emails / IPv6 /64 buckets). The helper is duplicated
    here because T17 (which moves it to a shared util) is a downstream
    task; flip to the shared form when T17 lands.
    """

    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

router = APIRouter()


@router.api_route(
    "/register",
    methods=["GET", "POST"],
    dependencies=[Depends(get_optional_login_session)],
    name="register:register",
)
async def register(
    request: Request,
    hx_trigger: str | None = Header(None),
    register_form_class: type[RF] = Depends(get_register_form_class),
    registration_flow: RegistrationFlow = Depends(get_registration_flow),
    authentication_flow: AuthenticationFlow = Depends(get_authentication_flow),
    registration_session: RegistrationSession | None = Depends(
        get_optional_registration_session
    ),
    oauth_providers: list[OAuthProvider] | None = Depends(get_oauth_providers),
    tenant: Tenant = Depends(get_current_tenant),
    context: BaseContext = Depends(get_base_context),
    ip_info: ClientIpInfo = Depends(get_client_ip_info),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    audit_logger: AuditLogger = Depends(get_audit_logger),
):
    if not tenant.registration_allowed:
        raise LoginException(
            LoginError.get_registration_disabled(_("Registration is disabled")),
            fatal=True,
        )

    response: Response
    form_helper = FormHelper(
        register_form_class,
        "auth/register.html",
        request=request,
        context={
            **context,
            "finalize": registration_session is not None
            and registration_session.flow != RegistrationSessionFlow.PASSWORD,
            "oauth_providers": oauth_providers,
        },
    )
    form = await form_helper.get_form()

    # SEC-1 T13: per-IP rate limit on POST /register. Skipped on GET
    # (which is just rendering the form) and skipped entirely when the
    # global ``rate_limit_enabled`` kill-switch is off. The throttled
    # response uses deliberately vague copy ("Something went wrong") so
    # an attacker can't tell rate-limiting from any other failure.
    if request.method == "POST" and settings.rate_limit_enabled:
        try:
            await rate_limiter.check(
                scope="register_ip",
                key=ip_info.rate_limit_key,
                window=RateLimitWindow(
                    settings.rate_limit_register_per_ip_per_min, 60
                ),
            )
        except RateLimitExceeded:
            audit_logger(
                AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                extra={
                    "scope": "register_ip",
                    "key_hash": _hash_key(ip_info.rate_limit_key),
                    "endpoint": "/register",
                    "client_ip": ip_info.raw,
                },
            )
            return await form_helper.get_error_response(
                _("Something went wrong. Please try again later."),
                error_code="rate_limited",
            )

    if (
        request.method != "POST"
        and registration_session is not None
        and registration_session.email
    ):
        form.email.data = registration_session.email

    if (
        registration_session is not None
        and await form_helper.is_submitted_and_valid()
        and hx_trigger is None
    ):
        try:
            user = await registration_flow.create_user(
                form.data, tenant, registration_session, request=request
            )
        except UserAlreadyExistsError:
            # SEC-1 T13: enumeration hardening. In production the silent
            # branch returns the same redirect a fresh registration would
            # — same Location header, same status code, no leaky
            # ``X-Fief-Error: user_already_exists``. We deliberately do
            # NOT create a session token (we have no real user here);
            # the verify-request page that follows will then bounce the
            # session-less visitor back through the standard auth flow,
            # so legit-but-forgetful users still land on a familiar
            # screen. v1 does NOT also send a "your account already
            # exists at this email — sign in or reset your password"
            # reminder email; that's a documented follow-up (see PRD
            # plan, "Open questions deferred"). Dev/staging keep the
            # explicit error by setting the flag to False.
            if settings.register_silent_on_email_collision:
                return RedirectResponse(
                    tenant.url_path_for(request, "auth:verify_email_request"),
                    status_code=status.HTTP_302_FOUND,
                )
            return await form_helper.get_error_response(
                _("A user with the same email address already exists."),
                error_code="user_already_exists",
            )
        else:
            response = RedirectResponse(
                tenant.url_path_for(request, "auth:verify_email_request"),
                status_code=status.HTTP_302_FOUND,
            )
            response = await authentication_flow.create_session_token(response, user.id)
            response = await registration_flow.set_login_hint(
                response, registration_session
            )
            response = await registration_flow.delete_registration_session(
                response, registration_session
            )
            return response

    response = await form_helper.get_response()
    if registration_session is None:
        await registration_flow.create_registration_session(
            response, flow=RegistrationSessionFlow.PASSWORD, tenant=tenant
        )
    return response
