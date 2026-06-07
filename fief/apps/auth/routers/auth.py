import asyncio
import hashlib
import time
import urllib.parse
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import AnyUrl
from sqlalchemy import select

from fief.apps.auth.forms.auth import ConsentForm, LoginForm
from fief.apps.auth.forms.mfa import MfaRecoveryForm, TotpVerifyForm
from fief.apps.auth.forms.verify_email import VerifyEmailForm
from fief.dependencies.auth import (
    BaseContext,
    check_unsupported_request_parameter,
    get_authorize_acr,
    get_authorize_client,
    get_authorize_code_challenge,
    get_authorize_prompt,
    get_authorize_redirect_uri,
    get_authorize_response_mode,
    get_authorize_response_type,
    get_authorize_scope,
    get_authorize_screen,
    get_base_context,
    get_consent_prompt,
    get_login_session,
    get_needs_consent,
    get_nonce,
    get_optional_login_session,
    get_verified_branding_origin,
    has_valid_session_token,
)
from fief.dependencies.authentication_flow import get_authentication_flow
from fief.dependencies.brand import get_current_brand
from fief.dependencies.client_ip import ClientIpInfo, get_client_ip_info
from fief.dependencies.logger import get_audit_logger
from fief.dependencies.login_hint import LoginHint, get_login_hint
from fief.dependencies.oauth_provider import get_oauth_providers
from fief.dependencies.repositories import get_repository
from fief.dependencies.security import (
    get_account_lockout_service,
    get_device_sessions_service,
    get_rate_limiter,
    get_recovery_code_service,
    get_totp_service,
    get_webauthn_service,
)
from fief.dependencies.session_token import (
    get_session_token,
    get_session_token_or_login,
    get_user_from_session_token_or_login,
    get_verified_email_user_from_session_token_or_verify,
)
from fief.dependencies.tenant import get_current_tenant
from fief.dependencies.users import get_user_manager
from fief.exceptions import LogoutException
from fief.forms import FormHelper
from fief.locale import gettext_lazy as _
from fief.logger import AuditLogger
from fief.models import (
    AuditLogMessage,
    Brand,
    Client,
    LoginSession,
    OAuthProvider,
    Tenant,
    User,
)
from fief.models.session_token import SessionToken
from fief.repositories import (
    ClientRepository,
    LoginSessionRepository,
    UserRepository,
)
from fief.repositories.session_token import SessionTokenRepository
from fief.schemas.auth import LogoutError
from fief.services.acr import ACR
from fief.services.authentication_flow import AuthenticationFlow
from fief.services.security.account_lockout import (
    AccountLocked,
    AccountLockoutService,
)
from fief.services.security.device_sessions import DeviceSessionsService
from fief.services.security.rate_limiter import (
    RateLimiter,
    RateLimitExceeded,
    RateLimitWindow,
)
from fief.services.security.recovery_codes import RecoveryCodeService
from fief.services.security.totp import TotpService, VerifyResult
from fief.services.security.webauthn import (
    ChallengeExpired,
    CredentialNotFound,
    InvalidAssertion,
    SignCountRollback,
    WebAuthnService,
    derive_rp_params,
)
from fief.services.user_manager import InvalidEmailVerificationCodeError, UserManager
from fief.settings import settings
from fief.templates import templates


def _hash_key(key: str) -> str:
    """Stable, truncated SHA-256 hash for audit log ``key_hash`` fields.

    SEC-1 audit entries record bucket identifiers as a 16-char hex hash so
    support can correlate two log lines reporting the same bucket without
    ever seeing the raw email address or IP — see T17 of the plan.
    """

    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# Maximum allowed wrong MFA attempts on a single LoginSession before it is
# locked. Hard-coded here (rather than in settings) so the value is part of
# the security review surface for MFA-1; T16/T26 will revisit if we want a
# tenant-level override.
MFA_MAX_ATTEMPTS = 5
MFA_LOCKOUT_DURATION = timedelta(minutes=10)

router = APIRouter()


@router.get(
    "/authorize",
    name="auth:authorize",
    dependencies=[Depends(check_unsupported_request_parameter)],
)
async def authorize(
    request: Request,
    response_type: str = Depends(get_authorize_response_type),
    client: Client = Depends(get_authorize_client),
    redirect_uri: str = Depends(get_authorize_redirect_uri),
    response_mode: str = Depends(get_authorize_response_mode),
    scope: list[str] = Depends(get_authorize_scope),
    prompt: str | None = Depends(get_authorize_prompt),
    screen: str = Depends(get_authorize_screen),
    code_challenge_tuple: tuple[str, str] | None = Depends(
        get_authorize_code_challenge
    ),
    nonce: str | None = Depends(get_nonce),
    state: str | None = Query(None),
    login_hint: str | None = Query(None),
    requested_acr: ACR = Depends(get_authorize_acr),
    lang: str | None = Query(None),
    verified_branding_origin: str | None = Depends(get_verified_branding_origin),
    authentication_flow: AuthenticationFlow = Depends(get_authentication_flow),
    has_valid_session_token: bool = Depends(has_valid_session_token),
):
    tenant = client.tenant
    acr = ACR.LEVEL_ONE

    if (
        has_valid_session_token
        and prompt != "login"
        and requested_acr <= ACR.LEVEL_ZERO
    ):
        redirection = tenant.url_path_for(request, "auth:consent")
        acr = ACR.LEVEL_ZERO  # Reuse of existing session, lowest assurance level
    elif screen == "register":
        redirection = tenant.url_path_for(request, "register:register")
    else:
        redirection = tenant.url_path_for(request, "auth:login")

    response = RedirectResponse(url=redirection, status_code=status.HTTP_302_FOUND)
    response = await authentication_flow.create_login_session(
        response,
        response_type=response_type,
        response_mode=response_mode,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        nonce=nonce,
        acr=acr,
        code_challenge_tuple=code_challenge_tuple,
        client=client,
        branding_origin=verified_branding_origin,
    )

    if login_hint is not None:
        response.set_cookie(
            settings.login_hint_cookie_name,
            urllib.parse.quote(login_hint),
            max_age=settings.login_hint_cookie_lifetime_seconds,
            domain=settings.login_hint_cookie_domain,
            secure=settings.login_hint_cookie_secure,
            httponly=True,
        )

    if lang is not None:
        response.set_cookie(
            settings.user_locale_cookie_name,
            lang,
            max_age=settings.user_locale_lifetime_seconds,
            domain=settings.session_cookie_domain,
            secure=settings.session_cookie_secure,
            httponly=True,
        )

    return response


@router.api_route(
    "/login",
    methods=["GET", "POST"],
    name="auth:login",
)
async def login(
    request: Request,
    user_manager: UserManager = Depends(get_user_manager),
    authentication_flow: AuthenticationFlow = Depends(get_authentication_flow),
    session_token: SessionToken | None = Depends(get_session_token),
    oauth_providers: list[OAuthProvider] = Depends(get_oauth_providers),
    login_hint: LoginHint | None = Depends(get_login_hint),
    tenant: Tenant = Depends(get_current_tenant),
    context: BaseContext = Depends(get_base_context),
    login_session: LoginSession | None = Depends(get_optional_login_session),
    login_session_repository: LoginSessionRepository = Depends(
        get_repository(LoginSessionRepository)
    ),
    user_repository: UserRepository = Depends(get_repository(UserRepository)),
    ip_info: ClientIpInfo = Depends(get_client_ip_info),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    account_lockout: AccountLockoutService = Depends(get_account_lockout_service),
    audit_logger: AuditLogger = Depends(get_audit_logger),
):
    # Track wall-clock for the SEC-1 latency floor on failure paths. We
    # initialise the timer at the very top of the handler (NOT after form
    # validation) so the floor includes the cost of form parsing — a
    # noticeably-faster bad-credentials response would otherwise leak that
    # the validation path exited early.
    start_time = time.monotonic()

    # Prefill email with login_hint if it's a string
    initial_form_data = None
    if isinstance(login_hint, str):
        initial_form_data = {"email": login_hint}

    form_helper = FormHelper(
        LoginForm,
        "auth/login.html",
        request=request,
        data=initial_form_data,
        context={
            **context,
            "oauth_providers": oauth_providers,
            "oauth_provider_login_hint": login_hint
            if isinstance(login_hint, OAuthProvider)
            else None,
        },
    )
    form = await form_helper.get_form()

    async def _floor_latency() -> None:
        """Sleep until the wall-clock from ``start_time`` reaches the
        configured ``auth_failure_min_latency_ms`` floor. No-op when the
        request is already over the floor."""

        elapsed_ms = (time.monotonic() - start_time) * 1000
        remaining_ms = settings.auth_failure_min_latency_ms - elapsed_ms
        if remaining_ms > 0:
            await asyncio.sleep(remaining_ms / 1000.0)

    async def _generic_login_error_response(
        retry_after: int | None = None,
    ):
        """Render the same 'Invalid email or password' the bad-credentials
        path returns, with an optional ``Retry-After`` header for HTTP
        clients that respect it (browsers ignore it on form posts; SDKs
        and APIs may not)."""

        await _floor_latency()
        response = await form_helper.get_error_response(
            _("Invalid email or password"), "bad_credentials"
        )
        if retry_after is not None:
            response.headers["Retry-After"] = str(retry_after)
        return response

    if await form_helper.is_submitted_and_valid():
        # Normalised email used for our own keys (rate-limit bucket, lockout
        # row lookup, audit log). ``UserManager.authenticate`` already
        # normalises case-insensitively at the DB level via
        # ``email_lower``; we mirror that here so ``Foo@x.com`` and
        # ``foo@x.com`` hit the same bucket and lockout row.
        email_normalized = form.email.data.strip().lower()

        # ---- Pre-authenticate gates (SEC-1 T11) -------------------------
        # Rate limits and lockout are gated by ``settings.rate_limit_enabled``
        # so a bad rollout / Redis problem can be flipped off via
        # configuration. The factories themselves remain wired regardless;
        # we only skip the side effects here.
        if settings.rate_limit_enabled:
            # 1. Per-IP rate limit. Bucketed against ``ip_info.rate_limit_key``
            #    (IPv6 collapsed to /64) so an attacker can't trivially rotate
            #    through a personal IPv6 allocation.
            try:
                await rate_limiter.check(
                    scope="login_ip",
                    key=ip_info.rate_limit_key,
                    window=RateLimitWindow(
                        settings.rate_limit_login_per_ip_per_min, 60
                    ),
                )
            except RateLimitExceeded as exc:
                audit_logger(
                    AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                    extra={
                        "scope": "login_ip",
                        "key_hash": _hash_key(ip_info.rate_limit_key),
                        "endpoint": "/login",
                        "client_ip": ip_info.raw,
                    },
                )
                return await _generic_login_error_response(
                    retry_after=exc.retry_after_seconds
                )

            # 2. Per-email rate limit. Caps the credential-stuffing rate
            #    against any single account from any source IP combined.
            try:
                await rate_limiter.check(
                    scope="login_email",
                    key=email_normalized,
                    window=RateLimitWindow(
                        settings.rate_limit_login_per_email_per_min, 60
                    ),
                )
            except RateLimitExceeded as exc:
                audit_logger(
                    AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                    extra={
                        "scope": "login_email",
                        "key_hash": _hash_key(email_normalized),
                        "endpoint": "/login",
                        "client_ip": ip_info.raw,
                    },
                )
                return await _generic_login_error_response(
                    retry_after=exc.retry_after_seconds
                )

        # 3. Lockout pre-check. Look up the user up-front so we can both
        #    consult the lockout table AND, if authenticate fails below,
        #    increment the per-account counter (the user reference is
        #    reused so we don't run the lookup twice). The presence of a
        #    matching user is NOT leaked: the response shape is identical
        #    whether the user exists or not.
        existing_user: User | None = None
        if settings.rate_limit_enabled:
            existing_user = await user_repository.get_by_email_and_tenant(
                email_normalized, tenant.id
            )
            if existing_user is not None:
                try:
                    await account_lockout.check_locked(existing_user)
                except AccountLocked as exc:
                    # Treat lockout as a rate-limit equivalent for telemetry
                    # parity (SEC-1 plan T11).
                    audit_logger(
                        AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                        subject_user_id=existing_user.id,
                        extra={
                            "scope": "account_lockout",
                            "endpoint": "/login",
                            "client_ip": ip_info.raw,
                        },
                    )
                    return await _generic_login_error_response(
                        retry_after=exc.retry_after_seconds
                    )

        # ---- Authenticate (unchanged) -----------------------------------
        user = await user_manager.authenticate(
            form.email.data, form.password.data, tenant.id
        )
        if user is None or not user.is_active:
            # Bump the per-account failed counter when the user record
            # exists. ``record_failed`` may set ``locked_until`` if the
            # ladder threshold was crossed; that's audited from inside the
            # service.
            if settings.rate_limit_enabled and existing_user is not None:
                await account_lockout.record_failed(existing_user)
            audit_logger(
                AuditLogMessage.USER_LOGIN_FAILED,
                subject_user_id=existing_user.id if existing_user is not None else None,
                extra={
                    "email": email_normalized,
                    "client_ip": ip_info.raw,
                },
            )
            return await _generic_login_error_response()

        # ---- Successful authenticate path -------------------------------
        # Wipe SEC-1 lockout state so the next failure starts from zero.
        if settings.rate_limit_enabled:
            await account_lockout.reset(user)

        # Always clear stale MFA carry-state at the start of a fresh /login
        # POST. This defends against reusing a session that retained pending
        # MFA state from a previously abandoned challenge.
        if login_session is not None:
            login_session.mfa_pending_user_id = None
            login_session.mfa_attempts_count = 0
            login_session.mfa_locked_until = None
            await login_session_repository.update(login_session)

        # T16: tenant-level enforcement. When the tenant requires MFA but
        # the user hasn't enrolled yet, issue a session cookie (so they
        # can navigate the dashboard normally to enroll) and redirect to
        # the enrollment landing instead of the usual post-login flow.
        # The dashboard route guard (also wired in T16) will keep funneling
        # them back here until they enroll.
        if tenant.mfa_required and not user.mfa_enabled:
            try:
                enroll_path = tenant.url_path_for(request, "auth.dashboard:mfa_index")
            except Exception:
                # Defensive fallback if the dashboard router isn't mounted
                # (e.g. in a stripped-down test app). The dashboard always
                # mounts ``/security/mfa`` as the enrollment landing.
                path_prefix = "" if tenant.default else f"/{tenant.slug}"
                enroll_path = f"{path_prefix}/security/mfa"
            sep = "&" if "?" in enroll_path else "?"
            response = RedirectResponse(
                f"{enroll_path}{sep}mfa_required=1",
                status_code=status.HTTP_302_FOUND,
            )
            response = await authentication_flow.rotate_session_token(
                response, user.id, request, session_token=session_token
            )
            response = await authentication_flow.set_login_hint(
                response, str(user.email)
            )
            return response

        # If the user has MFA enabled, defer issuing a session cookie until
        # the TOTP/recovery challenge succeeds. Mark the login session with
        # the pending user id so the verify route (T14) can identify the
        # user without trusting any client-side state.
        if user.mfa_enabled and login_session is not None:
            login_session.mfa_pending_user_id = user.id
            await login_session_repository.update(login_session)
            try:
                mfa_redirect_path = tenant.url_path_for(request, "auth:mfa_totp")
            except Exception:
                # T14 will register ``auth:mfa_totp``. Until it lands we fall
                # back to the well-known path so this branch is safe to ship
                # ahead of T14's route.
                path_prefix = "" if tenant.default else f"/{tenant.slug}"
                mfa_redirect_path = f"{path_prefix}/mfa/totp"
            response = RedirectResponse(
                mfa_redirect_path,
                status_code=status.HTTP_302_FOUND,
            )
            response = await authentication_flow.set_login_hint(
                response, str(user.email)
            )
            return response

        response = RedirectResponse(
            tenant.url_path_for(request, "auth:verify_email_request"),
            status_code=status.HTTP_302_FOUND,
        )
        response = await authentication_flow.rotate_session_token(
            response, user.id, request, session_token=session_token
        )
        response = await authentication_flow.set_login_hint(response, str(user.email))

        return response

    return await form_helper.get_response()


@router.get("/verify-request", name="auth:verify_email_request")
async def verify_email_request(
    request: Request,
    login_session: LoginSession | None = Depends(get_optional_login_session),
    user: User = Depends(get_user_from_session_token_or_login),
    user_manager: UserManager = Depends(get_user_manager),
    tenant: Tenant = Depends(get_current_tenant),
):
    if user.email_verified:
        if login_session is not None:
            response = RedirectResponse(
                tenant.url_path_for(request, "auth:consent"),
                status_code=status.HTTP_302_FOUND,
            )
        else:
            response = RedirectResponse(
                tenant.url_path_for(request, "auth.dashboard:profile"),
                status_code=status.HTTP_302_FOUND,
            )
        return response

    await user_manager.request_verify_email(user, user.email)

    return RedirectResponse(
        tenant.url_path_for(request, "auth:verify_email"),
        status_code=status.HTTP_302_FOUND,
    )


@router.api_route("/verify", methods=["GET", "POST"], name="auth:verify_email")
async def verify_email(
    request: Request,
    login_session: LoginSession | None = Depends(get_optional_login_session),
    user: User = Depends(get_user_from_session_token_or_login),
    user_manager: UserManager = Depends(get_user_manager),
    tenant: Tenant = Depends(get_current_tenant),
    context: BaseContext = Depends(get_base_context),
    ip_info: ClientIpInfo = Depends(get_client_ip_info),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    audit_logger: AuditLogger = Depends(get_audit_logger),
):
    form_helper = FormHelper(
        VerifyEmailForm,
        "auth/verify_email.html",
        request=request,
        context={**context, "code_length": settings.email_verification_code_length},
    )
    form = await form_helper.get_form()

    async def _generic_invalid_code_response():
        """Render the same form error the bad-code path returns. Used by
        the SEC-1 rate-limit gate so a throttled caller can't tell whether
        the code was valid or whether their bucket was full."""

        return await form_helper.get_error_response(
            _(
                "The verification code is invalid. Please check that you have entered it correctly. "
                "If the code was copied and pasted, ensure it has not expired. "
                "If it has been more than one hour, please request a new verification code."
            ),
            "invalid_code",
        )

    if await form_helper.is_submitted_and_valid():
        # ---- SEC-1 T14: pre-verify rate-limit gates -----------------------
        # The identifier for the per-email bucket is the email of the
        # pending user injected by ``get_user_from_session_token_or_login``;
        # we normalise it for parity with the /login bucket. On
        # RateLimitExceeded we audit and return the SAME generic
        # invalid-code form error the bad-code path renders, so a
        # throttled attacker can't distinguish "bucket full" from "wrong
        # code" — and crucially, can't probe whether the code was for a
        # known account.
        if settings.rate_limit_enabled:
            email_normalized = (user.email or "").strip().lower()

            try:
                await rate_limiter.check(
                    scope="verify_ip",
                    key=ip_info.rate_limit_key,
                    window=RateLimitWindow(
                        settings.rate_limit_verify_per_ip_per_min, 60
                    ),
                )
            except RateLimitExceeded:
                audit_logger(
                    AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                    extra={
                        "scope": "verify_ip",
                        "key_hash": _hash_key(ip_info.rate_limit_key),
                        "endpoint": "/verify-email",
                        "client_ip": ip_info.raw,
                    },
                )
                return await _generic_invalid_code_response()

            if email_normalized:
                try:
                    await rate_limiter.check(
                        scope="verify_email",
                        key=email_normalized,
                        window=RateLimitWindow(
                            settings.rate_limit_verify_per_email_per_5min,
                            300,
                        ),
                    )
                except RateLimitExceeded:
                    audit_logger(
                        AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                        extra={
                            "scope": "verify_email",
                            "key_hash": _hash_key(email_normalized),
                            "endpoint": "/verify-email",
                            "client_ip": ip_info.raw,
                        },
                    )
                    return await _generic_invalid_code_response()

        try:
            user = await user_manager.verify_email(
                user, form.code.data, request=request
            )
        except InvalidEmailVerificationCodeError:
            return await _generic_invalid_code_response()

        if login_session is not None:
            response = RedirectResponse(
                tenant.url_path_for(request, "auth:consent"),
                status_code=status.HTTP_302_FOUND,
            )
        else:
            response = RedirectResponse(
                tenant.url_path_for(request, "auth.dashboard:profile"),
                status_code=status.HTTP_302_FOUND,
            )
        return response

    return await form_helper.get_response()


@router.get("/verify-link", name="auth:verify_email_link")
async def verify_email_link(
    request: Request,
    code: str = Query(...),
    user_manager: UserManager = Depends(get_user_manager),
    tenant: Tenant = Depends(get_current_tenant),
    ip_info: ClientIpInfo = Depends(get_client_ip_info),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    audit_logger: AuditLogger = Depends(get_audit_logger),
):
    """Sessionless one-click email activation. The ``code`` query param is the
    secret (delivered to the address), so possession proves ownership and no
    login session is required — this is what makes the link clickable straight
    from the inbox. On success/failure we bounce to /login with a flag the
    template can surface."""
    login_url = tenant.url_path_for(request, "auth:login")

    if settings.rate_limit_enabled:
        try:
            await rate_limiter.check(
                scope="verify_ip",
                key=ip_info.rate_limit_key,
                window=RateLimitWindow(settings.rate_limit_verify_per_ip_per_min, 60),
            )
        except RateLimitExceeded:
            audit_logger(
                AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                extra={
                    "scope": "verify_ip",
                    "key_hash": _hash_key(ip_info.rate_limit_key),
                    "endpoint": "/verify-link",
                    "client_ip": ip_info.raw,
                },
            )
            return RedirectResponse(login_url, status_code=status.HTTP_302_FOUND)

    try:
        await user_manager.verify_email_by_code(
            code, tenant_id=tenant.id, request=request
        )
    except InvalidEmailVerificationCodeError:
        return RedirectResponse(
            f"{login_url}?verify_error=1", status_code=status.HTTP_302_FOUND
        )

    return RedirectResponse(
        f"{login_url}?verified=1", status_code=status.HTTP_302_FOUND
    )


# ---------------------------------------------------------------------------
# Login-time MFA challenge routes (T14)
# ---------------------------------------------------------------------------
#
# Reached after the /login POST flagged ``LoginSession.mfa_pending_user_id``
# for an MFA-enabled user (T15). These routes never trust client-side state
# beyond the LoginSession cookie itself: the user identity is *always* read
# off ``login_session.mfa_pending_user_id``, never from a form field or a
# query parameter, so a stolen cookie cannot be used to challenge a
# different user's account.
#
# The gating helper below also handles two defense-in-depth concerns:
#
# 1. Lockout — a session that has racked up :data:`MFA_MAX_ATTEMPTS` wrong
#    attempts is bounced to /login until ``mfa_locked_until`` elapses. The
#    /login POST always wipes carry-state at the start (see commit
#    ``3e51874``), so an attacker can't sit on a stale locked session
#    indefinitely once the user re-authenticates.
#
# 2. Orphan self-heal — if ``user.mfa_enabled=True`` but no confirmed
#    ``UserTotpSecret`` row exists (e.g. the secret table was wiped out of
#    band), the GET handlers call :meth:`TotpService.disable` to flip the
#    flag back to false and bounce to /login. That avoids stranding the
#    user on a challenge they can never answer. Audit-logged with
#    ``USER_MFA_STATE_INCONSISTENT`` so the inconsistency is observable.


def _redirect_to_login_generic(request: Request, tenant: Tenant) -> RedirectResponse:
    """Bounce back to /login with a generic flash. Used for every gating
    failure on /mfa/totp and /mfa/recover so we don't leak whether the
    underlying cause was a missing cookie, an unset ``mfa_pending_user_id``,
    a lockout, or a missing user."""

    return RedirectResponse(
        tenant.url_path_for(request, "auth:login"),
        status_code=status.HTTP_302_FOUND,
    )


async def _gate_mfa_challenge(
    request: Request,
    tenant: Tenant,
    login_session: LoginSession | None,
    login_session_repository: LoginSessionRepository,
    user_repository: UserRepository,
) -> tuple[User | None, RedirectResponse | None]:
    """Common gating for the MFA challenge routes.

    Returns ``(user, None)`` on success, or ``(None, redirect_response)``
    when the request must be sent back to /login. The caller is
    responsible for the orphan self-heal step on the GET handlers, since
    that needs the :class:`TotpService` instance.
    """

    if login_session is None or login_session.mfa_pending_user_id is None:
        return None, _redirect_to_login_generic(request, tenant)

    if (
        login_session.mfa_locked_until is not None
        and login_session.mfa_locked_until > datetime.now(UTC)
    ):
        # Defense-in-depth: clear pending user id so a refresh after
        # lockout-expiry forces a fresh /login round-trip rather than
        # silently re-arming the challenge.
        login_session.mfa_pending_user_id = None
        await login_session_repository.update(login_session)
        return None, _redirect_to_login_generic(request, tenant)

    user = await user_repository.get_by_id(login_session.mfa_pending_user_id)
    if user is None:
        # User vanished between /login and /mfa/* — clear carry-state and
        # bounce. This is exceptional but cheap to defend against.
        login_session.mfa_pending_user_id = None
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)
        return None, _redirect_to_login_generic(request, tenant)

    return user, None


async def _maybe_self_heal_orphan_mfa(
    user: User,
    totp_service: TotpService,
    request: Request,
    tenant: Tenant,
    login_session: LoginSession,
    login_session_repository: LoginSessionRepository,
) -> RedirectResponse | None:
    """If ``user.mfa_enabled`` is set but no confirmed secret row exists,
    self-heal by calling :meth:`TotpService.disable` and bounce to /login.
    Returns the redirect response (or ``None`` to continue rendering)."""

    confirmed = await totp_service.totp_repo.get_confirmed_by_user_id(user.id)
    if user.mfa_enabled and confirmed is None:
        await totp_service.disable(user)
        totp_service.audit_logger(
            AuditLogMessage.USER_MFA_STATE_INCONSISTENT,
            subject_user_id=user.id,
            extra={"reason": "missing_confirmed_secret_at_challenge"},
        )
        # Clear the carry-state on the way out so the next /login POST
        # starts clean (the /login POST clears it again — defense in depth).
        login_session.mfa_pending_user_id = None
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)
        return _redirect_to_login_generic(request, tenant)
    return None


async def _record_failed_mfa_attempt(
    login_session: LoginSession,
    login_session_repository: LoginSessionRepository,
) -> bool:
    """Increment ``mfa_attempts_count`` and apply the lockout once the
    threshold is reached. Returns ``True`` when the session is now locked
    (caller should redirect to /login)."""

    login_session.mfa_attempts_count = (login_session.mfa_attempts_count or 0) + 1
    locked = False
    if login_session.mfa_attempts_count >= MFA_MAX_ATTEMPTS:
        login_session.mfa_locked_until = datetime.now(UTC) + MFA_LOCKOUT_DURATION
        locked = True
    await login_session_repository.update(login_session)
    return locked


@router.api_route("/mfa/totp", methods=["GET", "POST"], name="auth:mfa_totp")
async def mfa_totp(
    request: Request,
    session_token: SessionToken | None = Depends(get_session_token),
    authentication_flow: AuthenticationFlow = Depends(get_authentication_flow),
    totp_service: TotpService = Depends(get_totp_service),
    audit_logger: AuditLogger = Depends(get_audit_logger),
    tenant: Tenant = Depends(get_current_tenant),
    context: BaseContext = Depends(get_base_context),
    login_session: LoginSession | None = Depends(get_optional_login_session),
    login_session_repository: LoginSessionRepository = Depends(
        get_repository(LoginSessionRepository)
    ),
    user_repository: UserRepository = Depends(get_repository(UserRepository)),
    ip_info: ClientIpInfo = Depends(get_client_ip_info),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
):
    user, redirect = await _gate_mfa_challenge(
        request,
        tenant,
        login_session,
        login_session_repository,
        user_repository,
    )
    if redirect is not None:
        return redirect
    assert user is not None  # narrowed by _gate_mfa_challenge contract
    assert login_session is not None

    if request.method == "GET":
        orphan_redirect = await _maybe_self_heal_orphan_mfa(
            user,
            totp_service,
            request,
            tenant,
            login_session,
            login_session_repository,
        )
        if orphan_redirect is not None:
            return orphan_redirect

    form_helper = FormHelper(
        TotpVerifyForm,
        "auth/mfa/totp.html",
        request=request,
        context={**context},
    )

    if not await form_helper.is_submitted_and_valid():
        return await form_helper.get_response()

    # ---- SEC-1 T14: per-IP gate ON TOP of MFA-1's per-LoginSession lockout
    # ---------------------------------------------------------------------
    # SEC-1 layers a per-IP rate limit on top of the existing per-LoginSession
    # ``mfa_attempts_count`` lockout that MFA-1 owns. The per-account
    # ``account_lockout.record_failed`` path is intentionally NOT touched
    # here — losing your phone shouldn't lock your whole account on top of
    # the session-bound counter that already does the right thing. Per the
    # SEC-1 plan T14, MFA-1's counter is the right scope for MFA failures.
    #
    # We also fire the gate BEFORE incrementing ``mfa_attempts_count`` so a
    # throttled attacker can't burn through MFA-1's 5-strike budget by
    # spamming a known LoginSession from many IPs. On exceed, we return the
    # SAME generic form error the wrong-code path returns.
    if settings.rate_limit_enabled:
        try:
            await rate_limiter.check(
                scope="mfa_totp_ip",
                key=ip_info.rate_limit_key,
                window=RateLimitWindow(settings.rate_limit_mfa_per_ip_per_min, 60),
            )
        except RateLimitExceeded:
            audit_logger(
                AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                subject_user_id=user.id,
                extra={
                    "scope": "mfa_totp_ip",
                    "key_hash": _hash_key(ip_info.rate_limit_key),
                    "endpoint": "/mfa/totp",
                    "client_ip": ip_info.raw,
                },
            )
            message = _("Invalid code. Please try again.")
            return await form_helper.get_error_response(message, "invalid_mfa_code")

    form = await form_helper.get_form()
    result = await totp_service.verify(user, form.code.data)

    if result == VerifyResult.SUCCESS:
        # Build the redirect to the post-login destination first; we mirror
        # the non-MFA branch of /login here (verify_email_request handles
        # the email-verification gate, then forwards to /consent).
        response = RedirectResponse(
            tenant.url_path_for(request, "auth:verify_email_request"),
            status_code=status.HTTP_302_FOUND,
        )
        response = await authentication_flow.complete_login_after_mfa(
            response,
            login_session,
            user,
            request,
            session_token=session_token,
        )
        audit_logger(
            AuditLogMessage.USER_MFA_VERIFIED,
            subject_user_id=user.id,
        )
        return response

    if result == VerifyResult.INCONSISTENT_STATE:
        # The verify path already audit-logged with reason=decryption_failed
        # or reason=missing_confirmed_secret. Self-heal and bounce.
        await totp_service.disable(user)
        audit_logger(
            AuditLogMessage.USER_MFA_STATE_INCONSISTENT,
            subject_user_id=user.id,
            extra={"reason": "decryption_failed_or_missing_at_verify"},
        )
        login_session.mfa_pending_user_id = None
        login_session.mfa_attempts_count = 0
        login_session.mfa_locked_until = None
        await login_session_repository.update(login_session)
        return _redirect_to_login_generic(request, tenant)

    # INVALID or REPLAY: increment the attempt counter, possibly lock.
    locked = await _record_failed_mfa_attempt(login_session, login_session_repository)
    audit_logger(
        AuditLogMessage.USER_MFA_VERIFY_FAILED,
        subject_user_id=user.id,
        extra={"reason": "replay" if result == VerifyResult.REPLAY else "invalid"},
    )
    if locked:
        return _redirect_to_login_generic(request, tenant)

    message = _("Invalid code. Please try again.")
    form.code.errors.append(message)
    return await form_helper.get_error_response(message, "invalid_mfa_code")


@router.api_route("/mfa/recover", methods=["GET", "POST"], name="auth:mfa_recover")
async def mfa_recover(
    request: Request,
    session_token: SessionToken | None = Depends(get_session_token),
    authentication_flow: AuthenticationFlow = Depends(get_authentication_flow),
    totp_service: TotpService = Depends(get_totp_service),
    recovery_code_service: RecoveryCodeService = Depends(get_recovery_code_service),
    audit_logger: AuditLogger = Depends(get_audit_logger),
    tenant: Tenant = Depends(get_current_tenant),
    context: BaseContext = Depends(get_base_context),
    login_session: LoginSession | None = Depends(get_optional_login_session),
    login_session_repository: LoginSessionRepository = Depends(
        get_repository(LoginSessionRepository)
    ),
    user_repository: UserRepository = Depends(get_repository(UserRepository)),
    ip_info: ClientIpInfo = Depends(get_client_ip_info),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    device_sessions_service: DeviceSessionsService = Depends(
        get_device_sessions_service
    ),
):
    user, redirect = await _gate_mfa_challenge(
        request,
        tenant,
        login_session,
        login_session_repository,
        user_repository,
    )
    if redirect is not None:
        return redirect
    assert user is not None
    assert login_session is not None

    if request.method == "GET":
        orphan_redirect = await _maybe_self_heal_orphan_mfa(
            user,
            totp_service,
            request,
            tenant,
            login_session,
            login_session_repository,
        )
        if orphan_redirect is not None:
            return orphan_redirect

    form_helper = FormHelper(
        MfaRecoveryForm,
        "auth/mfa/recover.html",
        request=request,
        context={**context},
    )

    if not await form_helper.is_submitted_and_valid():
        return await form_helper.get_response()

    # ---- SEC-1 T14: per-IP + per-email gates on /mfa/recover ------------
    # Recovery codes are precious — the PRD asks for the most-locked-down
    # gate on this endpoint. The caps are hardcoded here (5 per 10 min/IP,
    # 3 per hour/email) rather than read from settings; if we want to make
    # them tunable later that's a follow-up. As with /mfa/totp, the SEC-1
    # gate fires BEFORE the recovery-code consume call AND BEFORE the
    # MFA-1 per-LoginSession counter increment, so a throttled attacker
    # cannot burn through either budget. A throttled call returns the
    # SAME generic invalid-code form error the bad-code path renders.
    if settings.rate_limit_enabled:
        try:
            await rate_limiter.check(
                scope="mfa_recover_ip",
                key=ip_info.rate_limit_key,
                window=RateLimitWindow(5, 600),
            )
        except RateLimitExceeded:
            audit_logger(
                AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                subject_user_id=user.id,
                extra={
                    "scope": "mfa_recover_ip",
                    "key_hash": _hash_key(ip_info.rate_limit_key),
                    "endpoint": "/mfa/recover",
                    "client_ip": ip_info.raw,
                },
            )
            message = _("Invalid recovery code. Please try again.")
            return await form_helper.get_error_response(
                message, "invalid_recovery_code"
            )

        email_normalized = (user.email or "").strip().lower()
        if email_normalized:
            try:
                await rate_limiter.check(
                    scope="mfa_recover_email",
                    key=email_normalized,
                    window=RateLimitWindow(3, 3600),
                )
            except RateLimitExceeded:
                audit_logger(
                    AuditLogMessage.USER_RATE_LIMIT_EXCEEDED,
                    subject_user_id=user.id,
                    extra={
                        "scope": "mfa_recover_email",
                        "key_hash": _hash_key(email_normalized),
                        "endpoint": "/mfa/recover",
                        "client_ip": ip_info.raw,
                    },
                )
                message = _("Invalid recovery code. Please try again.")
                return await form_helper.get_error_response(
                    message, "invalid_recovery_code"
                )

    form = await form_helper.get_form()
    accepted = await recovery_code_service.consume(user, form.code.data)

    if accepted:
        # Force re-enroll on next login: tear down both the secret and any
        # remaining recovery codes.
        await totp_service.disable(user)
        response = RedirectResponse(
            tenant.url_path_for(request, "auth:verify_email_request"),
            status_code=status.HTTP_302_FOUND,
        )
        response = await authentication_flow.complete_login_after_mfa(
            response,
            login_session,
            user,
            request,
            session_token=session_token,
        )
        # UX-1 T12: a recovery-code login is the strongest signal we have
        # that the user no longer trusts existing sessions on the account
        # (they presumably reached this path because they lost their TOTP
        # device). Wipe every PRE-recovery session/refresh row; the new
        # post-MFA cookie just minted by ``complete_login_after_mfa`` is
        # passed in as ``current_session_id`` so it survives. Audit logged
        # with ``trigger_reason="recovery_code_used"``.
        new_session_token_id = (
            authentication_flow.last_minted_session_token_id
        )
        await device_sessions_service.auto_revoke_others(
            user.id,
            current_session_id=new_session_token_id,
            reason="recovery_code_used",
        )
        # ``recovery_code_service.consume`` already audit-logged
        # USER_MFA_RECOVERY_CODE_USED on success; no double-emit needed.
        return response

    locked = await _record_failed_mfa_attempt(login_session, login_session_repository)
    audit_logger(
        AuditLogMessage.USER_MFA_VERIFY_FAILED,
        subject_user_id=user.id,
        extra={"reason": "recovery_invalid"},
    )
    if locked:
        return _redirect_to_login_generic(request, tenant)

    message = _("Invalid recovery code. Please try again.")
    form.code.errors.append(message)
    return await form_helper.get_error_response(message, "invalid_recovery_code")


# ---------------------------------------------------------------------------
# MFA-2 T9: Login-time passkey challenge (sibling to /mfa/totp + /mfa/recover)
# ---------------------------------------------------------------------------
#
# Reached the same way as /mfa/totp — the /login POST flagged
# ``LoginSession.mfa_pending_user_id`` for an MFA-enabled user. The same
# gating helper (``_gate_mfa_challenge``) governs cookie-binding, lockout,
# and user-existence checks; the WebAuthn ceremony layers on top.
#
# GET /mfa/passkey embeds a freshly-issued ``PublicKeyCredentialRequestOptions``
# JSON object in the page so the JS bridge (T8 ``authenticateWithEmbeddedOptions``)
# can call ``startAuthentication`` without a separate /begin fetch — we keep
# the 2FA case to a single GET round-trip. Discoverable / passwordless flows
# (MFA-2.5) will need a dedicated /begin endpoint.
#
# POST /mfa/passkey/verify is JSON-only. Body = the WebAuthn AuthenticationResponse
# from ``startAuthentication``. The route maps ``WebAuthnService`` exceptions to
# stable, JS-friendly status codes:
#
#   - ``CredentialNotFound`` / ``InvalidAssertion`` → 401 ``{"error":"invalid"}``
#     and the per-LoginSession lockout counter increments (parity with TOTP).
#   - ``SignCountRollback`` → 401 ``{"error":"credential_compromised"}`` but the
#     counter does NOT increment — a regressed sign count is a credential
#     defect, not a user-attributable wrong attempt. The service already
#     audited ``USER_PASSKEY_SIGN_COUNT_ROLLBACK``.
#   - ``ChallengeExpired`` → 400 ``{"error":"challenge_expired"}`` (the JS bridge
#     reads this and prompts a page reload).
#
# On success the route returns ``{"redirect_to": <verify_email_request URL>}``;
# the JS bridge follows with ``window.location.assign(...)`` so the freshly
# issued session cookie set by ``complete_login_after_mfa`` survives the
# transition.


@router.get("/mfa/passkey", name="auth:mfa_passkey")
async def mfa_passkey(
    request: Request,
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
    tenant: Tenant = Depends(get_current_tenant),
    brand: Brand | None = Depends(get_current_brand),
    context: BaseContext = Depends(get_base_context),
    login_session: LoginSession | None = Depends(get_optional_login_session),
    login_session_repository: LoginSessionRepository = Depends(
        get_repository(LoginSessionRepository)
    ),
    user_repository: UserRepository = Depends(get_repository(UserRepository)),
):
    user, redirect = await _gate_mfa_challenge(
        request,
        tenant,
        login_session,
        login_session_repository,
        user_repository,
    )
    if redirect is not None:
        return redirect
    assert user is not None
    assert login_session is not None

    # Defensive: a user with no passkeys shouldn't have reached this route.
    # Bounce to /mfa/totp (the only other 2FA challenge in v1) rather than
    # render an empty allowCredentials prompt.
    credentials = await webauthn_service.list_for_user(user)
    if not credentials:
        return RedirectResponse(
            tenant.url_path_for(request, "auth:mfa_totp"),
            status_code=status.HTTP_302_FOUND,
        )

    rp_id, _rp_name, _origin = derive_rp_params(brand, tenant)
    options = await webauthn_service.begin_assertion(
        user, rp_id=rp_id, login_session_id=login_session.id
    )

    return templates.TemplateResponse(
        request,
        "auth/mfa/passkey.html",
        {**context, "options": options},
    )


@router.post("/mfa/passkey/verify", name="auth:mfa_passkey_verify")
async def mfa_passkey_verify(
    request: Request,
    session_token: SessionToken | None = Depends(get_session_token),
    authentication_flow: AuthenticationFlow = Depends(get_authentication_flow),
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
    audit_logger: AuditLogger = Depends(get_audit_logger),
    tenant: Tenant = Depends(get_current_tenant),
    brand: Brand | None = Depends(get_current_brand),
    login_session: LoginSession | None = Depends(get_optional_login_session),
    login_session_repository: LoginSessionRepository = Depends(
        get_repository(LoginSessionRepository)
    ),
    user_repository: UserRepository = Depends(get_repository(UserRepository)),
):
    user, redirect = await _gate_mfa_challenge(
        request,
        tenant,
        login_session,
        login_session_repository,
        user_repository,
    )
    if redirect is not None:
        return redirect
    assert user is not None
    assert login_session is not None

    rp_id, _, origin = derive_rp_params(brand, tenant)
    body = await request.json()

    try:
        await webauthn_service.verify_assertion(
            user=user,
            rp_id=rp_id,
            origin=origin,
            login_session_id=login_session.id,
            assertion_response=body,
        )
    except CredentialNotFound:
        # Service already audit-logged USER_PASSKEY_VERIFY_FAILED with
        # ``reason=credential_not_found``; we just bump the counter to
        # match the TOTP lockout ladder.
        await _record_failed_mfa_attempt(login_session, login_session_repository)
        return JSONResponse({"error": "invalid"}, status_code=status.HTTP_401_UNAUTHORIZED)
    except InvalidAssertion:
        # Service already audit-logged USER_PASSKEY_VERIFY_FAILED with
        # ``reason=invalid_signature``.
        await _record_failed_mfa_attempt(login_session, login_session_repository)
        return JSONResponse({"error": "invalid"}, status_code=status.HTTP_401_UNAUTHORIZED)
    except SignCountRollback:
        # The credential is suspect, not the attempt — do NOT burn the
        # user's lockout budget on a sign-count regression. The service
        # already audited USER_PASSKEY_SIGN_COUNT_ROLLBACK.
        return JSONResponse(
            {
                "error": "credential_compromised",
                "detail": "Please contact support.",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    except ChallengeExpired:
        # System-level (TTL or replay), not a wrong attempt — counter stays.
        return JSONResponse(
            {
                "error": "challenge_expired",
                "detail": "Please reload the page and try again.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Success: complete the login. We mirror the TOTP success branch — set
    # cookies on a JSONResponse instead of a RedirectResponse so the JS
    # bridge can read ``redirect_to`` and call window.location.assign(...).
    post_login_url = tenant.url_path_for(request, "auth:verify_email_request")
    response = JSONResponse({"redirect_to": str(post_login_url)})
    response = await authentication_flow.complete_login_after_mfa(
        response,
        login_session,
        user,
        request,
        session_token=session_token,
    )
    # Service already audited USER_PASSKEY_VERIFIED on the happy path.
    return response


@router.api_route(
    "/consent",
    methods=["GET", "POST"],
    name="auth:consent",
    dependencies=[Depends(get_verified_email_user_from_session_token_or_verify)],
)
async def consent(
    request: Request,
    login_session: LoginSession = Depends(get_login_session),
    session_token: SessionToken = Depends(get_session_token_or_login),
    prompt: str | None = Depends(get_consent_prompt),
    needs_consent: bool = Depends(get_needs_consent),
    tenant: Tenant = Depends(get_current_tenant),
    authentication_flow: AuthenticationFlow = Depends(get_authentication_flow),
    context: BaseContext = Depends(get_base_context),
):
    form_helper = FormHelper(
        ConsentForm,
        "auth/consent.html",
        request=request,
        context={
            **context,
            "client": login_session.client,
            "scopes": login_session.scope,
        },
    )
    form = await form_helper.get_form()

    if not needs_consent and prompt != "consent":
        response = await authentication_flow.get_authorization_code_success_redirect(
            login_session=login_session,
            authenticated_at=session_token.created_at,
            user=session_token.user,
            client=login_session.client,
            tenant=tenant,
        )
        response = await authentication_flow.delete_login_session(
            response, login_session
        )
        return response

    if await form_helper.is_submitted_and_valid():
        # Allow
        if form.allow.data:
            user_id = session_token.user_id
            await authentication_flow.create_or_update_grant(
                user_id, login_session.client, login_session.scope
            )
            response = (
                await authentication_flow.get_authorization_code_success_redirect(
                    login_session=login_session,
                    authenticated_at=session_token.created_at,
                    user=session_token.user,
                    client=login_session.client,
                    tenant=tenant,
                )
            )
        # Deny
        elif form.deny.data:
            response = AuthenticationFlow.get_authorization_code_error_redirect(
                login_session.redirect_uri,
                login_session.response_mode,
                "access_denied",
                error_description=_("The user denied access to their data."),
                state=login_session.state,
            )

        response = await authentication_flow.delete_login_session(
            response, login_session
        )
        return response

    return await form_helper.get_response()


@router.get("/logout", name="auth:logout")
async def logout(
    redirect_uri: AnyUrl | None = Query(None),
    session_token: SessionToken | None = Depends(get_session_token),
    session_token_repository: SessionTokenRepository = Depends(
        get_repository(SessionTokenRepository)
    ),
    client_repository: ClientRepository = Depends(get_repository(ClientRepository)),
    tenant: Tenant = Depends(get_current_tenant),
):
    if redirect_uri is None:
        raise LogoutException(
            LogoutError.get_invalid_request(_("redirect_uri is missing")),
            tenant,
        )

    # Validate redirect_uri against registered client redirect URIs
    # to prevent open redirect attacks (CWE-601)
    redirect_uri_str = str(redirect_uri)
    parsed = urllib.parse.urlparse(redirect_uri_str.replace("\\", ""))
    if parsed.scheme and parsed.netloc:
        clients = await client_repository.list(
            select(Client).where(Client.tenant_id == tenant.id)
        )
        allowed_origins = set()
        for client in clients:
            for uri in client.redirect_uris:
                client_parsed = urllib.parse.urlparse(uri)
                if client_parsed.scheme and client_parsed.netloc:
                    allowed_origins.add(
                        f"{client_parsed.scheme}://{client_parsed.netloc}"
                    )
        redirect_origin = f"{parsed.scheme}://{parsed.netloc}"
        if redirect_origin not in allowed_origins:
            raise LogoutException(
                LogoutError.get_invalid_request(
                    _("redirect_uri is not allowed for this tenant")
                ),
                tenant,
            )

    if session_token is not None:
        await session_token_repository.delete(session_token)

    response = RedirectResponse(redirect_uri_str, status_code=status.HTTP_302_FOUND)

    response.delete_cookie(
        settings.session_cookie_name,
        domain=settings.session_cookie_domain,
        secure=settings.session_cookie_secure,
        httponly=True,
    )

    return response
