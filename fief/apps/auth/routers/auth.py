import urllib.parse
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import RedirectResponse
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
    has_valid_session_token,
)
from fief.dependencies.authentication_flow import get_authentication_flow
from fief.dependencies.login_hint import LoginHint, get_login_hint
from fief.dependencies.logger import get_audit_logger
from fief.dependencies.oauth_provider import get_oauth_providers
from fief.dependencies.repositories import get_repository
from fief.dependencies.security import (
    get_recovery_code_service,
    get_totp_service,
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
from fief.services.security.recovery_codes import RecoveryCodeService
from fief.services.security.totp import TotpService, VerifyResult
from fief.services.user_manager import InvalidEmailVerificationCodeError, UserManager
from fief.settings import settings

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
):
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

    if await form_helper.is_submitted_and_valid():
        user = await user_manager.authenticate(
            form.email.data, form.password.data, tenant.id
        )
        if user is None or not user.is_active:
            return await form_helper.get_error_response(
                _("Invalid email or password"), "bad_credentials"
            )

        # Always clear stale MFA carry-state at the start of a fresh /login
        # POST. This defends against reusing a session that retained pending
        # MFA state from a previously abandoned challenge.
        if login_session is not None:
            login_session.mfa_pending_user_id = None
            login_session.mfa_attempts_count = 0
            login_session.mfa_locked_until = None
            await login_session_repository.update(login_session)

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
            response, user.id, session_token=session_token
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
):
    form_helper = FormHelper(
        VerifyEmailForm,
        "auth/verify_email.html",
        request=request,
        context={**context, "code_length": settings.email_verification_code_length},
    )
    form = await form_helper.get_form()

    if await form_helper.is_submitted_and_valid():
        try:
            user = await user_manager.verify_email(
                user, form.code.data, request=request
            )
        except InvalidEmailVerificationCodeError:
            return await form_helper.get_error_response(
                _(
                    "The verification code is invalid. Please check that you have entered it correctly. "
                    "If the code was copied and pasted, ensure it has not expired. "
                    "If it has been more than one hour, please request a new verification code."
                ),
                "invalid_code",
            )

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


def _redirect_to_login_generic(
    request: Request, tenant: Tenant
) -> RedirectResponse:
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

    login_session.mfa_attempts_count = (
        login_session.mfa_attempts_count or 0
    ) + 1
    locked = False
    if login_session.mfa_attempts_count >= MFA_MAX_ATTEMPTS:
        login_session.mfa_locked_until = (
            datetime.now(UTC) + MFA_LOCKOUT_DURATION
        )
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
    user_repository: UserRepository = Depends(
        get_repository(UserRepository)
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
    locked = await _record_failed_mfa_attempt(
        login_session, login_session_repository
    )
    audit_logger(
        AuditLogMessage.USER_MFA_VERIFY_FAILED,
        subject_user_id=user.id,
        extra={
            "reason": "replay" if result == VerifyResult.REPLAY else "invalid"
        },
    )
    if locked:
        return _redirect_to_login_generic(request, tenant)

    message = _("Invalid code. Please try again.")
    form.code.errors.append(message)
    return await form_helper.get_error_response(message, "invalid_mfa_code")


@router.api_route(
    "/mfa/recover", methods=["GET", "POST"], name="auth:mfa_recover"
)
async def mfa_recover(
    request: Request,
    session_token: SessionToken | None = Depends(get_session_token),
    authentication_flow: AuthenticationFlow = Depends(get_authentication_flow),
    totp_service: TotpService = Depends(get_totp_service),
    recovery_code_service: RecoveryCodeService = Depends(
        get_recovery_code_service
    ),
    audit_logger: AuditLogger = Depends(get_audit_logger),
    tenant: Tenant = Depends(get_current_tenant),
    context: BaseContext = Depends(get_base_context),
    login_session: LoginSession | None = Depends(get_optional_login_session),
    login_session_repository: LoginSessionRepository = Depends(
        get_repository(LoginSessionRepository)
    ),
    user_repository: UserRepository = Depends(
        get_repository(UserRepository)
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
            session_token=session_token,
        )
        # ``recovery_code_service.consume`` already audit-logged
        # USER_MFA_RECOVERY_CODE_USED on success; no double-emit needed.
        return response

    locked = await _record_failed_mfa_attempt(
        login_session, login_session_repository
    )
    audit_logger(
        AuditLogMessage.USER_MFA_VERIFY_FAILED,
        subject_user_id=user.id,
        extra={"reason": "recovery_invalid"},
    )
    if locked:
        return _redirect_to_login_generic(request, tenant)

    message = _("Invalid recovery code. Please try again.")
    form.code.errors.append(message)
    return await form_helper.get_error_response(
        message, "invalid_recovery_code"
    )


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
    client_repository: ClientRepository = Depends(
        get_repository(ClientRepository)
    ),
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
