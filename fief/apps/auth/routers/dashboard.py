from typing import TypedDict

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from fief import schemas
from fief.apps.auth.forms.mfa import TotpDisableForm, TotpEnrollConfirmForm
from fief.apps.auth.forms.password import ChangePasswordForm
from fief.apps.auth.forms.profile import PF, ChangeEmailForm, get_profile_form_class
from fief.apps.auth.forms.verify_email import VerifyEmailForm
from fief.apps.auth.responses import HXLocationResponse
from fief.dependencies.brand import get_current_brand
from fief.dependencies.branding import get_show_branding
from fief.dependencies.security import (
    enforce_tenant_mfa_required,
    get_device_sessions_service,
    get_recovery_code_service,
    get_totp_service,
)
from fief.dependencies.session_token import (
    get_session_token_or_login,
    get_verified_email_user_from_session_token_or_verify,
)
from fief.dependencies.tasks import get_send_task
from fief.dependencies.tenant import get_current_tenant
from fief.dependencies.theme import get_current_theme
from fief.dependencies.users import get_user_manager, get_user_update_model
from fief.forms import FormHelper
from fief.locale import gettext_lazy as _
from fief.models import Brand, SessionToken, Tenant, Theme, User
from fief.services.security.device_sessions import DeviceSessionsService
from fief.services.security.recovery_codes import RecoveryCodeService
from fief.services.security.totp import (
    MfaAlreadyEnrolledError,
    TotpService,
    VerifyResult,
)
from fief.services.user_manager import (
    BreachedPasswordError,
    InvalidEmailVerificationCodeError,
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserManager,
)
from fief.settings import settings
from fief.tasks import SendTask
from fief.templates import templates

router = APIRouter()


class BaseContext(TypedDict):
    request: Request
    user: User
    tenant: Tenant
    theme: Theme
    brand: Brand | None
    show_branding: bool
    mfa_enforcement_active: bool


async def get_base_context(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    tenant: Tenant = Depends(get_current_tenant),
    theme: Theme = Depends(get_current_theme),
    brand: Brand | None = Depends(get_current_brand),
    show_branding: bool = Depends(get_show_branding),
) -> BaseContext:
    # T16: tenant-level MFA enforcement. Raises a 307 redirect to the
    # enrollment landing when ``tenant.mfa_required and not
    # user.mfa_enabled`` AND the request is not already on a
    # ``/security/mfa*`` path. Returns ``True`` when the gate is active
    # for this user so the layout can render an "enroll now" banner.
    mfa_enforcement_active = enforce_tenant_mfa_required(request, user, tenant)
    return {
        "request": request,
        "user": user,
        "tenant": tenant,
        "theme": theme,
        "brand": brand,
        "show_branding": show_branding,
        "mfa_enforcement_active": mfa_enforcement_active,
    }


@router.api_route("/", methods=["GET", "POST"], name="auth.dashboard:profile")
async def update_profile(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    user_manager: UserManager = Depends(get_user_manager),
    profile_form_class: type[PF] = Depends(get_profile_form_class),
    user_update_model: type[schemas.user.UserUpdate[schemas.user.UF]] = Depends(
        get_user_update_model
    ),
    context: BaseContext = Depends(get_base_context),
):
    form_helper = FormHelper(
        profile_form_class,
        "auth/dashboard/index.html",
        request=request,
        object=user,
        context={**context, "current_route": "auth.dashboard:profile"},
    )

    if await form_helper.is_submitted_and_valid():
        form = await form_helper.get_form()
        data = form.data
        user_update = user_update_model(**data)

        user = await user_manager.update(user_update, user, request=request)

        form_helper.context["success"] = _(
            "Your profile has successfully been updated."
        )

    return await form_helper.get_response()


@router.api_route(
    "/email/change", methods=["GET", "POST"], name="auth.dashboard:email_change"
)
async def email_change(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    user_manager: UserManager = Depends(get_user_manager),
    context: BaseContext = Depends(get_base_context),
    tenant: Tenant = Depends(get_current_tenant),
):
    form_helper = FormHelper(
        ChangeEmailForm,
        "auth/dashboard/email/change.html",
        request=request,
        object=user,
        context={**context},
    )

    if await form_helper.is_submitted_and_valid():
        form = await form_helper.get_form()

        current_password = form.current_password.data
        (
            current_password_valid,
            _hash_update,
        ) = user_manager.password_helper.verify_and_update(
            current_password, user.hashed_password
        )

        if not current_password_valid:
            message = _("Your password is invalid.")
            form.current_password.errors.append(message)
            return await form_helper.get_error_response(
                message, "invalid_current_password"
            )

        try:
            await user_manager.request_verify_email(
                user, form.email.data, request=request
            )
        except UserAlreadyExistsError:
            message = _("A user with this email address already exists.")
            form.email.errors.append(message)
            return await form_helper.get_error_response(message, "user_already_exists")

        return HXLocationResponse(
            tenant.url_for(request, "auth.dashboard:email_verify"),
            status_code=status.HTTP_202_ACCEPTED,
            hx_target="#email-change",
        )

    return await form_helper.get_response()


@router.api_route(
    "/email/verify", methods=["GET", "POST"], name="auth.dashboard:email_verify"
)
async def email_verify(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    user_manager: UserManager = Depends(get_user_manager),
    context: BaseContext = Depends(get_base_context),
    tenant: Tenant = Depends(get_current_tenant),
):
    form_helper = FormHelper(
        VerifyEmailForm,
        "auth/dashboard/email/verify.html",
        request=request,
        object=user,
        context={**context, "code_length": settings.email_verification_code_length},
    )

    if await form_helper.is_submitted_and_valid():
        form = await form_helper.get_form()
        try:
            user = await user_manager.verify_email(
                user, form.code.data, request=request
            )
        except InvalidEmailVerificationCodeError:
            return await form_helper.get_error_response(
                _(
                    "The verification code is invalid. Please check that you have entered it correctly. "
                    "If the code was copied and pasted, ensure it has not expired. "
                    "If it has been more than one hour, start over the email change process."
                ),
                "invalid_code",
            )

        return HXLocationResponse(
            tenant.url_for(request, "auth.dashboard:profile"),
        )

    return await form_helper.get_response()


@router.api_route("/password", methods=["GET", "POST"], name="auth.dashboard:password")
async def update_password(
    request: Request,
    hx_trigger: str | None = Header(None),
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    user_manager: UserManager = Depends(get_user_manager),
    context: BaseContext = Depends(get_base_context),
    session_token: SessionToken = Depends(get_session_token_or_login),
    device_sessions_service: DeviceSessionsService = Depends(
        get_device_sessions_service
    ),
):
    form_helper = FormHelper(
        ChangePasswordForm,
        "auth/dashboard/password.html",
        request=request,
        context={**context, "current_route": "auth.dashboard:password"},
    )

    if await form_helper.is_submitted_and_valid() and hx_trigger is None:
        form = await form_helper.get_form()

        old_password = form.old_password.data
        (
            old_password_valid,
            _hash_update,
        ) = user_manager.password_helper.verify_and_update(
            old_password, user.hashed_password
        )

        if not old_password_valid:
            message = _("Old password is invalid.")
            form.old_password.errors.append(message)
            return await form_helper.get_error_response(message, "invalid_old_password")

        new_password = form.new_password.data
        new_password_confirm = form.new_password_confirm.data

        if new_password != new_password_confirm:
            message = _("Passwords don't match.")
            form.new_password.errors.append(message)
            return await form_helper.get_error_response(message, "passwords_dont_match")

        try:
            user = await user_manager.set_user_attributes(
                user, password=new_password, tenant=context["tenant"]
            )
        except InvalidPasswordError as exc:
            # SEC-2 T8: HIBP rejection (or any other validate_password
            # failure not already filtered out by the wtforms-level
            # ``PasswordValidator``) raises through ``set_user_attributes``.
            # Without this branch the route 500s. The error code branches
            # on ``BreachedPasswordError`` so admin UX can show
            # HIBP-specific copy ("this password appeared in a known
            # breach — pick something else").
            message = "; ".join(str(m) for m in exc.messages)
            form.new_password.errors.append(message)
            error_code = (
                "password_breached"
                if isinstance(exc, BreachedPasswordError)
                else "invalid_password"
            )
            return await form_helper.get_error_response(message, error_code)
        await user_manager.user_repository.update(user)

        # UX-1 T12: auto-revoke every OTHER session/refresh token after a
        # successful password change. The current cookie's session is
        # preserved so the user stays signed in here. Audit logged with
        # ``trigger_reason="password_change"`` so support can correlate
        # "why did my other sessions get killed?" back to this action.
        await device_sessions_service.auto_revoke_others(
            user.id,
            current_session_id=session_token.id,
            reason="password_change",
        )

        form_helper.context["success"] = _(
            "Your password has been changed successfully."
        )

    return await form_helper.get_response()


# ---------------------------------------------------------------------------
# MFA / security routes (T13)
# ---------------------------------------------------------------------------
#
# These routes mount the second-factor enrollment / disable / regeneration
# UI under the existing dashboard router so they inherit the brand-aware
# ``BaseContext`` (user, tenant, brand, theme). Templates (T17/T19) own the
# rendering — the routes only wire data into the context.
#
# Notes:
# - The QR/secret bundle is regenerated on every retry (the upsert behaviour
#   in ``TotpService.begin_enrollment`` replaces an unconfirmed row), so a
#   bad confirmation code never strands the user with a stale secret.
# - The disable flow requires BOTH the current password AND a valid
#   authenticator code OR recovery code. Either one of the two factors
#   alone is insufficient.
# - Recovery codes are displayed exactly once after generation. The DB only
#   stores bcrypt hashes (see :mod:`fief.services.security.recovery_codes`).


def _mfa_label(brand: Brand | None, tenant: Tenant) -> str:
    """Issuer label embedded in the otpauth:// URI shown to the user.

    Brands take precedence over the tenant name so the entry in the user's
    authenticator app reads the way they expect ("LightNVR" rather than
    "Default tenant").
    """

    return brand.name if brand is not None else tenant.name


@router.get("/security/mfa", name="auth.dashboard:mfa_index")
async def mfa_index(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    context: BaseContext = Depends(get_base_context),
):
    return templates.TemplateResponse(
        request,
        "auth/dashboard/security/index.html",
        {
            **context,
            "current_route": "auth.dashboard:mfa_index",
            "mfa_enabled": user.mfa_enabled,
            # Render an empty disable form on initial GET so the password +
            # code fields are visible alongside the danger-zone button. The
            # POST handler re-renders with `form` populated on validation
            # failure, so the same template handles both paths.
            "form": TotpDisableForm(meta={"request": request})
            if user.mfa_enabled
            else None,
        },
    )


@router.post("/security/mfa/totp/begin", name="auth.dashboard:mfa_totp_begin")
async def mfa_totp_begin(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    tenant: Tenant = Depends(get_current_tenant),
    brand: Brand | None = Depends(get_current_brand),
    totp_service: TotpService = Depends(get_totp_service),
    context: BaseContext = Depends(get_base_context),
):
    label = _mfa_label(brand, tenant)
    try:
        enrollment = await totp_service.begin_enrollment(user, label)
    except MfaAlreadyEnrolledError:
        # Refuse to silently overwrite a working second factor; render the
        # landing with a clear error so the user goes through ``disable``
        # first.
        return templates.TemplateResponse(
            request,
            "auth/dashboard/security/index.html",
            {
                **context,
                "current_route": "auth.dashboard:mfa_index",
                "mfa_enabled": user.mfa_enabled,
                "error": _("MFA is already enabled. Disable it first."),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    form = TotpEnrollConfirmForm(meta={"request": request})
    return templates.TemplateResponse(
        request,
        "auth/dashboard/security/setup.html",
        {
            **context,
            "current_route": "auth.dashboard:mfa_index",
            "form": form,
            "secret_b32": enrollment.secret_b32,
            "qr_png_data_uri": enrollment.qr_png_data_uri,
            "otpauth_uri": enrollment.otpauth_uri,
        },
    )


@router.post("/security/mfa/totp/confirm", name="auth.dashboard:mfa_totp_confirm")
async def mfa_totp_confirm(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    tenant: Tenant = Depends(get_current_tenant),
    brand: Brand | None = Depends(get_current_brand),
    totp_service: TotpService = Depends(get_totp_service),
    recovery_code_service: RecoveryCodeService = Depends(
        get_recovery_code_service
    ),
    send_task: SendTask = Depends(get_send_task),
    context: BaseContext = Depends(get_base_context),
    session_token: SessionToken = Depends(get_session_token_or_login),
    device_sessions_service: DeviceSessionsService = Depends(
        get_device_sessions_service
    ),
):
    form_helper = FormHelper(
        TotpEnrollConfirmForm,
        "auth/dashboard/security/setup.html",
        request=request,
        context={**context, "current_route": "auth.dashboard:mfa_index"},
    )

    if not await form_helper.is_submitted_and_valid():
        # Form-level validation failure (missing/malformed code). Re-issue a
        # fresh QR so the template still has something to render — the
        # upsert in ``begin_enrollment`` keeps this idempotent.
        try:
            enrollment = await totp_service.begin_enrollment(
                user, _mfa_label(brand, tenant)
            )
        except MfaAlreadyEnrolledError:
            # Edge case: another tab already confirmed. Bounce to the
            # landing page rather than rendering a stale QR.
            return templates.TemplateResponse(
                request,
                "auth/dashboard/security/index.html",
                {
                    **context,
                    "current_route": "auth.dashboard:mfa_index",
                    "mfa_enabled": user.mfa_enabled,
                },
            )
        form_helper.context.update(
            {
                "secret_b32": enrollment.secret_b32,
                "qr_png_data_uri": enrollment.qr_png_data_uri,
                "otpauth_uri": enrollment.otpauth_uri,
            }
        )
        return await form_helper.get_response()

    form = await form_helper.get_form()
    confirmed = await totp_service.confirm_enrollment(
        user,
        form.code.data,
        send_task=send_task,
        brand_id=str(brand.id) if brand is not None else None,
    )

    if not confirmed:
        # Bad code: re-render the setup page with a fresh QR (the unconfirmed
        # row stays in place across this retry, but rebuilding the bundle
        # gives the template the same shape it expects).
        try:
            enrollment = await totp_service.begin_enrollment(
                user, _mfa_label(brand, tenant)
            )
        except MfaAlreadyEnrolledError:
            # Defensive: can't really happen here (confirm failed → row
            # is still unconfirmed) but keep the path total.
            return templates.TemplateResponse(
                request,
                "auth/dashboard/security/index.html",
                {
                    **context,
                    "current_route": "auth.dashboard:mfa_index",
                    "mfa_enabled": user.mfa_enabled,
                },
            )
        message = _("That code didn't match. Try again.")
        form.code.errors.append(message)
        form_helper.context.update(
            {
                "secret_b32": enrollment.secret_b32,
                "qr_png_data_uri": enrollment.qr_png_data_uri,
                "otpauth_uri": enrollment.otpauth_uri,
            }
        )
        return await form_helper.get_error_response(message, "invalid_totp_code")

    recovery_codes = await recovery_code_service.generate_for(user)

    # UX-1 T12: enrolling a second factor is a credential-elevation event;
    # purge every OTHER session/refresh token so an attacker who already
    # has a stale cookie can't ride past the new MFA gate. The current
    # session is preserved.
    await device_sessions_service.auto_revoke_others(
        user.id,
        current_session_id=session_token.id,
        reason="mfa_enrolled",
    )

    return templates.TemplateResponse(
        request,
        "auth/dashboard/security/recovery_codes.html",
        {
            **context,
            "current_route": "auth.dashboard:mfa_index",
            "codes": recovery_codes,
            "success": _("Two-factor authentication enabled."),
        },
    )


@router.post("/security/mfa/totp/disable", name="auth.dashboard:mfa_totp_disable")
async def mfa_totp_disable(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    user_manager: UserManager = Depends(get_user_manager),
    totp_service: TotpService = Depends(get_totp_service),
    recovery_code_service: RecoveryCodeService = Depends(
        get_recovery_code_service
    ),
    tenant: Tenant = Depends(get_current_tenant),
    brand: Brand | None = Depends(get_current_brand),
    send_task: SendTask = Depends(get_send_task),
    context: BaseContext = Depends(get_base_context),
    session_token: SessionToken = Depends(get_session_token_or_login),
    device_sessions_service: DeviceSessionsService = Depends(
        get_device_sessions_service
    ),
):
    form_helper = FormHelper(
        TotpDisableForm,
        "auth/dashboard/security/index.html",
        request=request,
        context={
            **context,
            "current_route": "auth.dashboard:mfa_index",
            "mfa_enabled": user.mfa_enabled,
        },
    )

    if not await form_helper.is_submitted_and_valid():
        return await form_helper.get_response()

    form = await form_helper.get_form()

    # Step 1: re-prompt password. Mirror the `email_change` pattern.
    (
        password_valid,
        _hash_update,
    ) = user_manager.password_helper.verify_and_update(
        form.current_password.data, user.hashed_password
    )

    if not password_valid:
        message = _("Your password is invalid.")
        form.current_password.errors.append(message)
        return await form_helper.get_error_response(
            message, "invalid_current_password"
        )

    # Step 2: require a valid TOTP **or** recovery code. Try TOTP first
    # (cheaper), fall back to recovery if it's not a 6-digit shape or it
    # didn't verify. We never leak which side matched.
    code = form.code.data
    second_factor_ok = False
    if code.isdigit() and len(code) == 6:
        verify_result = await totp_service.verify(user, code)
        if verify_result == VerifyResult.SUCCESS:
            second_factor_ok = True
    if not second_factor_ok:
        if await recovery_code_service.consume(user, code):
            second_factor_ok = True

    if not second_factor_ok:
        message = _("Invalid authenticator or recovery code.")
        form.code.errors.append(message)
        return await form_helper.get_error_response(
            message, "invalid_mfa_code"
        )

    await totp_service.disable(
        user,
        send_task=send_task,
        brand_id=str(brand.id) if brand is not None else None,
    )

    # UX-1 T12: disabling a second factor is itself a credential-state change
    # — every other live cookie/refresh-token must be invalidated so an
    # attacker who already has one can't continue to ride it. The current
    # session is preserved so the user stays signed in to the dashboard
    # for the post-disable confirmation render.
    await device_sessions_service.auto_revoke_others(
        user.id,
        current_session_id=session_token.id,
        reason="mfa_disabled",
    )

    # Re-fetch context flag so the success render reflects the new state.
    form_helper.context["mfa_enabled"] = False
    form_helper.context["success"] = _("Two-factor authentication disabled.")

    # Tell HTMX to fully reload the security page so the disabled banner
    # replaces the form.
    return HXLocationResponse(
        tenant.url_for(request, "auth.dashboard:mfa_index"),
        status_code=status.HTTP_200_OK,
    )


@router.post(
    "/security/mfa/recovery-codes/regenerate",
    name="auth.dashboard:mfa_recovery_regen",
)
async def mfa_recovery_regen(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    recovery_code_service: RecoveryCodeService = Depends(
        get_recovery_code_service
    ),
    context: BaseContext = Depends(get_base_context),
):
    if not user.mfa_enabled:
        # Don't regenerate codes for users who haven't enrolled — pretend
        # the route doesn't exist rather than returning a 4xx, so we don't
        # leak enrollment state.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    recovery_codes = await recovery_code_service.generate_for(user)
    return templates.TemplateResponse(
        request,
        "auth/dashboard/security/recovery_codes.html",
        {
            **context,
            "current_route": "auth.dashboard:mfa_index",
            "codes": recovery_codes,
            "success": _("New recovery codes generated. Save them now."),
        },
    )


# ---------------------------------------------------------------------------
# UX-1 T11: /security/sessions — devices tab routes
# ---------------------------------------------------------------------------
#
# These three routes power the "Active sessions" / devices tab in the user
# dashboard. They mount under the same router as the Profile / Password /
# MFA routes so they inherit the brand-aware ``BaseContext`` (user, tenant,
# brand, theme, MFA-enforcement gate).
#
# Authorization model
# ~~~~~~~~~~~~~~~~~~~
# Every device row is filtered through
# :meth:`DeviceSessionsService.list_for_user(user.id, ...)`. The opaque
# ``device_key`` URL segment is just a stable hash of token ids inside
# that user-scoped result set; a key from another user's listing simply
# won't appear in the requester's set, so the matching step returns
# ``None`` and we translate to 404. There is no separate cross-user
# authorization check needed at the route layer.


@router.get(
    "/security/sessions", name="auth.dashboard:sessions_index"
)
async def sessions_index(
    request: Request,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    session_token: SessionToken = Depends(get_session_token_or_login),
    device_sessions_service: DeviceSessionsService = Depends(
        get_device_sessions_service
    ),
    context: BaseContext = Depends(get_base_context),
):
    """Render the "Active sessions" tab.

    The actual template (``auth/dashboard/security/sessions.html``) ships
    in T13. This route only assembles the context: the deduped device
    list (with ``is_current`` annotated for the requester's session
    cookie) plus the standard ``current_route`` marker the sidebar uses
    to highlight the active tab.
    """

    devices = await device_sessions_service.list_for_user(
        user.id, current_session_id=session_token.id
    )
    return templates.TemplateResponse(
        request,
        "auth/dashboard/security/sessions.html",
        {
            **context,
            "current_route": "auth.dashboard:sessions_index",
            "devices": devices,
        },
    )


@router.delete(
    "/security/sessions/{device_key}",
    name="auth.dashboard:sessions_revoke",
)
async def sessions_revoke(
    request: Request,
    device_key: str,
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    session_token: SessionToken = Depends(get_session_token_or_login),
    device_sessions_service: DeviceSessionsService = Depends(
        get_device_sessions_service
    ),
    tenant: Tenant = Depends(get_current_tenant),
):
    """Revoke a single device row.

    Three response shapes:

    - **404** when ``device_key`` doesn't match any row in the
      requester's listing — the concurrent-double-click guard. HTMX
      swallows it as a no-op so the button can re-enable cleanly.
    - **303** to ``/login`` when the revoked row is the requester's
      *current* session. We deliberately do NOT call ``delete_cookie``
      here: the session-token row backing the cookie is gone, so the
      next request's cookie validation fails naturally and the user
      lands on /login. Returning 303 also lets HTMX honor the redirect
      via ``HX-Redirect`` semantics (303 + Location is a hard navigation
      regardless of the request kind).
    - **204** when a non-current device was revoked. HTMX removes the
      row from the table on success.
    """

    revoked = await device_sessions_service.revoke(user.id, device_key)
    if revoked is None:
        # Stale device_key (concurrent double-click, foreign user, etc.).
        return Response(status_code=status.HTTP_404_NOT_FOUND)

    if session_token.id in revoked.session_token_ids:
        # The user just revoked their own current session. The cookie's
        # underlying row is gone — return a 303 to /login. No explicit
        # delete_cookie() needed; the next request's stale cookie fails
        # to validate and the user is redirected naturally.
        return RedirectResponse(
            tenant.url_path_for(request, "auth:login"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/security/sessions/sign-out-others",
    name="auth.dashboard:sessions_sign_out_others",
)
async def sessions_sign_out_others(
    user: User = Depends(get_verified_email_user_from_session_token_or_verify),
    session_token: SessionToken = Depends(get_session_token_or_login),
    device_sessions_service: DeviceSessionsService = Depends(
        get_device_sessions_service
    ),
):
    """Sign out of every device except the current session.

    Returns a small JSON payload with the revoked counts so HTMX can
    render the success flash. Other devices return 401 / redirect to
    /login on their next request because their session and refresh
    tokens have been deleted.
    """

    s_count, r_count = await device_sessions_service.sign_out_others(
        user.id, current_session_id=session_token.id
    )
    return JSONResponse(
        {
            "success": True,
            "revoked_session_count": s_count,
            "revoked_refresh_count": r_count,
        }
    )
