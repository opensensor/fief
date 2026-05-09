from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request, Response

from fief.crypto.access_token import generate_access_token
from fief.crypto.id_token import generate_id_token
from fief.crypto.token import generate_token, get_token_hash
from fief.dependencies.client_ip import get_client_ip_info
from fief.dependencies.logger import get_audit_logger
from fief.dependencies.permission import (
    UserPermissionsGetter,
    get_user_permissions_getter,
)
from fief.dependencies.repositories import get_repository
from fief.dependencies.tenant import get_current_tenant
from fief.dependencies.token import (
    GrantRequest,
    get_user_from_grant_request,
    validate_grant_request,
)
from fief.logger import AuditLogger
from fief.models import AuditLogMessage, RefreshToken, Tenant, User
from fief.repositories import RefreshTokenRepository
from fief.schemas.auth import TokenResponse

router = APIRouter()


@router.post("/token", name="auth:token")
async def token(
    request: Request,
    response: Response,
    # UX-1 T9: when the grant is ``refresh_token`` we re-resolve the
    # presented refresh token by hash so we can call ``touch_last_seen``
    # on the *existing* row before the validation dependency's post-yield
    # cleanup deletes it. The form field name matches the OAuth2 spec
    # (RFC 6749 §6); the alias keeps the Python identifier non-shadowing
    # against the local ``token, token_hash = generate_token()`` below.
    refresh_token_form: str | None = Form(None, alias="refresh_token"),
    grant_request: GrantRequest = Depends(validate_grant_request),
    user: User = Depends(get_user_from_grant_request),
    get_user_permissions: UserPermissionsGetter = Depends(get_user_permissions_getter),
    refresh_token_repository: RefreshTokenRepository = Depends(
        get_repository(RefreshTokenRepository)
    ),
    tenant: Tenant = Depends(get_current_tenant),
    audit_logger: AuditLogger = Depends(get_audit_logger),
):
    scope = grant_request["scope"]
    authenticated_at = grant_request["authenticated_at"]
    acr = grant_request["acr"]
    nonce = grant_request["nonce"]
    c_hash = grant_request["c_hash"]
    client = grant_request["client"]
    permissions = await get_user_permissions(user)

    # UX-1 T9 — last-seen hook: if this is a refresh-token grant, advance
    # ``last_seen_at`` / ``last_seen_ip`` on the existing refresh-token
    # row before the dependency's post-yield cleanup deletes it. We do
    # NOT touch ``created_user_agent`` / ``created_ip`` — those columns
    # capture first-seen device identity and intentionally stay frozen
    # across refreshes (a long-lived OAuth client may report jittered UA
    # strings on every request and we want a stable device label).
    if grant_request["grant_type"] == "refresh_token" and refresh_token_form is not None:
        existing_refresh_token = await refresh_token_repository.get_by_token(
            get_token_hash(refresh_token_form)
        )
        if existing_refresh_token is not None:
            await refresh_token_repository.touch_last_seen(
                existing_refresh_token.id,
                last_seen_at=datetime.now(UTC),
                last_seen_ip=get_client_ip_info(request).raw,
            )

    tenant_host = tenant.get_host()
    access_token = generate_access_token(
        tenant.get_sign_jwk(),
        tenant_host,
        client,
        authenticated_at,
        acr,
        user,
        scope,
        permissions,
        client.access_id_token_lifetime_seconds,
    )
    id_token = generate_id_token(
        tenant.get_sign_jwk(),
        tenant_host,
        client,
        authenticated_at,
        acr,
        user,
        client.access_id_token_lifetime_seconds,
        nonce=nonce,
        c_hash=c_hash,
        access_token=access_token,
        encryption_key=client.get_encrypt_jwk(),
    )
    token_response = TokenResponse(
        access_token=access_token,
        id_token=id_token,
        expires_in=client.access_id_token_lifetime_seconds,
    )

    if "offline_access" in scope:
        token, token_hash = generate_token()
        # UX-1 T9 — creation hook: hydrate device-annotation columns at
        # mint time so the new row is immediately visible on the
        # /security/sessions device list (T11) without needing a follow-up
        # refresh request to populate ``last_seen_*``.
        ip_info = get_client_ip_info(request)
        now = datetime.now(UTC)
        refresh_token = RefreshToken(
            token=token_hash,
            scope=scope,
            user_id=user.id,
            client_id=client.id,
            authenticated_at=authenticated_at,
            expires_at=client.get_refresh_token_expires_at(),
            created_ip=ip_info.raw,
            created_user_agent=request.headers.get("user-agent"),
            last_seen_at=now,
            last_seen_ip=ip_info.raw,
        )
        refresh_token = await refresh_token_repository.create(refresh_token)
        token_response.refresh_token = token

    audit_logger(
        AuditLogMessage.USER_TOKEN_GENERATED,
        subject_user_id=user.id,
        grant_type=grant_request["grant_type"],
        authenticated_at=authenticated_at.isoformat(),
        scope=scope,
    )

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return token_response.model_dump(exclude_none=True)
