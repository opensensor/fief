from datetime import UTC, datetime

from fastapi import Cookie, Depends, HTTPException, Request, status

from fief.crypto.token import get_token_hash
from fief.dependencies.client_ip import ClientIpInfo, get_client_ip_info
from fief.dependencies.repositories import get_repository
from fief.dependencies.tenant import get_current_tenant
from fief.models import SessionToken, Tenant, User
from fief.repositories import SessionTokenRepository
from fief.settings import settings


async def get_session_token(
    request: Request,
    token: str | None = Cookie(None, alias=settings.session_cookie_name),
    repository: SessionTokenRepository = Depends(
        get_repository(SessionTokenRepository)
    ),
    ip_info: ClientIpInfo = Depends(get_client_ip_info),
) -> SessionToken | None:
    if token is not None:
        token_hash = get_token_hash(token)
        session_token = await repository.get_by_token(token_hash)
        if session_token is not None:
            # UX-1 T8: stamp ``last_seen_at`` / ``last_seen_ip`` on every
            # protected dashboard request. One tiny UPDATE; we deliberately
            # do not refresh ``created_user_agent`` — that field is the
            # device's identity, not the request envelope.
            await repository.touch_last_seen(
                session_token.id,
                last_seen_at=datetime.now(UTC),
                last_seen_ip=ip_info.raw,
            )
        return session_token
    return None


async def get_session_token_or_login(
    request: Request,
    session_token: SessionToken | None = Depends(get_session_token),
    tenant: Tenant = Depends(get_current_tenant),
) -> SessionToken:
    if session_token is None or session_token.user.tenant_id != tenant.id:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": str(tenant.url_for(request, "auth:login"))},
        )
    return session_token


async def get_user_from_session_token_or_login(
    session_token: SessionToken = Depends(get_session_token_or_login),
) -> User:
    return session_token.user


async def get_verified_email_user_from_session_token_or_verify(
    request: Request,
    user: User = Depends(get_user_from_session_token_or_login),
    tenant: Tenant = Depends(get_current_tenant),
) -> User:
    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={
                "Location": str(tenant.url_for(request, "auth:verify_email_request"))
            },
        )
    return user
