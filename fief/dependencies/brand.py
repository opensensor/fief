from urllib.parse import urlparse

from fastapi import Depends, Request

from fief.models import Brand, LoginSession
from fief.repositories import BrandRepository


async def get_current_brand(
    request: Request,
    repository: BrandRepository = Depends(BrandRepository),
) -> Brand | None:
    """Host-based brand resolver.

    Reads ``request.url.hostname`` and returns the matching :class:`Brand`,
    or the row flagged ``is_default=True`` as fallback. This is the
    resolver consumed everywhere the in-flight authentication flow is
    NOT relevant (e.g. dashboard pages, post-login screens served on
    ``account.<brand-host>.example``).

    For ``/login`` / ``/consent`` / ``/mfa/*`` / ``/verify`` and other
    in-flight pages, prefer
    :func:`get_current_brand_for_login_session`, which honours the
    verified ``branding_origin`` persisted on the active
    :class:`LoginSession` (T46) before falling through to host-based
    lookup.
    """

    host = request.url.hostname
    if host:
        brand = await repository.get_by_host(host)
        if brand is not None:
            return brand

    return await repository.get_default()


async def get_current_brand_for_login_session(
    request: Request,
    login_session: LoginSession | None,
    repository: BrandRepository,
) -> Brand | None:
    """Login-session-aware brand resolver (T46).

    When the active :class:`LoginSession` carries a verified
    ``branding_origin`` (set by the signed-token check on
    ``GET /authorize``), look up the brand whose ``host`` matches the
    origin's host. If found, return it -- this is the storefront-correct
    brand for a Saleor-driven login.

    Otherwise (no login session, no signed origin, or no brand row for
    the origin host), fall through to the host-based resolver so native
    Fief multi-brand whitelabel keeps working.

    Not a FastAPI dependency itself; helpers compose it inside their
    own dependencies (see :func:`fief.dependencies.auth.get_base_context`)
    because the login-session dep injection happens at a different
    layer than this generic resolver.
    """

    if login_session is not None and login_session.branding_origin:
        host: str | None = None
        try:
            host = urlparse(login_session.branding_origin).hostname
        except ValueError:
            host = None
        if host:
            brand = await repository.get_by_host(host)
            if brand is not None:
                return brand

    # Fall through to host-based / default lookup.
    return await get_current_brand(request, repository)
