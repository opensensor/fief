from pydantic import UUID4, HttpUrl

from fief.schemas.generics import BaseModel


class BrandEmailContext(BaseModel):
    """Brand fields exposed to email templates so transactional emails can
    address the user under the brand they signed up under (LightNVR,
    OwlBooks, etc.) instead of the underlying tenant name."""

    id: UUID4
    name: str
    host: str
    application_url: HttpUrl
    logo_url: HttpUrl | None = None
