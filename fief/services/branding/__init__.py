"""Branding-related services.

Houses the signed ``branding_origin`` verifier (T46) used to switch the
brand on ``GET /authorize`` based on the storefront the user actually came
from (rather than the host Fief itself was reached on).
"""

from fief.services.branding.origin_verifier import (
    BrandingOriginVerifier,
    VerificationResult,
    VerifiedBrandingOrigin,
)

__all__ = [
    "BrandingOriginVerifier",
    "VerificationResult",
    "VerifiedBrandingOrigin",
]
