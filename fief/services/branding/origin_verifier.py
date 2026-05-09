"""Signed ``branding_origin`` verifier for the OAuth ``/authorize`` flow.

Background
----------
For Saleor-driven logins, the storefront sends users to Fief's ``/authorize``
endpoint on Fief's host (e.g. ``auth.opensensor.io``). Without intervention,
brand selection on that request -- which is keyed off ``request.url.hostname``
-- would always resolve to whichever Brand row matches Fief's own host (or
the default brand), never the storefront the user actually came from.

To fix this without regressing native Fief multi-brand whitelabel, the
Saleor app (`saleor-apps/apps/fief` T15) signs a short-lived
``branding_origin`` token and appends it to the authorize URL. The token's
shape is::

    "<origin>.<nonce>.<expiry>.<sig>"

where:

* ``<origin>`` -- the storefront origin string (e.g. ``https://shop-a.example.com``);
* ``<nonce>``  -- random opaque string from the signer (replay-cache outside scope);
* ``<expiry>`` -- unix-seconds integer at which the token MUST be rejected;
* ``<sig>``    -- HMAC-SHA256(client.branding_signing_key, "<origin>.<nonce>.<expiry>")
                 hex-digest, compared with :func:`hmac.compare_digest`.

The verifier returns a :class:`VerificationResult` that always has both a
``status`` and (on success only) the trusted ``origin`` string. Failure
modes never raise -- the calling dependency in
:mod:`fief.dependencies.auth` falls back silently to the default brand and
WARN-logs the failure with a hashed origin so the abuse signal is
preserved without leaking the storefront identity.

Allowlist
---------
Even if the HMAC verifies, the verifier requires the host portion of the
``origin`` to match a host appearing in the OIDC client's existing
``redirect_uris``. This re-uses the data Fief already trusts to gate
redirect targets and keeps the operator surface small (audit
recommendation §4.4 / open question #1, default chosen).
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from fief.models import Client


# Maximum age accepted for a signed branding_origin token, in seconds.
# Hard-coded here (rather than in settings) to match the value committed
# to by the T15 signer on the Saleor side -- the two sides MUST agree.
# The expiry only gates the initial ``/authorize`` boundary; once verified,
# the origin is persisted on the LoginSession so multi-step flows (MFA,
# email verification, consent) keep the same brand even past 5 minutes.
TOKEN_MAX_AGE_SECONDS = 5 * 60


class VerificationResult(StrEnum):
    """Outcome of a branding_origin verification attempt.

    Values double as the structured ``failure_reason`` field on the WARN
    log emitted by the calling dependency, so they read as
    ops-friendly tokens rather than free text. Adding a new failure mode
    here means updating the structured-log consumer too.
    """

    OK = "ok"
    NO_TOKEN = "no_token"
    NO_SIGNING_KEY = "no_signing_key"
    MALFORMED = "malformed"
    SIGNATURE_MISMATCH = "signature_mismatch"
    EXPIRED = "expired"
    ORIGIN_NOT_ALLOWED = "origin_not_allowed"


@dataclass(frozen=True)
class VerifiedBrandingOrigin:
    """Result wrapper.

    On a successful verification, ``status == VerificationResult.OK`` and
    ``origin`` is the trusted storefront origin string the brand resolver
    should use. On any failure path, ``status`` carries the structured
    reason and ``origin`` is ``None``.
    """

    status: VerificationResult
    origin: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is VerificationResult.OK


def hash_origin_for_log(origin: str) -> str:
    """SHA-256 hash of an origin, truncated to 16 hex chars.

    Used in WARN logs (open-question #3, default chosen): we need to
    correlate repeated verification failures from the same storefront to
    catch abuse, but logging the raw origin would leak operator
    identities into ops logs. 16 chars is plenty to disambiguate
    realistic deployment sizes.
    """

    return hashlib.sha256(origin.encode("utf-8")).hexdigest()[:16]


class BrandingOriginVerifier:
    """Stateless verifier bound to a single OIDC :class:`Client`.

    Construction is cheap: it captures the per-client signing key and
    pre-computes the set of allowed redirect-URI hosts. Re-create per
    request (or keep one per client if a cache becomes warranted later).
    """

    def __init__(self, client: Client) -> None:
        self._signing_key: str | None = client.branding_signing_key
        self._allowed_hosts: set[str] = self._extract_hosts(client.redirect_uris)

    @staticmethod
    def _extract_hosts(redirect_uris: list[str]) -> set[str]:
        hosts: set[str] = set()
        for uri in redirect_uris or ():
            try:
                parsed = urlparse(uri)
            except ValueError:
                continue
            host = parsed.hostname
            if host:
                hosts.add(host)
        return hosts

    def verify(
        self, token: str | None, *, now: float | None = None
    ) -> VerifiedBrandingOrigin:
        """Verify ``token`` and return a structured outcome.

        The ``now`` argument is exposed only for test injection. In
        production, leave it as ``None`` to read wall-clock from
        :func:`time.time`.

        This method NEVER raises. All failure modes return a result with
        ``status != OK``; the caller is expected to silently fall back to
        the default brand and WARN-log the structured ``status`` (plus a
        hashed origin via :func:`hash_origin_for_log` when one is
        recoverable from the token).
        """

        if self._signing_key is None:
            return VerifiedBrandingOrigin(VerificationResult.NO_SIGNING_KEY)

        if token is None or token == "":
            return VerifiedBrandingOrigin(VerificationResult.NO_TOKEN)

        # Split from the right so an origin that contains '.' (every URL
        # does) doesn't get truncated. The token shape has exactly 4
        # dot-separated segments; ``rsplit(".", 3)`` gives us back
        # ``[origin, nonce, expiry, sig]`` with the origin intact.
        parts = token.rsplit(".", 3)
        if len(parts) != 4:
            return VerifiedBrandingOrigin(VerificationResult.MALFORMED)

        origin, nonce, expiry_str, signature = parts
        if not origin or not nonce or not expiry_str or not signature:
            return VerifiedBrandingOrigin(VerificationResult.MALFORMED)

        # Expiry must be an integer; anything else is malformed (the T15
        # signer always emits a base-10 integer).
        try:
            expiry = int(expiry_str)
        except ValueError:
            return VerifiedBrandingOrigin(VerificationResult.MALFORMED)

        # HMAC verification first. Doing this BEFORE the expiry check
        # means a tampered token (which will fail the HMAC) doesn't leak
        # whether its expiry was in the past or future via timing.
        message = f"{origin}.{nonce}.{expiry}".encode()
        expected_sig = hmac.new(
            self._signing_key.encode("utf-8"),
            msg=message,
            digestmod=hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, signature):
            return VerifiedBrandingOrigin(VerificationResult.SIGNATURE_MISMATCH)

        # Expiry check second.
        wall_clock = time.time() if now is None else now
        if expiry < wall_clock:
            return VerifiedBrandingOrigin(VerificationResult.EXPIRED)

        # Maximum-age sanity check: a token whose expiry is far in the
        # future (well past the 5-minute window the signer should
        # produce) suggests either a clock-skew bug or a forged token
        # whose signature happened to validate (the latter is impossible
        # without the key, but we belt-and-brace anyway). Reject it.
        if expiry - wall_clock > TOKEN_MAX_AGE_SECONDS:
            return VerifiedBrandingOrigin(VerificationResult.EXPIRED)

        # Allowlist enforcement. The HMAC tells us the token was minted
        # by the holder of this client's signing key, but not whether
        # the operator approved the named origin -- defence-in-depth on
        # top of the Saleor-side allowlist (R5).
        try:
            origin_host = urlparse(origin).hostname
        except ValueError:
            origin_host = None
        if origin_host is None or origin_host not in self._allowed_hosts:
            return VerifiedBrandingOrigin(VerificationResult.ORIGIN_NOT_ALLOWED)

        return VerifiedBrandingOrigin(VerificationResult.OK, origin=origin)
