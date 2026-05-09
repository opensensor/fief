"""Unit tests for :class:`BrandingOriginVerifier` (T46).

Covers the eight cases enumerated in the audit doc § 4.7:

1. Happy path -- valid signed token, allowed origin, fresh expiry -> ``OK``.
2. Missing/empty token -> ``NO_TOKEN``.
3. Tampered origin segment -> ``SIGNATURE_MISMATCH``.
4. Tampered signature segment -> ``SIGNATURE_MISMATCH``.
5. Expired token (6 minutes in the past) -> ``EXPIRED``.
6. Origin host not in client's redirect-URI allowlist -> ``ORIGIN_NOT_ALLOWED``.
7. Client with ``branding_signing_key=None`` -> ``NO_SIGNING_KEY``.
8. Cross-client replay (token signed by Client A presented to Client B) ->
   ``SIGNATURE_MISMATCH`` (since Client B's key fails the HMAC check).

Plus a couple of malformed-token shape tests because they're free.

The verifier is a stateless function over a :class:`Client`; we use a
lightweight stand-in (``_FakeClient``) rather than instantiating real
SQLAlchemy models -- the verifier only reads two attributes
(``branding_signing_key``, ``redirect_uris``) and we want to keep
the test independent of the migration / DB layer.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field

import pytest

from fief.services.branding.origin_verifier import (
    TOKEN_MAX_AGE_SECONDS,
    BrandingOriginVerifier,
    VerificationResult,
    hash_origin_for_log,
)

# ---------------------------------------------------------------------------
# Fakes / helpers
# ---------------------------------------------------------------------------


@dataclass
class _FakeClient:
    """Minimal stand-in for :class:`fief.models.Client`.

    Only the two attributes the verifier reads are surfaced; using a real
    SQLAlchemy model here would force us to drag in the full DB fixture
    chain for what is a pure-function test.
    """

    branding_signing_key: str | None = None
    redirect_uris: list[str] = field(default_factory=list)


def _sign(secret: str, origin: str, nonce: str, expiry: int) -> str:
    """Replicate the T15 signer's token shape: ``origin.nonce.expiry.sig``."""

    message = f"{origin}.{nonce}.{expiry}".encode()
    sig = hmac.new(
        secret.encode("utf-8"),
        msg=message,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"{origin}.{nonce}.{expiry}.{sig}"


# ---------------------------------------------------------------------------
# Cases enumerated in the audit § 4.7
# ---------------------------------------------------------------------------


class TestBrandingOriginVerifier:
    SIGNING_KEY = "a" * 64  # 32-byte hex (matches T15 generator shape)
    OTHER_KEY = "b" * 64
    ORIGIN = "https://shop-a.example.com"
    NONCE = "rand-nonce-1234"

    @pytest.fixture
    def client(self) -> _FakeClient:
        return _FakeClient(
            branding_signing_key=self.SIGNING_KEY,
            redirect_uris=[
                "https://shop-a.example.com/callback",
                "https://shop-a.example.com/api/auth/callback/fief",
            ],
        )

    def _now(self) -> float:
        return time.time()

    # ---- happy path -------------------------------------------------------

    def test_happy_path_returns_ok_with_origin(self, client: _FakeClient) -> None:
        """Audit case: valid signed token, origin in allowlist, fresh expiry."""
        expiry = int(self._now()) + 60
        token = _sign(self.SIGNING_KEY, self.ORIGIN, self.NONCE, expiry)

        result = BrandingOriginVerifier(client).verify(token, now=self._now())

        assert result.status is VerificationResult.OK
        assert result.origin == self.ORIGIN
        assert result.ok is True

    # ---- missing token (no_token) -----------------------------------------

    def test_missing_token_returns_no_token(self, client: _FakeClient) -> None:
        """Audit case: no ``branding_origin`` query param at all."""
        result_none = BrandingOriginVerifier(client).verify(None)
        result_empty = BrandingOriginVerifier(client).verify("")

        assert result_none.status is VerificationResult.NO_TOKEN
        assert result_none.origin is None
        assert result_empty.status is VerificationResult.NO_TOKEN

    # ---- tampered origin segment ------------------------------------------

    def test_tampered_origin_returns_signature_mismatch(
        self, client: _FakeClient
    ) -> None:
        """Audit case: HMAC fails when the origin segment is rewritten."""
        expiry = int(self._now()) + 60
        token = _sign(self.SIGNING_KEY, self.ORIGIN, self.NONCE, expiry)
        # Replace the origin while keeping the original signature.
        original_sig = token.rsplit(".", 1)[1]
        tampered = f"https://attacker.example.com.{self.NONCE}.{expiry}.{original_sig}"

        result = BrandingOriginVerifier(client).verify(tampered, now=self._now())

        assert result.status is VerificationResult.SIGNATURE_MISMATCH
        assert result.origin is None

    # ---- tampered signature segment ---------------------------------------

    def test_tampered_signature_returns_signature_mismatch(
        self, client: _FakeClient
    ) -> None:
        """Audit case: HMAC fails when only the signature is mutated."""
        expiry = int(self._now()) + 60
        token = _sign(self.SIGNING_KEY, self.ORIGIN, self.NONCE, expiry)
        head, _sig = token.rsplit(".", 1)
        tampered = f"{head}.{'0' * 64}"

        result = BrandingOriginVerifier(client).verify(tampered, now=self._now())

        assert result.status is VerificationResult.SIGNATURE_MISMATCH

    # ---- expired token ----------------------------------------------------

    def test_expired_token_returns_expired(self, client: _FakeClient) -> None:
        """Audit case: ``expiry`` 6 minutes in the past -> EXPIRED."""
        now = self._now()
        expiry = int(now) - 6 * 60
        token = _sign(self.SIGNING_KEY, self.ORIGIN, self.NONCE, expiry)

        result = BrandingOriginVerifier(client).verify(token, now=now)

        assert result.status is VerificationResult.EXPIRED
        assert result.origin is None

    def test_far_future_expiry_treated_as_expired(self, client: _FakeClient) -> None:
        """Belt-and-brace: an expiry past the 5-minute max-age window also
        rejects, even if the HMAC validates. Defends against a buggy /
        forged signer that mints abnormally long-lived tokens."""
        now = self._now()
        # 1 hour in the future >> TOKEN_MAX_AGE_SECONDS (300s) -> reject.
        expiry = int(now) + TOKEN_MAX_AGE_SECONDS + 60
        token = _sign(self.SIGNING_KEY, self.ORIGIN, self.NONCE, expiry)

        result = BrandingOriginVerifier(client).verify(token, now=now)

        assert result.status is VerificationResult.EXPIRED

    # ---- unknown origin (not in allowlist) --------------------------------

    def test_unknown_origin_rejected(self, client: _FakeClient) -> None:
        """Audit case: HMAC valid but origin host not in client's
        ``redirect_uris`` -> ORIGIN_NOT_ALLOWED."""
        expiry = int(self._now()) + 60
        unknown_origin = "https://shop-b.example.com"
        token = _sign(self.SIGNING_KEY, unknown_origin, self.NONCE, expiry)

        result = BrandingOriginVerifier(client).verify(token, now=self._now())

        assert result.status is VerificationResult.ORIGIN_NOT_ALLOWED
        assert result.origin is None

    # ---- null signing key (backward-compat) -------------------------------

    def test_null_signing_key_returns_no_signing_key(self) -> None:
        """Audit case: client without ``branding_signing_key`` set -> any
        token is silently ignored. Guarantees first-party / dashboard /
        SDK clients that never opt into signed branding keep working."""
        client_no_key = _FakeClient(
            branding_signing_key=None,
            redirect_uris=["https://shop-a.example.com/callback"],
        )
        # Even a perfectly-valid-looking token should be ignored when the
        # client has no key on file -- the verifier short-circuits before
        # ever trying to do HMAC math.
        token = _sign("any-key", self.ORIGIN, self.NONCE, int(self._now()) + 60)

        result = BrandingOriginVerifier(client_no_key).verify(token)

        assert result.status is VerificationResult.NO_SIGNING_KEY
        assert result.origin is None

    # ---- cross-client replay ----------------------------------------------

    def test_cross_client_replay_rejected(self, client: _FakeClient) -> None:
        """Audit case: a token signed by Client A presented to Client B
        fails because Client B's key produces a different HMAC. This is
        the same HMAC logic as ``test_tampered_signature_returns_*`` but
        modeled explicitly because cross-client replay is the threat
        case ops cares about (R5 -- branding-param phishing)."""
        expiry = int(self._now()) + 60
        token_signed_by_other_client = _sign(
            self.OTHER_KEY, self.ORIGIN, self.NONCE, expiry
        )
        # ``client`` holds SIGNING_KEY, NOT OTHER_KEY -> HMAC mismatches.

        result = BrandingOriginVerifier(client).verify(
            token_signed_by_other_client, now=self._now()
        )

        assert result.status is VerificationResult.SIGNATURE_MISMATCH

    # ---- malformed token shapes (cheap extras) ----------------------------

    @pytest.mark.parametrize(
        "token",
        [
            pytest.param("just-a-string", id="no separators"),
            pytest.param("origin.nonce", id="too few segments"),
            pytest.param("..0.sig", id="empty origin segment"),
            pytest.param("origin..0.sig", id="empty nonce segment"),
            pytest.param("origin.nonce..sig", id="empty expiry segment"),
            pytest.param("origin.nonce.0.", id="empty signature segment"),
            pytest.param("origin.nonce.NOT_A_NUMBER.sig", id="non-integer expiry"),
        ],
    )
    def test_malformed_token_returns_malformed(
        self, client: _FakeClient, token: str
    ) -> None:
        result = BrandingOriginVerifier(client).verify(token)

        assert result.status is VerificationResult.MALFORMED

    # ---- log redaction helper ---------------------------------------------

    def test_hash_origin_for_log_is_stable_and_truncated(self) -> None:
        """The log helper SHA-256s the origin and truncates -- spot-check
        determinism (same input -> same hash) and the 16-char width."""
        h1 = hash_origin_for_log(self.ORIGIN)
        h2 = hash_origin_for_log(self.ORIGIN)
        h3 = hash_origin_for_log("https://other.example.com")

        assert h1 == h2
        assert h1 != h3
        assert len(h1) == 16
