"""Fernet-based encryption helper for MFA secrets at rest.

This module is the single chokepoint for encrypting and decrypting TOTP
secrets stored in the database. It is intentionally narrow:

- ``encrypt(secret)``  → bytes ciphertext (urlsafe Fernet token).
- ``decrypt(blob)``    → plaintext str.
- Failures during decryption are surfaced as :class:`MfaSecretDecryptionError`
  so callers can return a generic 500 / inconsistent-state response without
  leaking ``cryptography`` internals.

Keys are read lazily from ``fief.settings.settings`` at call time. Two
attributes are honoured (in order of preference):

1. ``mfa_secret_encryption_keys``: ``list[str]`` — current key first,
   followed by retired keys still needed for decryption. Backed by
   :class:`cryptography.fernet.MultiFernet` so rotation works without a
   migration sweep.
2. ``mfa_secret_encryption_key``: ``str`` — single-key shortcut for the
   common case.

If neither attribute is set, every call raises :class:`RuntimeError`. The
authoritative startup-time validation lives in T4; this is a
defense-in-depth runtime guard so sub-systems instantiated lazily still
fail loudly rather than silently producing unverifiable ciphertext.

The ``settings`` attribute may be absent at this stage (T4 lands the real
fields on the settings class); ``getattr`` lookups make that scenario
explicit and let T2 ship independently of T4.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from fief.settings import settings

__all__ = ["MfaSecretDecryptionError", "decrypt", "encrypt"]


class MfaSecretDecryptionError(Exception):
    """Raised when MFA ciphertext cannot be decrypted.

    Wraps :class:`cryptography.fernet.InvalidToken` (or any other Fernet-side
    failure) so callers can branch on a project-owned exception without
    importing ``cryptography`` directly. The original message is preserved so
    structured logs can be useful, but the typed surface keeps user-facing
    error responses generic.
    """


def _resolve_keys() -> list[str]:
    """Return the configured encryption key(s), current key first.

    ``mfa_secret_encryption_keys`` (the rotation-aware list) wins if set and
    non-empty; otherwise we fall back to ``mfa_secret_encryption_key``.
    Both attributes are looked up via ``getattr`` so this module remains
    importable before T4 lands the corresponding settings fields.
    """

    keys_list = getattr(settings, "mfa_secret_encryption_keys", None)
    if keys_list:
        return [key for key in keys_list if key]

    single = getattr(settings, "mfa_secret_encryption_key", None)
    if single:
        return [single]

    return []


def _build_fernet() -> MultiFernet:
    keys = _resolve_keys()
    if not keys:
        raise RuntimeError("MFA encryption key not configured")
    fernets = [Fernet(_to_bytes(key)) for key in keys]
    return MultiFernet(fernets)


def _to_bytes(key: str | bytes) -> bytes:
    if isinstance(key, bytes):
        return key
    return key.encode("utf-8")


def encrypt(secret: str) -> bytes:
    """Encrypt ``secret`` using the current MFA Fernet key.

    Always returns ``bytes``; two consecutive calls with the same plaintext
    yield distinct ciphertexts (Fernet seeds with a fresh IV per token).
    """

    fernet = _build_fernet()
    return fernet.encrypt(secret.encode("utf-8"))


def decrypt(blob: bytes) -> str:
    """Decrypt ``blob`` produced by :func:`encrypt`.

    Re-raises any :class:`cryptography.fernet.InvalidToken` (and adjacent
    decoding errors) as :class:`MfaSecretDecryptionError` so call sites can
    handle ciphertext tampering / key-loss in a single ``except`` block.
    """

    fernet = _build_fernet()
    try:
        plaintext = fernet.decrypt(blob)
    except InvalidToken as exc:
        raise MfaSecretDecryptionError(str(exc)) from exc
    return plaintext.decode("utf-8")
