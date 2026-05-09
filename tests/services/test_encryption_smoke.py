"""Smoke tests for the MFA Fernet encryption helper.

These cover the load-bearing contract that downstream callers rely on:
- round-trip
- distinct ciphertexts for repeated encryption of the same plaintext
- tampered ciphertext raises the typed `MfaSecretDecryptionError`
- absent configuration raises `RuntimeError` (defense-in-depth runtime check;
  the real fail-fast lives in T4 startup validation)

Full coverage (key rotation via `MultiFernet`, etc.) is owned by T24.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from fief.services.security import encryption as encryption_module
from fief.services.security.encryption import (
    MfaSecretDecryptionError,
    decrypt,
    encrypt,
)


class _FakeSettings:
    def __init__(
        self,
        *,
        key: str | None = None,
        keys: list[str] | None = None,
    ) -> None:
        if key is not None:
            self.mfa_secret_encryption_key = key
        if keys is not None:
            self.mfa_secret_encryption_keys = keys


@pytest.fixture
def fernet_key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture
def configured_settings(monkeypatch: pytest.MonkeyPatch, fernet_key: str) -> str:
    monkeypatch.setattr(
        encryption_module, "settings", _FakeSettings(key=fernet_key), raising=False
    )
    return fernet_key


def test_round_trip(configured_settings: str) -> None:
    plaintext = "JBSWY3DPEHPK3PXP"  # canonical pyotp base32 secret
    blob = encrypt(plaintext)
    assert isinstance(blob, bytes)
    assert decrypt(blob) == plaintext


def test_repeated_encryption_yields_distinct_ciphertexts(
    configured_settings: str,
) -> None:
    plaintext = "secret-value"
    a = encrypt(plaintext)
    b = encrypt(plaintext)
    assert a != b
    assert decrypt(a) == plaintext
    assert decrypt(b) == plaintext


def test_decrypt_tampered_ciphertext_raises_typed_error(
    configured_settings: str,
) -> None:
    blob = bytearray(encrypt("hello"))
    # Flip a byte in the middle to corrupt the token.
    blob[len(blob) // 2] ^= 0x01
    with pytest.raises(MfaSecretDecryptionError):
        decrypt(bytes(blob))


def test_missing_configuration_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        encryption_module, "settings", _FakeSettings(), raising=False
    )
    with pytest.raises(RuntimeError, match="MFA encryption key not configured"):
        encrypt("anything")
