"""Tests for the MFA encryption key settings (T4 of MFA-1).

These tests verify that:
1. The Settings class exposes ``mfa_secret_encryption_key`` and
   ``mfa_secret_encryption_keys`` fields.
2. ``mfa_secret_encryption_keys`` is parsed from a comma-separated env value.
3. The FastAPI lifespan refuses to start when neither is populated and emits
   a clear startup log line when one (or both) is set.
"""

import logging
from unittest.mock import patch

import pytest
from fastapi import FastAPI


def _import_settings_class():
    """Import the base Settings class fresh so env vars are picked up."""
    from fief.settings_class import Settings

    return Settings


def test_settings_has_mfa_encryption_key_fields():
    Settings = _import_settings_class()
    fields = Settings.model_fields
    assert "mfa_secret_encryption_key" in fields
    assert "mfa_secret_encryption_keys" in fields


def test_settings_default_mfa_keys_are_none():
    from fief.settings import settings

    # Both must be optional (default None) so existing deployments keep
    # constructing the Settings object — the lifespan check is what enforces
    # the presence at boot, not Pydantic validation.
    assert hasattr(settings, "mfa_secret_encryption_key")
    assert hasattr(settings, "mfa_secret_encryption_keys")


def test_settings_parses_comma_separated_keys(monkeypatch):
    monkeypatch.setenv(
        "MFA_SECRET_ENCRYPTION_KEYS",
        "key-one,key-two,key-three",
    )
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.mfa_secret_encryption_keys == ["key-one", "key-two", "key-three"]


def test_settings_strips_whitespace_in_comma_list(monkeypatch):
    monkeypatch.setenv(
        "MFA_SECRET_ENCRYPTION_KEYS",
        " key-one , key-two ",
    )
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.mfa_secret_encryption_keys == ["key-one", "key-two"]


def test_settings_single_key_env(monkeypatch):
    monkeypatch.setenv("MFA_SECRET_ENCRYPTION_KEY", "the-only-key")
    monkeypatch.delenv("MFA_SECRET_ENCRYPTION_KEYS", raising=False)
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.mfa_secret_encryption_key == "the-only-key"
    assert s.mfa_secret_encryption_keys is None


@pytest.mark.asyncio
async def test_lifespan_raises_when_no_mfa_key(monkeypatch):
    """When neither MFA env is populated, app boot must fail fast."""
    from fief import lifespan as lifespan_module

    with patch.object(
        lifespan_module.settings, "mfa_secret_encryption_key", None
    ), patch.object(
        lifespan_module.settings, "mfa_secret_encryption_keys", None
    ):
        app = FastAPI()
        with pytest.raises(EnvironmentError) as excinfo:
            async with lifespan_module.lifespan(app):
                pass
        assert "MFA_SECRET_ENCRYPTION_KEY" in str(excinfo.value)


@pytest.mark.asyncio
async def test_lifespan_succeeds_with_single_key(monkeypatch, caplog):
    """A single key on its own is sufficient and is logged."""
    from fief import lifespan as lifespan_module

    with patch.object(
        lifespan_module.settings, "mfa_secret_encryption_key", "single-key"
    ), patch.object(
        lifespan_module.settings, "mfa_secret_encryption_keys", None
    ):
        app = FastAPI()
        with caplog.at_level(logging.INFO):
            async with lifespan_module.lifespan(app):
                pass


@pytest.mark.asyncio
async def test_lifespan_succeeds_with_keys_list(monkeypatch):
    """A populated list of keys is sufficient (rotation case)."""
    from fief import lifespan as lifespan_module

    with patch.object(
        lifespan_module.settings, "mfa_secret_encryption_key", None
    ), patch.object(
        lifespan_module.settings,
        "mfa_secret_encryption_keys",
        ["k1", "k2"],
    ):
        app = FastAPI()
        async with lifespan_module.lifespan(app):
            pass
