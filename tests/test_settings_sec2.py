"""Tests for SEC-2 settings (T2 of SEC-2).

These tests verify that the Settings class exposes the HIBP breached-password
check toggles documented in
``docs/prds/SEC-2-hibp-breached-password-check-plan.md`` (Task T2).

The tests are pure schema/default checks — no startup validator is required
because the documented defaults are safe.
"""

import pytest


def _import_settings_class():
    """Import the base Settings class fresh so env vars are picked up."""
    from fief.settings_class import Settings

    return Settings


# Mapping: setting name -> (expected_type, expected_default)
EXPECTED_FIELDS: dict[str, tuple[type, object]] = {
    "breached_password_check_enabled": (bool, True),
    "breached_password_default_threshold": (int, 1),
    "breached_password_api_url": (str, "https://api.pwnedpasswords.com/range"),
    "breached_password_user_agent": (str, "opensensor-auth/1.0"),
    "breached_password_timeout_ms": (int, 1000),
    "breached_password_cache_ttl_s": (int, 86400),
}


@pytest.mark.parametrize("field_name", list(EXPECTED_FIELDS.keys()))
def test_settings_class_exposes_sec2_field(field_name):
    """Every documented SEC-2 field is declared on the Settings class."""
    Settings = _import_settings_class()
    assert field_name in Settings.model_fields, (
        f"SEC-2 setting '{field_name}' missing from Settings.model_fields"
    )


@pytest.mark.parametrize(
    "field_name,expected_type,expected_default",
    [(name, t, d) for name, (t, d) in EXPECTED_FIELDS.items()],
)
def test_settings_class_field_default(field_name, expected_type, expected_default):
    """Every SEC-2 field has the documented default value and type."""
    Settings = _import_settings_class()
    field_info = Settings.model_fields[field_name]
    assert field_info.default == expected_default, (
        f"SEC-2 setting '{field_name}' default is {field_info.default!r}, "
        f"expected {expected_default!r}"
    )
    # Pydantic stores the annotation under ``annotation``.
    assert field_info.annotation is expected_type, (
        f"SEC-2 setting '{field_name}' annotated as "
        f"{field_info.annotation!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("field_name", list(EXPECTED_FIELDS.keys()))
def test_settings_singleton_exposes_sec2_field(field_name):
    """The runtime singleton (loaded via ``fief.settings``) carries the field."""
    from fief.settings import settings

    assert hasattr(settings, field_name), (
        f"SEC-2 setting '{field_name}' missing from settings singleton"
    )


def test_breached_password_check_enabled_default_is_true():
    """Global kill switch defaults to ON — check fires by default."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.breached_password_check_enabled is True


def test_breached_password_default_threshold_default():
    """Threshold of 1 means reject any sighting (most strict default)."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.breached_password_default_threshold == 1


def test_breached_password_api_url_default():
    """HIBP k-anonymity range API is the default endpoint."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.breached_password_api_url == "https://api.pwnedpasswords.com/range"


def test_breached_password_user_agent_default():
    """HIBP requires a non-default UA — ours identifies the auth service."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.breached_password_user_agent == "opensensor-auth/1.0"


def test_breached_password_timeout_ms_default():
    """1 second HTTP timeout — fail-open if HIBP is slow."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.breached_password_timeout_ms == 1000


def test_breached_password_cache_ttl_s_default():
    """24-hour Redis cache TTL — keeps HIBP roundtrip rare."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.breached_password_cache_ttl_s == 86400


def test_breached_password_check_enabled_env_override(monkeypatch):
    """The toggle can be flipped off via env var (kill-switch behaviour)."""
    monkeypatch.setenv("BREACHED_PASSWORD_CHECK_ENABLED", "false")
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.breached_password_check_enabled is False


def test_breached_password_default_threshold_env_override(monkeypatch):
    """A tenant-wide leniency knob can be raised via env var."""
    monkeypatch.setenv("BREACHED_PASSWORD_DEFAULT_THRESHOLD", "100")
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.breached_password_default_threshold == 100
