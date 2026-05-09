"""Tests for SEC-1 settings (T2 of SEC-1).

These tests verify that the Settings class exposes the rate-limit toggles,
register collision flag, auth failure latency floor, and trusted-proxy hop
count documented in
``docs/prds/SEC-1-rate-limit-lockout-enumeration-plan.md`` (Task T2).

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
    "rate_limit_enabled": (bool, True),
    "rate_limit_login_per_ip_per_min": (int, 30),
    "rate_limit_login_per_email_per_min": (int, 10),
    "rate_limit_forgot_per_ip_per_min": (int, 10),
    "rate_limit_forgot_per_email_per_hour": (int, 3),
    "rate_limit_register_per_ip_per_min": (int, 5),
    "rate_limit_verify_per_ip_per_min": (int, 30),
    "rate_limit_verify_per_email_per_5min": (int, 10),
    "rate_limit_mfa_per_ip_per_min": (int, 30),
    "register_silent_on_email_collision": (bool, True),
    "auth_failure_min_latency_ms": (int, 150),
    "trusted_proxy_count": (int, 1),
}


@pytest.mark.parametrize("field_name", list(EXPECTED_FIELDS.keys()))
def test_settings_class_exposes_sec1_field(field_name):
    """Every documented SEC-1 field is declared on the Settings class."""
    Settings = _import_settings_class()
    assert field_name in Settings.model_fields, (
        f"SEC-1 setting '{field_name}' missing from Settings.model_fields"
    )


@pytest.mark.parametrize(
    "field_name,expected_type,expected_default",
    [(name, t, d) for name, (t, d) in EXPECTED_FIELDS.items()],
)
def test_settings_class_field_default(field_name, expected_type, expected_default):
    """Every SEC-1 field has the documented default value and type."""
    Settings = _import_settings_class()
    field_info = Settings.model_fields[field_name]
    assert field_info.default == expected_default, (
        f"SEC-1 setting '{field_name}' default is {field_info.default!r}, "
        f"expected {expected_default!r}"
    )
    # Pydantic stores the annotation under ``annotation``.
    assert field_info.annotation is expected_type, (
        f"SEC-1 setting '{field_name}' annotated as "
        f"{field_info.annotation!r}, expected {expected_type!r}"
    )


@pytest.mark.parametrize("field_name", list(EXPECTED_FIELDS.keys()))
def test_settings_singleton_exposes_sec1_field(field_name):
    """The runtime singleton (loaded via ``fief.settings``) carries the field."""
    from fief.settings import settings

    assert hasattr(settings, field_name), (
        f"SEC-1 setting '{field_name}' missing from settings singleton"
    )


def test_rate_limit_enabled_default_is_true():
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.rate_limit_enabled is True


def test_register_silent_on_email_collision_default_is_true():
    """Production default is silent-on-collision (no enumeration leak)."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.register_silent_on_email_collision is True


def test_auth_failure_min_latency_ms_default():
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.auth_failure_min_latency_ms == 150


def test_trusted_proxy_count_default():
    """DOKS single-ingress LB default is 1."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.trusted_proxy_count == 1


def test_rate_limit_window_defaults():
    """Spot-check the per-endpoint window defaults match the plan."""
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.rate_limit_login_per_ip_per_min == 30
    assert s.rate_limit_login_per_email_per_min == 10
    assert s.rate_limit_forgot_per_ip_per_min == 10
    assert s.rate_limit_forgot_per_email_per_hour == 3
    assert s.rate_limit_register_per_ip_per_min == 5
    assert s.rate_limit_verify_per_ip_per_min == 30
    assert s.rate_limit_verify_per_email_per_5min == 10
    assert s.rate_limit_mfa_per_ip_per_min == 30


def test_rate_limit_enabled_env_override(monkeypatch):
    """The toggle can be flipped off via env var (kill-switch behaviour)."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.rate_limit_enabled is False


def test_register_silent_on_email_collision_env_override(monkeypatch):
    """Dev/staging can flip the silent-on-collision flag off via env var."""
    monkeypatch.setenv("REGISTER_SILENT_ON_EMAIL_COLLISION", "false")
    Settings = _import_settings_class()
    s = Settings()  # type: ignore[call-arg]
    assert s.register_silent_on_email_collision is False
