"""Tests for the get_client_ip dependency (T7 of SEC-1).

Validates that the dependency:

* prefers ``X-Forwarded-For`` only when ``settings.trusted_proxy_count > 0``
  and otherwise falls back to ``request.client.host``;
* selects the **N-from-rightmost** entry of ``X-Forwarded-For`` where
  ``N = trusted_proxy_count`` (the rightmost entry is the one our LB injected);
* falls back to the leftmost entry when the header has fewer hops than
  ``trusted_proxy_count``;
* normalises IPv6 addresses to the ``/64`` network address for use as a
  rate-limit bucket key while preserving the exact IP under ``raw``;
* is robust to missing / empty / malformed XFF headers.
"""

from __future__ import annotations

import pytest
from starlette.requests import Request

from fief.dependencies.client_ip import (
    ClientIpInfo,
    get_client_ip,
    get_client_ip_info,
)


def _make_request(
    *,
    client_host: str | None = "1.2.3.4",
    xff: str | None = None,
) -> Request:
    """Build a minimal Starlette ``Request`` for unit tests.

    The scope mirrors what FastAPI/Starlette produce in the real server: a
    list of (header_name, header_value) byte pairs and a ``client`` tuple.
    """

    headers: list[tuple[bytes, bytes]] = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode("latin-1")))

    scope: dict = {
        "type": "http",
        "headers": headers,
        "client": (client_host, 12345) if client_host is not None else None,
    }
    return Request(scope)


# ---------------------------------------------------------------------------
# No XFF -> client.host is used for both fields.
# ---------------------------------------------------------------------------


def test_no_xff_header_uses_client_host(monkeypatch: pytest.MonkeyPatch) -> None:
    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(client_host="1.2.3.4", xff=None)
    info = get_client_ip_info(request)

    assert info == ClientIpInfo(raw="1.2.3.4", rate_limit_key="1.2.3.4")
    assert get_client_ip(request) == "1.2.3.4"


def test_trusted_proxy_count_zero_ignores_xff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``trusted_proxy_count`` is 0, XFF must be ignored entirely."""

    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 0)

    request = _make_request(client_host="1.2.3.4", xff="9.9.9.9")
    info = get_client_ip_info(request)

    assert info.raw == "1.2.3.4"
    assert info.rate_limit_key == "1.2.3.4"


# ---------------------------------------------------------------------------
# XFF resolution: N-from-rightmost selection.
# ---------------------------------------------------------------------------


def test_xff_two_hops_count_one_takes_rightmost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(client_host="127.0.0.1", xff="1.2.3.4, 5.6.7.8")
    info = get_client_ip_info(request)

    assert info.raw == "5.6.7.8"
    assert info.rate_limit_key == "5.6.7.8"


def test_xff_three_hops_count_one_takes_rightmost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(
        client_host="127.0.0.1",
        xff="1.2.3.4, 5.6.7.8, 9.10.11.12",
    )
    info = get_client_ip_info(request)

    assert info.raw == "9.10.11.12"
    assert info.rate_limit_key == "9.10.11.12"


def test_xff_two_hops_count_two_takes_leftmost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N-from-rightmost with N == len(entries) is the leftmost entry."""

    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 2)

    request = _make_request(client_host="127.0.0.1", xff="1.2.3.4, 5.6.7.8")
    info = get_client_ip_info(request)

    assert info.raw == "1.2.3.4"
    assert info.rate_limit_key == "1.2.3.4"


def test_xff_fewer_entries_than_trusted_count_falls_back_to_leftmost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When XFF has fewer hops than trusted_proxy_count, take the leftmost."""

    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 5)

    request = _make_request(client_host="127.0.0.1", xff="1.2.3.4, 5.6.7.8")
    info = get_client_ip_info(request)

    assert info.raw == "1.2.3.4"


# ---------------------------------------------------------------------------
# IPv6 /64 collapse for rate-limit bucket key.
# ---------------------------------------------------------------------------


def test_ipv6_xff_rate_limit_key_is_64_collapse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IPv6 ``raw`` is preserved exactly; ``rate_limit_key`` is the /64 net."""

    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(client_host="127.0.0.1", xff="2001:db8::1234")
    info = get_client_ip_info(request)

    assert info.raw == "2001:db8::1234"
    assert info.rate_limit_key == "2001:db8::"


def test_ipv6_with_full_address_collapses_to_64(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 0)

    request = _make_request(
        client_host="2001:db8:85a3:1234:dead:beef:cafe:0001",
        xff=None,
    )
    info = get_client_ip_info(request)

    assert info.raw == "2001:db8:85a3:1234:dead:beef:cafe:0001"
    # The /64 prefix of 2001:db8:85a3:1234:dead:... is 2001:db8:85a3:1234::
    assert info.rate_limit_key == "2001:db8:85a3:1234::"


def test_ipv4_rate_limit_key_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 0)

    request = _make_request(client_host="203.0.113.42", xff=None)
    info = get_client_ip_info(request)

    assert info.raw == "203.0.113.42"
    assert info.rate_limit_key == "203.0.113.42"


# ---------------------------------------------------------------------------
# Robustness: malformed / empty / missing values do not crash.
# ---------------------------------------------------------------------------


def test_empty_xff_falls_back_to_client_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(client_host="1.2.3.4", xff="")
    info = get_client_ip_info(request)

    assert info.raw == "1.2.3.4"
    assert info.rate_limit_key == "1.2.3.4"


def test_xff_only_whitespace_falls_back_to_client_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(client_host="1.2.3.4", xff="   ,  ,  ")
    info = get_client_ip_info(request)

    assert info.raw == "1.2.3.4"
    assert info.rate_limit_key == "1.2.3.4"


def test_malformed_ip_does_not_crash_uses_raw_for_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-parseable IP keeps the raw value as the rate-limit key."""

    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(client_host="127.0.0.1", xff="not-an-ip")
    info = get_client_ip_info(request)

    assert info.raw == "not-an-ip"
    assert info.rate_limit_key == "not-an-ip"


def test_missing_client_and_no_xff_returns_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If both XFF and ``request.client`` are absent the dependency must
    still produce a usable string (for logs / rate-limit buckets) instead of
    crashing."""

    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(client_host=None, xff=None)
    info = get_client_ip_info(request)

    # The exact sentinel is implementation-defined but must be a non-empty
    # string equal across both fields.
    assert isinstance(info.raw, str) and info.raw
    assert info.rate_limit_key == info.raw


def test_back_compat_get_client_ip_returns_raw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fief import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "trusted_proxy_count", 1)

    request = _make_request(client_host="127.0.0.1", xff="2001:db8::abcd")
    assert get_client_ip(request) == "2001:db8::abcd"
