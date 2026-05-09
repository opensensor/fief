"""Client IP extraction dependency (T7 of SEC-1).

Audit logging needs the **exact** client IP for forensic precision, while
rate-limit buckets need to **collapse IPv6 /128s into /64 networks** so an
attacker cannot trivially rotate through a personal IPv6 allocation. To keep
both contracts in one place, this module exposes a single dependency that
returns a :class:`ClientIpInfo` carrying both shapes.

Resolution rules
----------------

1. If ``settings.trusted_proxy_count > 0`` we trust the ``X-Forwarded-For``
   header and select the **N-from-rightmost** entry (where ``N`` equals
   ``trusted_proxy_count``). The rightmost entry is the IP injected by the
   load balancer closest to us; entries further to the right of that are the
   upstream proxy hops we trust. When the header has fewer entries than
   ``trusted_proxy_count`` we fall back to the leftmost entry — that is the
   most-likely real client IP and is the safest default for
   audit/rate-limiting in a misconfigured deployment.

2. Otherwise (or if the header is missing/empty/whitespace-only) we fall
   back to ``request.client.host``.

Rate-limit key normalisation
----------------------------

* IPv6 addresses are collapsed to their ``/64`` network address rendered as
  a string. We use :class:`ipaddress.IPv6Network` with ``strict=False`` so
  any host bits in the input are tolerated.
* IPv4 addresses are returned unchanged.
* Anything that fails to parse as an IP is returned as-is (and the caller
  bucket-keys against the raw value) — we still record it for audit.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from fastapi import Request

from fief.settings import settings

__all__ = [
    "ClientIpInfo",
    "get_client_ip",
    "get_client_ip_info",
]

# Sentinel used when neither X-Forwarded-For nor request.client are present.
# We still want a non-empty, deterministic string for audit logs and as a
# rate-limit bucket key (otherwise multiple unknowable clients would all
# share an empty bucket).
_UNKNOWN_CLIENT = "unknown"


@dataclass(frozen=True)
class ClientIpInfo:
    """Two-shape client IP container.

    ``raw`` is the exact IP string we resolved (good for audit logs).
    ``rate_limit_key`` is the normalised form used as a Redis bucket key —
    IPv6 is collapsed to its ``/64`` network address; IPv4 is unchanged.
    """

    raw: str
    rate_limit_key: str


def _select_xff_entry(xff_header: str, trusted_proxy_count: int) -> str | None:
    """Return the chosen entry from an ``X-Forwarded-For`` header value.

    Returns ``None`` when the header is empty / contains no usable entry, in
    which case the caller falls back to ``request.client.host``.
    """

    # Comma-separated, optional whitespace, case-insensitive. Empty entries
    # (e.g. ``"  ,  ,  "``) are filtered out.
    entries = [part.strip() for part in xff_header.split(",")]
    entries = [part for part in entries if part]
    if not entries:
        return None

    # N-from-rightmost. ``trusted_proxy_count == 1`` -> the last entry, which
    # is what our LB injected. Larger values dig into the trusted upstream
    # hops; if the chain is shorter than expected we fall back to the
    # leftmost entry — the safest known client IP in a short / misconfigured
    # chain.
    index_from_right = max(1, trusted_proxy_count)
    if index_from_right > len(entries):
        return entries[0]
    return entries[-index_from_right]


def _normalise_for_rate_limit(ip: str) -> str:
    """Return the rate-limit bucket key for ``ip``.

    * IPv6 → ``/64`` network address rendered as a string.
    * IPv4 → unchanged.
    * Unparseable → returned as-is.
    """

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return ip

    if isinstance(parsed, ipaddress.IPv6Address):
        network = ipaddress.IPv6Network(f"{parsed}/64", strict=False)
        return str(network.network_address)

    # IPv4Address: return the canonical string form (which equals ``ip`` for
    # any well-formed dotted-quad input).
    return str(parsed)


def get_client_ip_info(request: Request) -> ClientIpInfo:
    """FastAPI dependency returning both the raw and rate-limit-key forms."""

    # ``trusted_proxy_count`` was added by T2 of SEC-1; ``getattr`` keeps us
    # safe in the (unlikely) case that this dependency is exercised before
    # settings carries the field — e.g. partial-merge or stale test config.
    trusted_proxy_count = getattr(settings, "trusted_proxy_count", 1)

    chosen: str | None = None
    if trusted_proxy_count and trusted_proxy_count > 0:
        xff_header = request.headers.get("x-forwarded-for")
        if xff_header:
            chosen = _select_xff_entry(xff_header, trusted_proxy_count)

    if chosen is None:
        client = request.client
        chosen = client.host if client and client.host else _UNKNOWN_CLIENT

    return ClientIpInfo(raw=chosen, rate_limit_key=_normalise_for_rate_limit(chosen))


def get_client_ip(request: Request) -> str:
    """Back-compat shim returning the exact (audit) IP string.

    Existing call sites that just need a single string for logging keep
    working unchanged. New rate-limit code should use
    :func:`get_client_ip_info` and read ``.rate_limit_key``.
    """

    return get_client_ip_info(request).raw
