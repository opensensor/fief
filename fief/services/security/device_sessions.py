"""Combined session + refresh token "device list" service (UX-1 T10).

Users have two parallel token surfaces that look the same from a "where
am I signed in?" point of view:

- :class:`fief.models.SessionToken` — the dashboard's session-cookie
  rows (one per browser).
- :class:`fief.models.RefreshToken` — OAuth refresh tokens issued to
  third-party clients (one per ``client_id`` × per browser, roughly).

This service is the read+write API behind the dashboard's
``/security/sessions`` page (T11). It pulls both lists, deduplicates
near-misses with a stable ``(browser_family, os_family, /24-of-ip)``
key, and exposes :class:`DeviceRow` views that the route hands to the
template. It also owns the three revoke paths:

- :meth:`DeviceSessionsService.revoke` — explicit "Revoke" click for a
  single device (audits :data:`AuditLogMessage.USER_SESSION_REVOKED`).
- :meth:`DeviceSessionsService.sign_out_others` — explicit "Sign out
  everywhere else" button (audits
  :data:`AuditLogMessage.USER_SESSIONS_SIGNED_OUT_OTHERS`).
- :meth:`DeviceSessionsService.auto_revoke_others` — invoked by other
  services after a security-relevant change (password change, MFA
  enroll/disable, recovery-code use); audits
  :data:`AuditLogMessage.USER_SESSIONS_AUTO_REVOKED` with a
  ``trigger_reason`` extra.

Dedup rationale
~~~~~~~~~~~~~~~
A single phone/laptop frequently appears with multiple session tokens
(login + login again after cookie clear) and one refresh token per
client app. Showing each row separately would be both noisy and
actively misleading: revoking one row would leave the user signed in
on what looks like the "same" device. Collapsing on
``(browser, os, /24-or-/64)`` is intentionally conservative — it
catches near-misses (cellular IP rotation inside a carrier /24, IPv6
privacy extensions inside a /64) while still keeping genuinely
different devices apart. ``last_seen_ip`` on the row reports the
IP from the most-recently-seen underlying token so the user sees
something fresh rather than the original login IP.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import UUID4
from user_agents import parse as parse_ua

from fief.logger import AuditLogger
from fief.models.audit_log import AuditLogMessage
from fief.repositories.refresh_token import RefreshTokenRepository
from fief.repositories.session_token import SessionTokenRepository

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fief.models import RefreshToken, SessionToken

__all__ = ["DeviceRow", "DeviceSessionsService"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeviceRow:
    """Render-time view of one deduped device.

    The underlying ``session_token_ids`` / ``refresh_token_ids`` are
    preserved so the route layer can map a "Revoke" click back to the
    correct DB rows. ``device_key`` is a short stable hash of those ids
    that the route uses as a URL-safe lookup; collision risk is
    negligible at the per-user scale this list covers.
    """

    device_key: str
    device_label: str
    device_kind: str
    first_seen: datetime
    last_seen: datetime
    last_seen_ip: str | None
    session_token_ids: list[UUID4] = field(default_factory=list)
    refresh_token_ids: list[UUID4] = field(default_factory=list)
    is_current: bool = False
    client_label: str | None = None


def _ip_bucket(ip: str | None) -> str:
    """Reduce a raw IP to a coarse bucket for dedup.

    IPv4 → first three octets (``/24``). IPv6 → ``/64`` network address.
    Unparseable / missing → the literal ``"unknown"``.
    """

    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    try:
        if isinstance(addr, ipaddress.IPv4Address):
            return str(
                ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address
            )
        return str(
            ipaddress.IPv6Network(f"{ip}/64", strict=False).network_address
        )
    except ValueError:
        return "unknown"


def _label_and_kind(user_agent: str | None) -> tuple[str, str]:
    """Return ``(device_label, device_kind)`` for a raw UA string.

    ``user_agents.parse('')`` returns family ``'Other'`` for both
    browser and OS, which we treat as "Unknown device" so the dashboard
    never surfaces the literal "Other on Other".
    """

    if not user_agent:
        return "Unknown device", "unknown"

    ua = parse_ua(user_agent)
    browser = ua.browser.family or ""
    os_family = ua.os.family or ""
    if not browser or not os_family or browser == "Other" or os_family == "Other":
        label = "Unknown device"
    else:
        label = f"{browser} on {os_family}"

    if ua.is_mobile:
        kind = "phone"
    elif ua.is_tablet:
        kind = "tablet"
    elif ua.is_pc:
        kind = "computer"
    else:
        kind = "unknown"

    return label, kind


def _dedup_key(user_agent: str | None, ip: str | None) -> tuple[str, str, str]:
    """The ``(browser_family, os_family, ip_bucket)`` tuple used to
    collapse near-miss tokens into a single device row.
    """

    if not user_agent:
        browser, os_family = "", ""
    else:
        ua = parse_ua(user_agent)
        browser = ua.browser.family or ""
        os_family = ua.os.family or ""
    return (browser, os_family, _ip_bucket(ip))


class DeviceSessionsService:
    """Combined session + refresh token list and revocation orchestration.

    Stateless apart from its three handles (two repos + audit logger),
    so a fresh instance per request is the cheapest correct model and
    matches the other ``fief/services/security`` factories.
    """

    def __init__(
        self,
        session_repo: SessionTokenRepository,
        refresh_repo: RefreshTokenRepository,
        audit_logger: AuditLogger,
    ) -> None:
        self.session_repo = session_repo
        self.refresh_repo = refresh_repo
        self.audit_logger = audit_logger

    async def list_for_user(
        self, user_id: UUID4, *, current_session_id: UUID4 | None
    ) -> list[DeviceRow]:
        """Return the deduplicated device list for ``user_id``.

        Both repos already filter to non-expired rows, so we don't
        re-filter here. Within each dedup group:

        - ``first_seen`` = min(``created_at``)
        - ``last_seen`` = max(``last_seen_at`` or ``created_at``)
        - ``last_seen_ip`` = the IP on the most-recently-seen token
        - ``client_label`` = the refresh token's ``client.name`` (or a
          comma-joined set if multiple distinct clients land in the same
          dedup bucket — uncommon but cheap to handle).
        - ``is_current`` = ``current_session_id`` ∈ ``session_token_ids``.
        """

        session_tokens = await self.session_repo.list_by_user_id(user_id)
        refresh_tokens = await self.refresh_repo.list_by_user_id(user_id)

        # Group by dedup key. We hold raw row references in the bucket
        # so we can compute aggregates after grouping is complete.
        groups: dict[
            tuple[str, str, str],
            dict[str, list],
        ] = {}
        for st in session_tokens:
            key = _dedup_key(
                st.created_user_agent, st.last_seen_ip or st.created_ip
            )
            bucket = groups.setdefault(
                key, {"sessions": [], "refreshes": []}
            )
            bucket["sessions"].append(st)
        for rt in refresh_tokens:
            key = _dedup_key(
                rt.created_user_agent, rt.last_seen_ip or rt.created_ip
            )
            bucket = groups.setdefault(
                key, {"sessions": [], "refreshes": []}
            )
            bucket["refreshes"].append(rt)

        rows: list[DeviceRow] = []
        for _key, bucket in groups.items():
            sessions: list[SessionToken] = bucket["sessions"]
            refreshes: list[RefreshToken] = bucket["refreshes"]

            # ``effective_last_seen`` falls back to created_at for rows
            # that have never been touched (e.g. a fresh token issued in
            # the same request that's listing). This keeps the sort
            # stable in tests and in production.
            def _eff_last(t):  # noqa: ANN001 - internal helper
                return t.last_seen_at or t.created_at

            all_tokens = [*sessions, *refreshes]
            most_recent = max(all_tokens, key=_eff_last)
            first_seen = min(t.created_at for t in all_tokens)
            last_seen = _eff_last(most_recent)
            last_seen_ip = (
                most_recent.last_seen_ip or most_recent.created_ip
            )

            # Pick a representative UA for label/kind: the most-recently
            # seen token's UA wins, falling back to whatever we have.
            label, kind = _label_and_kind(most_recent.created_user_agent)

            session_ids = [s.id for s in sessions]
            refresh_ids = [r.id for r in refreshes]
            device_key = hashlib.sha256(
                ",".join(
                    sorted(str(i) for i in [*session_ids, *refresh_ids])
                ).encode()
            ).hexdigest()[:16]

            # Multiple distinct clients in one bucket: comma-join their
            # names so the user sees both. ``set`` preserves uniqueness;
            # ``sorted`` keeps the rendering deterministic.
            client_names = sorted(
                {
                    rt.client.name
                    for rt in refreshes
                    if rt.client is not None and getattr(rt.client, "name", None)
                }
            )
            client_label = ", ".join(client_names) if client_names else None

            is_current = (
                current_session_id is not None
                and current_session_id in session_ids
            )

            rows.append(
                DeviceRow(
                    device_key=device_key,
                    device_label=label,
                    device_kind=kind,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    last_seen_ip=last_seen_ip,
                    session_token_ids=session_ids,
                    refresh_token_ids=refresh_ids,
                    is_current=is_current,
                    client_label=client_label,
                )
            )

        rows.sort(key=lambda r: r.last_seen, reverse=True)
        return rows

    async def revoke(
        self, user_id: UUID4, device_key: str
    ) -> DeviceRow | None:
        """Revoke the device identified by ``device_key``.

        We re-list to recompute ``device_key`` server-side rather than
        trust the caller's mapping — the route hands us a 16-char hex
        string from the URL, and the only authoritative mapping back to
        the underlying tokens is to recompute the listing. A stale
        ``device_key`` (concurrent double-click → second click hits a
        key that no longer exists) returns ``None`` and the route
        translates that to a 404.

        On a match, every underlying session and refresh token is
        deleted (scoped by ``user_id`` so one user can't revoke
        another's tokens) and we audit
        :data:`AuditLogMessage.USER_SESSION_REVOKED` once.
        """

        rows = await self.list_for_user(user_id, current_session_id=None)
        match = next((r for r in rows if r.device_key == device_key), None)
        if match is None:
            return None

        for token_id in match.session_token_ids:
            await self.session_repo.delete_by_id_for_user(token_id, user_id)
        for token_id in match.refresh_token_ids:
            await self.refresh_repo.delete_by_id_for_user(token_id, user_id)

        self.audit_logger(
            AuditLogMessage.USER_SESSION_REVOKED,
            subject_user_id=user_id,
            extra={
                "device_label": match.device_label,
                "revoked_session_count": len(match.session_token_ids),
                "revoked_refresh_count": len(match.refresh_token_ids),
            },
        )
        return match

    async def sign_out_others(
        self, user_id: UUID4, current_session_id: UUID4 | None
    ) -> tuple[int, int]:
        """Revoke every session except ``current_session_id`` and ALL
        refresh tokens.

        Refresh tokens have no concept of "the current session" (they
        get re-issued on the next OAuth round-trip from whichever device
        the user is on right now), so the safest semantic for "Sign out
        everywhere else" is to wipe them all and let the user re-grant
        on next use. The session-cookie row backing the current browser
        is preserved via ``except_ids=[current_session_id]``.

        Returns ``(session_count, refresh_count)`` for the success flash.
        """

        except_ids = (
            [current_session_id] if current_session_id is not None else []
        )
        s_count = await self.session_repo.delete_all_except_for_user(
            user_id, except_ids
        )
        r_count = await self.refresh_repo.delete_all_except_for_user(
            user_id, []
        )

        self.audit_logger(
            AuditLogMessage.USER_SESSIONS_SIGNED_OUT_OTHERS,
            subject_user_id=user_id,
            extra={
                "revoked_session_count": s_count,
                "revoked_refresh_count": r_count,
            },
        )
        return (s_count, r_count)

    async def auto_revoke_others(
        self,
        user_id: UUID4,
        current_session_id: UUID4 | None,
        *,
        reason: str,
    ) -> tuple[int, int]:
        """Same revoke semantics as :meth:`sign_out_others` but audited
        as :data:`AuditLogMessage.USER_SESSIONS_AUTO_REVOKED`.

        ``reason`` is one of ``"password_change"``, ``"mfa_enrolled"``,
        ``"mfa_disabled"``, ``"recovery_code_used"`` and is stored under
        ``extra.trigger_reason`` so audit consumers can distinguish a
        user-initiated "sign out everywhere" from an automatic
        post-password-change purge.
        """

        except_ids = (
            [current_session_id] if current_session_id is not None else []
        )
        s_count = await self.session_repo.delete_all_except_for_user(
            user_id, except_ids
        )
        r_count = await self.refresh_repo.delete_all_except_for_user(
            user_id, []
        )

        self.audit_logger(
            AuditLogMessage.USER_SESSIONS_AUTO_REVOKED,
            subject_user_id=user_id,
            extra={
                "trigger_reason": reason,
                "revoked_session_count": s_count,
                "revoked_refresh_count": r_count,
            },
        )
        return (s_count, r_count)
