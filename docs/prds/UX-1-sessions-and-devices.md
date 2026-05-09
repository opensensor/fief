# UX-1 — Active sessions & devices tab

**Status:** Draft · **Owner:** TBD · **Tier:** 3 · **Depends on:** —

## Summary
Surface a "Sessions & Devices" view inside the modernized dashboard so users can see every place they're signed in, identify the current session, and revoke any individual session or "everything else." Pulls from data we already have (`fief_session_tokens`, `fief_refresh_tokens`); no schema changes beyond a few annotation fields.

## Why now
- Pure trust UX with low engineering cost — quick win on the user-trust narrative.
- Asked by every user who's lost a laptop or shared a device.
- Foundation for future "Suspicious activity" alerts.

## Goals
1. Users see a list of their active sessions and refresh tokens (deduped by device).
2. Each row shows: device label (parsed from User-Agent), location (city-level GeoIP), IP, first seen, last seen, and a "current session" badge.
3. Revoke a single session.
4. "Sign out of all other sessions" button.
5. After password change or MFA enrollment / disable, all other sessions auto-revoked.
6. Audit-logged.

## Non-goals
- Real-time push notifications about a new sign-in (separate feature; needs email infra wiring).
- Device fingerprinting beyond UA + IP (privacy sensitivity).
- Per-session permissions / scopes editor.

## Data we already have
- `fief_session_tokens.id`, `user_id`, `expires_at`, `created_at`.
- `fief_refresh_tokens.id`, `user_id`, `client_id`, `authenticated_at`, `expires_at`.
- (Add) on each token row: `last_seen_ip`, `last_seen_at`, `last_seen_user_agent`.

## Schema additions

```sql
ALTER TABLE fief_session_tokens
  ADD COLUMN created_ip text,
  ADD COLUMN created_user_agent text,
  ADD COLUMN last_seen_at timestamp,
  ADD COLUMN last_seen_ip text;

ALTER TABLE fief_refresh_tokens
  ADD COLUMN created_ip text,
  ADD COLUMN created_user_agent text,
  ADD COLUMN last_seen_at timestamp,
  ADD COLUMN last_seen_ip text;
```

A small middleware (or per-route hook) updates `last_seen_*` on session use and on refresh-token grant.

## UA parsing
Use [`ua-parser`](https://pypi.org/project/ua-parser/) to extract `Browser X on macOS` style labels. Fall back to "Unknown device".

## GeoIP
Use MaxMind GeoLite2-City (free) at startup load. Store no geo data persistently — resolve at display time. Document this for privacy: "We compute approximate location from IP when you view this page; we don't store it."

## Endpoints

| Method | Path                                       | Purpose                                |
|--------|--------------------------------------------|----------------------------------------|
| GET    | `/api/me/sessions`                         | Combined list (sessions + refresh)     |
| DELETE | `/api/me/sessions/{id}`                    | Revoke one (uses scoped `id`)          |
| POST   | `/api/me/sessions/sign-out-others`         | Revoke all but current                 |

Server-side dedup: a "device" is a `(user_agent_family, OS, last_seen_ip)` tuple; one row in the UI maps to multiple tokens. Revoking the row revokes all underlying tokens.

## UX
New left-rail nav item in the dashboard sidebar: **Devices**. Page layout:

- Header: "Active sessions" with count + sign-out-others button.
- Table rows, each with:
  - Device icon (laptop, phone, tablet, generic) inferred from UA
  - "MacBook · Safari 19" headline
  - Sub-line: `192.0.2.1 · San Francisco, CA · Last active 2 minutes ago`
  - Right side: badge "This device" or "Revoke" button
- Bottom note: "Signing out of a session won't sign you out of the application until its access token expires (about 60 minutes)." — sets accurate expectation.

## Auto-revocation triggers
- Password change → all other sessions revoked.
- MFA enrollment or disable → all other sessions revoked.
- (Future) Email change confirm → all other sessions revoked.
- These already make sense; wire them as part of this PRD.

## Edge cases
- Multiple refresh tokens per device — collapse via dedup; revoke cascades.
- Long-lived refresh token still valid after access token expiry → row shows it but with "Last active 12 days ago." Sort by recency.
- IPv6 + privacy extensions — last-seen IP changes frequently; dedup by family + OS only when within 24 h.
- User on a VPN — geo will look wrong; not our problem to solve, but note in UI: "approximate, based on IP".
- Concurrent sign-out-others while a request from another tab is in flight — last-write wins; tab gets 401 on next call.

## Telemetry
- `sessions.viewed`, `sessions.revoked`, `sessions.sign_out_others`, `sessions.auto_revoked.{password_change,mfa}`.

## Risks
- Storing IPs implicates GDPR — IP is personal data. Mitigation: document in privacy policy; offer deletion via existing data deletion (post GDPR PRD).
- UA parser library updates frequently — pin a version, periodically refresh.

## Open questions
- Show client_id (which app the session was issued for)? Recommend yes, as a small "via LightNVR Web" pill on the row.
- Allow revoking the *current* session via this UI? Recommend showing a confirmation that triggers a clean logout redirect, rather than the user nuking themselves silently.

## Sequencing
~1 sprint. Days 1-2: schema + ingest middleware + UA parsing. Days 3-5: UI + dedup + endpoints. Days 6-8: auto-revoke triggers, GeoIP wiring, copy review. Days 9-10: tests + ship.
