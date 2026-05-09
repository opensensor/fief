# SEC-1 — Rate limiting, account lockout, enumeration hardening

**Status:** Draft · **Owner:** TBD · **Tier:** 1 · **Depends on:** —

## Summary
Add per-IP and per-account rate limits, progressive lockouts, and consistent response shapes on every unauthenticated auth endpoint so credential-stuffing and email-enumeration attacks are infeasible.

## Why now
- Today `/login`, `/forgot-password`, `/register`, `/verify` are all unbounded. A scripted credential-stuffing attempt against `members.lightnvr.com` is currently free.
- `/forgot-password` returns different responses for "user found" vs. "user not found" — an enumeration oracle.
- Foundation for SEC-2 (HIBP) and ENT-1 (SAML) which both need a shared throttle.

## Goals
1. Per-IP and per-identifier (email) sliding-window rate limits on every unauthenticated auth endpoint.
2. Progressive backoff: 5 failures → 1 min, 10 → 5 min, 20 → 15 min, 50 → 24 h (resets on password reset).
3. Identical response time and body shape for "valid email / invalid password" vs. "no such user".
4. Identical response shape for `/forgot-password` whether or not the email exists.
5. Configurable global toggle and limits via `settings`. Default values shipped strict.

## Non-goals
- CAPTCHA / hCaptcha / Turnstile (track separately if abuse continues).
- Geo-IP blocking.
- Bot-classification heuristics.
- IP allowlisting (separate per-tenant feature).

## Backing store
- **Redis** if available (already part of Dramatiq stack). Otherwise PostgreSQL with a `fief_rate_limit_buckets` table; either backend behind a small `RateLimiter` interface so we can swap.
- Sliding window log algorithm (one Redis sorted set per `(scope, key)`) — accurate, easy to reason about.

## Schema (DB-backed fallback only)

```
fief_rate_limit_buckets
  scope        text       -- e.g. "login_ip", "login_email", "forgot_email"
  key          text       -- IP or email
  ts           timestamp
  primary key (scope, key, ts)
  index on (scope, key)
fief_user_lockouts
  user_id       uuid pk
  failed_count  int
  locked_until  timestamp null
  updated_at    timestamp
```

## Limits (defaults; configurable)

| Endpoint              | Per-IP            | Per-identifier   | Notes                              |
|-----------------------|-------------------|------------------|------------------------------------|
| `/login`              | 30 / min          | 10 / min         | Identifier = email                 |
| `/forgot-password`    | 10 / min          | 3 / hour         |                                    |
| `/register`           | 5 / min           | n/a              |                                    |
| `/verify-email`       | 30 / min          | 10 / 5 min       |                                    |
| `/mfa/totp/verify`    | 30 / min          | 10 / 10 min      | Per login session                  |
| `/mfa/recover`        | 5 / 10 min        | 3 / hour         |                                    |
| `/.well-known/*`      | unlimited         | n/a              | Public discovery                   |

When a per-IP or per-identifier limit is exceeded, return HTTP **429** with `Retry-After`. We do NOT distinguish "rate limited" from "wrong password" to the user — show the same generic error.

## Account lockout

After **N** failed `/login` attempts on an existing user (regardless of IP):

| Failed count | Lockout duration |
|--------------|------------------|
| 5            | 1 min            |
| 10           | 5 min            |
| 20           | 15 min           |
| 50           | 24 h             |

Lockout state lives in `fief_user_lockouts`. `failed_count` resets on:
- successful login (with correct password AND, if applicable, MFA),
- password reset via `/forgot-password` flow,
- admin-triggered `Unlock account` action.

While locked, login still returns the **generic "invalid credentials"** error — the lockout is invisible to the attacker but enforced on the server.

## Enumeration hardening
- `/login` invalid email returns the same 401 body and similar latency (constant-time email lookup) as invalid password. Add a small artificial floor of ~150 ms on failure paths.
- `/forgot-password` always returns 202 "If that email exists, we've sent a link." (it currently does not).
- `/register` invalid email-already-taken returns a **422** with field error AS LONG AS the user is in active flow; for un-throttled probing, fall back to "We've sent you a verification email" copy and silently no-op when the email exists. Decision: lean toward latter for production, configurable.
- Verify-email: never confirm whether a code was for a known account.

## Telemetry
- Counters: `auth.rate_limit.{scope}.exceeded`, `auth.lockout.{count_bucket}.triggered`, `auth.failed_login.total`.
- Log a sampled (1%) entry on every limit exceeded.

## Edge cases
- **Shared NAT IPs** (corporate, mobile carriers) — per-IP limits must be set generously enough not to lock out a legit office. The values above target this.
- **IPv6 ranges** — apply limits at the /64 prefix level for IPv6.
- **Reverse proxy** — read `X-Forwarded-For` only when behind a trusted proxy (the existing `ProxyHeadersMiddleware` config). Do not trust it raw.
- **Time-skew** in Redis — use server time only.

## Risks
- Setting limits too tight locks out real users. Mitigation: ship with the values above, watch dashboards for two weeks, tune.
- DB-backed fallback adds write load. Mitigation: prefer Redis; the DB path is for dev/local.

## Sequencing
~1 sprint. Day 1-2: `RateLimiter` interface + Redis impl. Day 3-4: wire to all endpoints. Day 5: lockout. Days 6-8: enumeration parity + tests. Day 9-10: dashboards + tuning.
