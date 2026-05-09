# SEC-2 — Breached-password check (HIBP k-anonymity)

**Status:** Draft · **Owner:** TBD · **Tier:** 1 · **Depends on:** SEC-1 (shares Redis cache)

## Summary
Block users from setting a password that appears in the HaveIBeenPwned password corpus, using the [k-anonymity Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) so the password (or full hash) never leaves our process.

## Why now
- Users routinely reuse passwords known to be in dumps (`Password1`, `qwerty123`). The API rejects ~12% of all real-world passwords on average.
- Trivial to implement (<150 LOC), big perceived security win, zero ongoing cost.
- Lets us keep zxcvbn-style strength validation but adds a true *empirical* check rather than just heuristic.

## Goals
1. On registration, password change, and password reset, reject any password whose SHA-1 prefix returns the suffix in HIBP's response.
2. Configurable threshold: by default reject any match (count ≥ 1). Per-tenant override `tenant.breached_password_threshold` (int) — set to higher for less-strict tenants.
3. Cache hash-prefix responses in Redis with 24 h TTL.
4. Fail-open if HIBP is unreachable (5xx, timeout > 1 s) — log a metric and let the password through. **Never** fail-closed for IdP availability.
5. Surfaced as a normal form error: "This password has appeared in a known data breach. Please pick another."

## Non-goals
- HIBP email-breach lookup ("your account showed up in a breach").
- Custom dictionary / banned-words list (separate, smaller PRD if needed).
- Notifying users post-hoc when *their* current password becomes breached.

## API call

```
GET https://api.pwnedpasswords.com/range/{first_5_chars_of_sha1}
Header: User-Agent: opensensor-auth/{version}
Header: Add-Padding: true
```

Response body is text, lines `HASH_SUFFIX:COUNT`. Match against the suffix of the user's SHA-1.

## Module sketch

```python
# fief/services/security/breached_passwords.py
class BreachedPasswordChecker:
    async def is_breached(self, password: str, tenant: Tenant) -> bool:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        suffixes = await self._fetch(prefix)            # Redis-cached
        threshold = tenant.breached_password_threshold or 1
        return suffixes.get(suffix, 0) >= threshold

    async def _fetch(self, prefix: str) -> dict[str, int]:
        cached = await self.redis.get(f"hibp:{prefix}")
        if cached:
            return json.loads(cached)
        try:
            resp = await self.http.get(f"{HIBP_URL}/{prefix}", timeout=1.0)
            resp.raise_for_status()
        except (httpx.HTTPError, httpx.TimeoutException):
            metrics.incr("hibp.fail_open")
            return {}                                  # fail open
        parsed = dict(line.split(":") for line in resp.text.splitlines())
        await self.redis.set(f"hibp:{prefix}", json.dumps(parsed), ex=86400)
        return parsed
```

Wire into the password validators alongside zxcvbn:
- `fief/apps/auth/forms/register.py` (registration password)
- `fief/apps/auth/forms/password.py` (change password)
- `fief/apps/auth/forms/reset.py` (forgot-password reset)
- Admin-triggered set-password flow.

## Schema
None. Counters in Redis, metric in metrics service. No DB changes.

## Configuration

```
HIBP_ENABLED        bool, default true
HIBP_TIMEOUT_MS     int, default 1000
HIBP_CACHE_TTL_S    int, default 86400
```

`tenants.breached_password_threshold` int default null (means use 1). 1 = reject anything seen even once. Raise to e.g. 100 to allow common-but-everywhere passwords.

## Edge cases
- Zero-knowledge: we send only the **first 5 chars** of SHA-1. The password and even the full hash never leave our server.
- HIBP is rate-limited (free tier: per IP). With prefix caching we should rarely hit it — ~1.05M possible prefixes total, but real password distribution is heavily skewed; 1 day TTL is fine.
- User keeps an existing breached password — we do NOT check on login (that's a separate "post-hoc rotate" feature, out of scope).
- Empty / very-short password — caught by zxcvbn first; no HIBP call.

## Telemetry
- `hibp.checked.total`, `hibp.breached.total`, `hibp.cache.{hit,miss}`, `hibp.fail_open`, `hibp.latency_ms`.

## Risks
- HIBP outage causes false-pass. Acceptable: zxcvbn still runs, fail-open is metric-monitored, abuse limited by SEC-1.
- Latency on registration form. Mitigation: 1 s timeout, cache.

## Sequencing
~3 days incl. tests. SEC-1 must be in first to avoid HIBP being a backdoor for unbounded calls.
