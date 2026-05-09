# Plan: SEC-1 — Rate limiting, account lockout, enumeration hardening

**Generated:** 2026-05-09
**Source PRD:** `docs/prds/SEC-1-rate-limit-lockout-enumeration.md`
**Decisions locked in:**
- Redis-only backing store (no Postgres fallback). Reuses the existing `REDIS_URL` from the Dramatiq broker; tests use `fakeredis`.
- Admin "Unlock account" endpoint **and** UI button included in scope.
- The MFA-1 per-LoginSession `mfa_attempts_count` lockout (already shipped) stays as-is — orthogonal to SEC-1's per-IP / per-account scopes.
- `/forgot-password` already returns identical responses for known/unknown emails (verified in `reset.py:40-49`); SEC-1 only adds rate limiting on top, not enumeration parity (already there).
- `UserManager.authenticate` already runs constant-time hash on missing-user paths (`user_manager.py:402-405`); we don't need to re-engineer that.

## Overview
Add per-IP and per-account-identifier sliding-window rate limits, progressive lockouts on `/login`, identical error shapes across the auth surface, and a small ~150 ms artificial latency floor on the login failure path. State for rate-limit windows lives in Redis; lockout state lives in a new `fief_user_lockouts` table (durable across Redis flushes).

Reference points (from codebase exploration):
- Login: `fief/apps/auth/routers/auth.py:168` → `user_manager.authenticate(...)` at line 203 → error response at line 207. Insertion point: BEFORE authenticate (rate-limit + lockout check) and AFTER authenticate result (lockout increment / reset).
- Forgot password: `fief/apps/auth/routers/reset.py:26` → enumeration parity already present; we add rate limiting only.
- Register: `fief/apps/auth/routers/register.py:40` → currently leaks "email already exists" at lines 89-93. Add rate limiting; flip to silent-on-collision behind a settings flag.
- Verify-email: `fief/apps/auth/routers/auth.py:318`. Add rate limiting on the code-submit path.
- MFA challenges: `fief/apps/auth/routers/auth.py:498, 607` (T14 of MFA-1). Add per-IP rate limit on top of existing per-LoginSession lockout.
- Redis: `fief/tasks/base.py:36` (Dramatiq's RedisBroker URL via `settings.redis_url` at `settings_class.py:78`). The `redis` Python lib is transitively pulled by `dramatiq[redis]` but we'll declare it explicitly with a version pin and use `redis.asyncio`.
- Audit log: `fief/models/audit_log.py:13`. Five new enum values get added (mirror MFA-1's pattern).

## Prerequisites
- `redis >= 5.0` declared explicitly in `pyproject.toml` (we use `redis.asyncio.Redis`); already transitively present via `dramatiq[redis]`.
- `fakeredis >= 2.20` in dev dependencies for tests (in-memory Redis substitute).
- `REDIS_URL` env var already provisioned in production (Dramatiq depends on it). No new secrets.

## Dependency Graph

```
Wave 1 (Foundation) — parallel
  T1 deps          T2 settings          T3 audit-log enum

Wave 2 (Schema + clients + helpers) — parallel
  T4 alembic       T5 UserLockout    T6 redis client    T7 get_client_ip
  migration        SQLAlchemy model  dependency         dependency
       │           │                 │                  │
       └────┬──────┘                 │                  │
            ↓                        │                  │
Wave 3 (Repos + services) — parallel
  T8 UserLockoutRepository (T5)
  T9 RateLimiter service (T1, T6)
  T10 AccountLockoutService (T8)

Wave 4a (Route wiring — different files, parallel)
  T11 /login wiring (T9, T10, T7)
  T12 /forgot-password rate limit (T9, T7)
  T13 /register rate limit + silent-on-collision flag (T9, T7, T2)

Wave 4b (Route wiring — same file as T11; sequential)
  T14 /verify-email + /mfa challenge rate limits (T9, T7) — sequential after T11

Wave 5 (Admin)
  T15 POST /api/users/{id}/unlock endpoint (T10)
  T16 Admin "Unlock account" UI button (T15)

Wave 6 (Cross-cutting)
  T17 Audit log call sites (T3, T11-T16)
  T18 User-visible 429 copy in form helper / templates (T11-T14)

Wave 7 (Tests) — parallel
  T19 Unit: RateLimiter (T9)
  T20 Unit: AccountLockoutService (T10)
  T21 Integration: /login rate-limit + lockout ladder + parity (T11, T17, T18)
  T22 Integration: /forgot, /register, /verify rate limits (T12, T13, T14)
  T23 Integration: admin unlock + audit (T15, T16)

Wave 8 (Rollout)
  T24 Dev rollout (T19-T23)
  T25 Production rollout (T24)
```

## Tasks

### T1: Add Python dependencies
- **depends_on:** []
- **location:** `pyproject.toml`
- **description:** Pin `redis >= 5.0` (for `redis.asyncio.Redis`) and add `fakeredis >= 2.20` to dev deps. `redis` is already transitively present via `dramatiq[redis] == 1.17.x`; the explicit pin documents the dependency and lets dependabot track it. `fakeredis 2.20+` ships `fakeredis.aioredis.FakeRedis` which is API-compatible with `redis.asyncio.Redis`, so test fixtures can drop it in via `app.dependency_overrides[get_redis]`.
- **validation:** `python -c "import redis.asyncio; import fakeredis; print('ok')"` in the local venv.
- **reason_not_testable:** configuration; verified by import smoke
- **status:** Completed
- **log:**
  - 2026-05-09: Added `redis >=5.0` to `[project].dependencies` (alphabetically between `pyotp` and `segno`). Added `fakeredis>=2.20` to `[tool.hatch.envs.default].dependencies` (alphabetically between `coverage[toml]` and `gevent`). Verified via temp venv: `python -c "import redis.asyncio; import fakeredis.aioredis; print('ok')"` → `ok`.
- **files edited/created:**
  - `pyproject.toml` (modified)

### T2: Settings — rate limit toggles + register collision flag
- **depends_on:** []
- **location:** `fief/settings_class.py`
- **description:** Add the following fields:
  - `rate_limit_enabled: bool = True`
  - `rate_limit_login_per_ip_per_min: int = 30`
  - `rate_limit_login_per_email_per_min: int = 10`
  - `rate_limit_forgot_per_ip_per_min: int = 10`
  - `rate_limit_forgot_per_email_per_hour: int = 3`
  - `rate_limit_register_per_ip_per_min: int = 5`
  - `rate_limit_verify_per_ip_per_min: int = 30`
  - `rate_limit_verify_per_email_per_5min: int = 10`
  - `rate_limit_mfa_per_ip_per_min: int = 30`
  - `register_silent_on_email_collision: bool = True` (production default; dev/staging should override to `false` for clearer dev UX)
  - `auth_failure_min_latency_ms: int = 150` (the artificial latency floor on login-failure paths to make timing analysis useless)

  No startup validator needed; defaults are safe.
- **validation:** App boots; `from fief.settings import settings; assert settings.rate_limit_enabled` works.
- **status:** Completed
- **log:**
  - 2026-05-09: Added 12 SEC-1 settings (9 rate-limit windows, register silent-on-collision flag, auth failure latency floor, trusted_proxy_count) to `fief/settings_class.py`. Grouped into a "Rate limiting" block followed by an "Enumeration / timing hardening" block, both placed after the MFA-1 block and before `branding`. Defaults match the spec exactly. No startup validator added (defaults are safe).
  - Added `trusted_proxy_count: int = 1` to this task's diff per T7's note (T7's `get_client_ip` dependency reads it).
  - TDD: wrote `tests/test_settings_sec1.py` first (43 cases via parametrize), confirmed RED (32 fails before impl), then GREEN (43 passed) after the impl. `tests/test_settings_mfa.py` still passes (no regression).
- **files edited/created:**
  - `fief/settings_class.py` (added SEC-1 fields)
  - `tests/test_settings_sec1.py` (new; 43 parametrized assertions)

### T3: Audit-log enum additions
- **depends_on:** []
- **location:** `fief/models/audit_log.py`
- **description:** Add `USER_LOGIN_FAILED` (every wrong-password attempt), `USER_RATE_LIMIT_EXCEEDED` (any throttled endpoint hit), `USER_ACCOUNT_LOCKED` (lockout triggered), `USER_ACCOUNT_AUTO_UNLOCKED` (lockout duration elapsed and the account self-unlocked on next attempt), `USER_ACCOUNT_ADMIN_UNLOCKED` (admin clicked the unlock button). Keep value strings the same as the names.
- **validation:** `from fief.models.audit_log import AuditLogMessage; assert AuditLogMessage.USER_RATE_LIMIT_EXCEEDED`.
- **status:** Completed
- **reason_not_testable:** enum-only addition; verified by import smoke + existing audit-log tests passing.
- **log:** 2026-05-09 — Added the five new `USER_*` members to `AuditLogMessage` in the existing `USER_*` block, immediately after `USER_MFA_STATE_INCONSISTENT` and before `OAUTH_PROVIDER_USER_ACCESS_TOKEN_GET`. Names mirror values exactly (StrEnum convention, matching the MFA-1 style). Smoke check via `.venv/bin/python` printed all five members: `['USER_LOGIN_FAILED', 'USER_RATE_LIMIT_EXCEEDED', 'USER_ACCOUNT_LOCKED', 'USER_ACCOUNT_AUTO_UNLOCKED', 'USER_ACCOUNT_ADMIN_UNLOCKED']`.
- **files edited/created:** `fief/models/audit_log.py`

### T4: Alembic migration — fief_user_lockouts table
- **depends_on:** []
- **location:** `fief/alembic/versions/2026-05-09c_add_user_lockouts.py` (new)
- **description:**
  - `revision = "<new 12-char hex>"`, `down_revision = "a1b2c3d4e5f6"` (the MFA-1 email seeds head).
  - Schema:
    ```
    CREATE TABLE fief_user_lockouts (
      user_id        UUID PRIMARY KEY REFERENCES fief_users(id) ON DELETE CASCADE,
      failed_count   INTEGER NOT NULL DEFAULT 0,
      locked_until   TIMESTAMPTZ NULL,
      created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX ix_fief_user_lockouts_locked_until ON fief_user_lockouts(locked_until);
    ```
  - `down()` reverses cleanly.
  - Use the table-prefix codemod placeholder pattern (read `fief/alembic/versions/2026-05-09_add_mfa_tables_and_columns.py` for the style — it's the closest recent reference).
  - **Concurrency:** the `ON DELETE CASCADE` clause makes lockout rows self-clean on user deletion; no explicit cleanup task or scheduled sweep needed.
- **validation:** `python -c "import importlib.util; spec = importlib.util.spec_from_file_location('m', 'fief/alembic/versions/2026-05-09c_add_user_lockouts.py'); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print(m.revision, m.down_revision)"`. If a dev DB is available: `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`.
- **status:** Completed
- **reason_not_testable:** SQL DDL migration; verified by alembic head check + parser run.
- **log:**
  - 2026-05-09 — Created migration `revision = "b400430e70fc"`, `down_revision = "a1b2c3d4e5f6"`. Schema matches T4 spec: `fief_user_lockouts(user_id PK FK→fief_users(id) ON DELETE CASCADE, failed_count INTEGER NOT NULL DEFAULT 0, locked_until TIMESTAMPTZ NULL, created_at/updated_at TIMESTAMPTZ NOT NULL DEFAULT now())` + `ix_fief_user_lockouts_locked_until` index. Uses the table-prefix codemod placeholder pattern (`op.get_context().opts["table_prefix"]` + f-strings) per the MFA-1 T5 reference. No SQLite batch_alter_table branch needed: `create_table` + `create_index` are cross-dialect on their own; the MFA-1 batch branch was only required there for the FK-add ALTER. Parser run prints `b400430e70fc a1b2c3d4e5f6`. `alembic -c fief/alembic.ini heads` reports `b400430e70fc (head)` — single linear head as expected. Live up/down/up cycle deferred to T24 (this venv lacks `sqlalchemy_utils` so `alembic current` against a real DB cannot run here; `alembic heads` does not import the env).
- **files edited/created:**
  - `fief/alembic/versions/2026-05-09c_add_user_lockouts.py` (new)

### T5: SQLAlchemy model — UserLockout
- **depends_on:** []
- **location:** `fief/models/user_lockout.py` (new), `fief/models/__init__.py` (add import)
- **description:** Single declarative model matching T4's schema. Use `UUIDModel` + `CreatedUpdatedAt` mixins. PK is `user_id` (not a synthetic UUID — there's exactly one lockout row per user). Relationship: `user = relationship("User", back_populates="lockout")`.
  **DO NOT touch `fief/models/user.py`** — file ownership boundary; T6 (which doesn't touch user.py either) and the future tasks that DO touch user.py will add the back-relationship via a follow-up edit. **Actually wait** — there's no separate task touching user.py here, so add `lockout` relationship to `User` in this same task as a small contained edit.
- **validation:** `from fief.models import UserLockout; assert UserLockout.__tablename__.endswith('user_lockouts')`. Mapper `configure_mappers()` runs without warnings.
- **status:** Completed
- **log:**
  - 2026-05-09: Implemented `UserLockout` model with `CreatedUpdatedAt` mixin only (no synthetic `id` column from `UUIDModel`); `user_id` is the primary key + FK to `users.id` `ON DELETE CASCADE`. Columns: `failed_count INTEGER NOT NULL DEFAULT 0` (with `server_default="0"` so direct SQL inserts also default), `locked_until TIMESTAMPTZ NULL` indexed (matches T4's `ix_fief_user_lockouts_locked_until`). Added string-based `user = relationship("User", back_populates="lockout")` to keep import order decoupled. On the `User` side, added `lockout: Mapped["UserLockout | None"]` relationship next to `mfa_recovery_codes` with `uselist=False, cascade="all, delete-orphan"` and a `TYPE_CHECKING` import for `UserLockout`. Exported `UserLockout` from `fief.models` (alphabetical between `UserFieldValue` and `UserMfaRecoveryCode`). TDD: wrote 9 tests in `tests/models/test_user_lockout_model.py` covering import, tablename suffix, default `failed_count=0`, nullable `locked_until`, single-column `user_id` primary key, FK ondelete CASCADE to `users`, presence of `created_at`/`updated_at`, `User.lockout` relationship metadata (uselist=False, delete-orphan cascade), and `UserLockout.user` back-population. RED first (ImportError on `from fief.models import UserLockout`), then GREEN: 9/9 pass; full `tests/models/` suite still 17/17 green; `configure_mappers()` runs without warnings.
- **files edited/created:**
  - `fief/models/user_lockout.py` (new)
  - `fief/models/__init__.py` (modified — added import + `__all__` entry)
  - `fief/models/user.py` (modified — added `lockout` relationship + `TYPE_CHECKING` import)
  - `tests/models/test_user_lockout_model.py` (new)

### T6: Redis async client dependency
- **depends_on:** []
- **location:** `fief/dependencies/redis.py` (new)
- **description:**
  - Module-level singleton `redis.asyncio.Redis.from_url(settings.redis_url, decode_responses=False)` created lazily.
  - FastAPI dependency `get_redis() -> redis.asyncio.Redis` that returns the singleton.
  - On app shutdown, close the connection pool. Hook into the existing lifespan in `fief/lifespan.py`.
  - Tests: provide a fakeredis-backed override via the existing `app.dependency_overrides` test pattern (see `tests/conftest.py:285`).
- **validation:** `python -c "from fief.dependencies.redis import get_redis; print('ok')"`.
- **status:** Completed
- **log:** 2026-05-09 — Implemented lazy singleton (`_client`) with `_build_client()` factored out so tests can patch the constructor without monkey-patching `redis.asyncio` itself. `decode_responses=False` is explicit because the rate-limit ZADD members and lockout payloads are binary. The singleton is intentionally separate from the dramatiq `RedisBroker` in `fief/tasks/base.py` (different connection pool, different sizing concerns). `close_redis()` clears the singleton *before* awaiting `aclose()` so a concurrent `get_redis()` cannot hand out an in-flight-closing client; it is a no-op when the pool was never built (defensive against startup-aborted shutdowns). Wired `close_redis()` into `fief/lifespan.py` after `main_engine.dispose()` so any draining request still has Redis available during SQL teardown. Tests cover: clean import, singleton identity, close-then-rebuild, close-when-uninitialized no-op, and `fakeredis.aioredis.FakeRedis` constructibility (the override pattern). 5/5 pass. Plan validation `python -c "from fief.dependencies.redis import get_redis; print('ok')"` returns `ok`.
- **files edited/created:**
  - `fief/dependencies/redis.py` (new)
  - `fief/lifespan.py` (modified — added `close_redis` import + shutdown call)
  - `tests/dependencies/__init__.py` (new package marker)
  - `tests/dependencies/test_redis_smoke.py` (new)

### T7: get_client_ip dependency
- **depends_on:** []
- **location:** `fief/dependencies/client_ip.py` (new)
- **description:** Expose **two** values, since audit logging needs forensic precision but rate-limit keys need /64 collapse for IPv6.

  ```python
  @dataclass(frozen=True)
  class ClientIpInfo:
      raw: str           # exact IP from XFF or request.client.host — for audit logs
      rate_limit_key: str  # IPv6 collapsed to /64; IPv4 unchanged — for rate-limit buckets

  def get_client_ip_info(request: Request) -> ClientIpInfo: ...
  def get_client_ip(request: Request) -> str:  # back-compat shim → returns .raw
      return get_client_ip_info(request).raw
  ```
  - Resolution order:
    1. If `settings.trusted_proxy_count > 0` (new field; default `1` since DOKS LB sits in front), trust `X-Forwarded-For` and take the **N-from-rightmost** entry where N = `trusted_proxy_count` (the last one is the one our LB injected; further-right are the upstream hops we trust).
    2. Else fall back to `request.client.host`.
  - `rate_limit_key`: for IPv6 compute `ipaddress.IPv6Network(f"{ip}/64", strict=False).network_address` (so an attacker can't rotate through their /128). For IPv4, return as-is.
  - Add `trusted_proxy_count: int = 1` to settings (in T2's diff). The fief deployment is behind a single ingress LB, so 1 is correct. If the deployment ever moves behind Cloudflare or a second LB tier this needs to grow — flagged in "Open questions deferred".
- **validation:** Unit-test with a stub `Request`: forwarded-for, no header (uses client.host), IPv6 with /64 collapse, IPv4 unchanged.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T8: UserLockoutRepository
- **depends_on:** [T5]
- **location:** `fief/repositories/user_lockout.py` (new), `fief/repositories/__init__.py` (export)
- **description:** Standard `BaseRepository`-derived. Methods:
  - `async get_by_user_id(user_id) -> UserLockout | None`
  - `async upsert(user_id, *, failed_count, locked_until) -> UserLockout` (creates or updates)
  - `async increment_and_apply_ladder(user_id) -> UserLockout` — read-then-write inside a single transaction. Read current row (or insert with failed_count=0 if missing), increment by 1, compute new `locked_until` from the ladder (5→+1m, 10→+5m, 20→+15m, 50→+24h), persist. **Race tolerance:** under concurrent failed-login bursts the read-then-write may double-increment; we accept this because the result (account locks slightly faster) is in the correct direction. Avoiding it would require a row-level advisory lock or `SELECT ... FOR UPDATE`, which adds complexity for negligible benefit.
  - `async clear(user_id)` — set failed_count=0 and locked_until=null.
- **validation:** Smoke test verifies the methods exist with correct signatures.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T9: RateLimiter service (Redis sliding-window log)
- **depends_on:** [T1, T6]
- **location:** `fief/services/security/rate_limiter.py` (new)
- **description:**
  ```python
  class RateLimitExceeded(Exception):
      def __init__(self, retry_after_seconds: int): ...

  @dataclass
  class RateLimitWindow:
      max_count: int
      per_seconds: int

  class RateLimiter:
      def __init__(self, redis: Redis): ...

      async def check(
          self,
          *,
          scope: str,        # e.g. "login_ip", "login_email"
          key: str,          # the IP or email
          window: RateLimitWindow,
      ) -> int:
          """
          Sliding window log via Redis sorted set. Returns the post-increment
          count. Raises RateLimitExceeded(retry_after_seconds) if count >
          window.max_count.

          Implementation:
            - bucket_key = f"rl:{{scope}}:{{key}}"
            - now = time.time()
            - ZREMRANGEBYSCORE bucket_key 0 (now - window.per_seconds)
            - ZADD bucket_key now <random-uuid>
            - ZCARD bucket_key
            - EXPIRE bucket_key window.per_seconds
            - Pipeline these into one MULTI/EXEC for atomicity.
          """
  ```
  Use `redis.asyncio.Redis.pipeline(transaction=True)`. The per-bucket EXPIRE keeps idle buckets from leaking memory.

  **Fail-open on Redis errors.** Wrap the pipeline in `try/except redis.RedisError`. On exception:
  - Log a structured warning with `scope`, `key` (hashed for emails — see T17), and the exception class name.
  - Increment counter `rate_limiter.fail_open` (or equivalent metric).
  - Return `0` (under-limit) so the request proceeds.

  Rationale: the whole point of rate limits is bot mitigation; locking everyone out on a Redis blip is a worse outcome than the temporary attack window. Same logic as Auth0/Cloudflare's published patterns.

  **Key namespace.** Use `rl:` prefix exclusively. Dramatiq uses `dramatiq:*`; no collision. `rl:` is reserved for SEC-1's RateLimiter — future security features should pick their own prefix.
- **validation:** Unit tests cover: under-limit case, over-limit case, sliding-window correctness (entries past `per_seconds` don't count), bucket TTL applied, Redis-down → fail-open returns 0. Use fakeredis.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T10: AccountLockoutService
- **depends_on:** [T8]
- **location:** `fief/services/security/account_lockout.py` (new)
- **description:**
  ```python
  class AccountLocked(Exception):
      def __init__(self, retry_after_seconds: int): ...

  class AccountLockoutService:
      LADDER = [(5, timedelta(minutes=1)), (10, timedelta(minutes=5)),
                (20, timedelta(minutes=15)), (50, timedelta(hours=24))]

      def __init__(
          self,
          repo: UserLockoutRepository,
          audit_logger: AuditLogger,
      ): ...

      async def check_locked(self, user: User) -> None:
          """Raise AccountLocked if user has an active lockout. Auto-unlock
          + audit USER_ACCOUNT_AUTO_UNLOCKED if locked_until <= now()."""

      async def record_failed(self, user: User) -> None:
          """Increment counter. If count crosses a ladder threshold, set
          locked_until and audit USER_ACCOUNT_LOCKED."""

      async def reset(self, user: User) -> None:
          """Clear failed_count + locked_until. Called on successful login
          AND on password reset (T11 wires the latter)."""
  ```
- **validation:** Unit tests cover: ladder boundary behavior (4 fails → no lock; 5th → 1 min; 9th → still 5 min; 10th → 5 min; etc.), auto-unlock path, reset path, audit emission.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T11: /login route — rate limit + lockout + latency floor
- **depends_on:** [T9, T10, T7, T2]
- **location:** `fief/apps/auth/routers/auth.py` (the `login` POST handler at line ~168)
- **description:**
  Insert the following pipeline AROUND the existing `user_manager.authenticate` call:

  **Email normalization (used by both rate-limit key and lockout lookup):**
  ```python
  email_normalized = form.email.data.strip().lower()
  ```
  `UserManager.authenticate` already normalizes case-insensitively at the DB level, so this `email_normalized` is purely for our own keys / log records — making sure `Foo@x.com` and `foo@x.com` hit the same bucket and the same lockout row.

  **IP info:** the dependency from T7 returns `ClientIpInfo` with both `.raw` (for audit) and `.rate_limit_key` (IPv6 collapsed to /64).

  1. **Pre-authenticate gates:**
     - `rate_limiter.check(scope="login_ip", key=ip_info.rate_limit_key, window=RateLimitWindow(settings.rate_limit_login_per_ip_per_min, 60))`
     - `rate_limiter.check(scope="login_email", key=email_normalized, window=RateLimitWindow(settings.rate_limit_login_per_email_per_min, 60))`
     - On `RateLimitExceeded`: audit `USER_RATE_LIMIT_EXCEEDED`. Return the SAME generic 401 "Invalid email or password" form error the bad-credentials path returns (do NOT differentiate). Set `Retry-After` header for HTTP-aware clients.
     - Lookup user by email (without revealing existence to the response). If user exists: `account_lockout.check_locked(user)`. On `AccountLocked`: audit `USER_RATE_LIMIT_EXCEEDED` (treat lockout as a rate-limit equivalent for telemetry parity). Return the same generic 401.
  2. **authenticate path** (unchanged): existing call returns `User | None`.
  3. **Post-authenticate:**
     - On `None` (or constant-time fall-through): if user existed, `await account_lockout.record_failed(user)` (which may set lockout). Audit `USER_LOGIN_FAILED`. Floor wall-clock latency to `settings.auth_failure_min_latency_ms` (track start time at top of handler; sleep diff if positive). Then return existing 401.
     - On valid user: `await account_lockout.reset(user)` (clears failed_count). Continue with existing MFA branch / session rotation.
  4. **Inject deps:** add `client_ip: str = Depends(get_client_ip)`, `rate_limiter: RateLimiter = Depends(get_rate_limiter)`, `account_lockout: AccountLockoutService = Depends(get_account_lockout_service)`. Add factories in `fief/dependencies/security.py` next to existing `get_totp_service`.
  5. **Settings toggle:** if `settings.rate_limit_enabled is False`, all calls to `rate_limiter.check` and `account_lockout.check_locked / record_failed` are no-ops. Wrap in a small `if settings.rate_limit_enabled:` guard, or have the dependency factories return a `NoOpRateLimiter` when disabled.
- **validation:** Integration tests in T21.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T12: /forgot-password rate limit
- **depends_on:** [T9, T7, T2]
- **location:** `fief/apps/auth/routers/reset.py` (the `forgot_password` POST handler at line ~26)
- **description:** Wrap the existing handler with two rate-limit checks:
  - `rate_limiter.check(scope="forgot_ip", key=client_ip, window=RateLimitWindow(settings.rate_limit_forgot_per_ip_per_min, 60))`
  - `rate_limiter.check(scope="forgot_email", key=email_normalized, window=RateLimitWindow(settings.rate_limit_forgot_per_email_per_hour, 3600))`
  - On `RateLimitExceeded`: audit + return the SAME 202 "If that email exists..." response the existing handler returns. Do NOT change the response shape — the existing parity is good. The only difference under throttle is the user gets the "Check your inbox..." message even though we did nothing. (Or, if we want to be slightly more honest in logs, return 429 internally but render the same 202 page; recommend keeping 202 for caller parity, and use the audit log for telemetry.)
- **validation:** Integration test in T22 hammers /forgot-password, asserts no enumeration leak and 202 throughout.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T13: /register rate limit + silent-on-collision flag
- **depends_on:** [T9, T7, T2]
- **location:** `fief/apps/auth/routers/register.py` (the `register` POST handler at line ~40)
- **description:**
  - Per-IP rate limit: `rate_limiter.check(scope="register_ip", key=client_ip, window=RateLimitWindow(settings.rate_limit_register_per_ip_per_min, 60))` at the top of the handler. On `RateLimitExceeded`: return the 422 / form-error response shape the existing flow uses for any validation error, with copy "Too many requests. Please try again later." (or the same generic copy as a normal validation error if we want stricter parity).
  - **Silent-on-collision behaviour:** when `settings.register_silent_on_email_collision is True` AND the email-already-exists branch fires (lines 89-93 of `register.py`):
    - Do NOT return the 422 with `error_code="user_already_exists"`.
    - Instead, mimic the success path: enqueue a "your account already exists at this email — was that you? sign in or reset your password" email (use the existing forgot-password / welcome email infrastructure — add a new template type if needed), and return the same "We've sent you a verification email — check your inbox" 202/page that a fresh registration would show.
    - This requires adding `EmailTemplateType.REGISTER_DUPLICATE` (or reusing `FORGOT_PASSWORD` with a tweaked context). Recommend a new template type for clarity.
  - When `settings.register_silent_on_email_collision is False` (dev): existing behaviour preserved.
  - **Note:** The new email template + dramatiq actor are subordinate to T13. The full email flow can be a follow-up; for v1, the "silent" path can simply not send the email and just render the success page. Document the gap.
- **validation:** Integration test in T22.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T14: /verify-email and /mfa challenge route rate limits
- **depends_on:** [T9, T7, T2, T11]
- **location:** `fief/apps/auth/routers/auth.py` (verify-email handler at line ~318; /mfa/totp at ~498; /mfa/recover at ~607)
- **description:** Add rate limits to three POST handlers, all in `auth.py` (sequential after T11 to avoid file-merge conflicts on the same module):
  - **`/verify-email` (POST):** per-IP at 30/min, per-email at 10/5min. Identifier is the email of the LoginSession's pending user. On `RateLimitExceeded`: audit + return the same generic 401/form-error the bad-code path returns. Do NOT reveal whether the code was for a known account.
  - **`/mfa/totp` (POST verify):** per-IP at 30/min. The existing per-LoginSession `mfa_attempts_count` lockout from MFA-1 stays as-is. SEC-1 layer is just per-IP throttling to slow distributed attacks against a known session.
  - **`/mfa/recover` (POST):** per-IP at 5/10min, per-email at 3/hour. (Recovery codes are precious; lock them down hard.)
  - **MFA failure does NOT count toward SEC-1 account lockout.** A user who lost their phone shouldn't have their account locked out by SEC-1 on top of MFA-1's session-bound counter — they'd be unable to use a recovery code without first triggering an admin unlock. SEC-1's `account_lockout.record_failed` fires only on bad-password attempts in T11; MFA failures are handled by MFA-1's per-LoginSession counter alone. Document this explicitly in code comments at each call site.
  - All `RateLimitExceeded` responses return the same shape as the existing failure path (form re-rendered with generic invalid-code error). Audit in all cases.
- **validation:** Integration tests in T22.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T15: Admin "Unlock account" API endpoint
- **depends_on:** [T10]
- **location:** `fief/apps/api/routers/users.py` (next to T21 of MFA-1's `mfa/reset` endpoint)
- **description:**
  ```
  POST /api/users/{id}/unlock
  ```
  - Admin-only (existing `is_authenticated_admin_api` router-level dep).
  - Look up user by id; 404 if not found.
  - Call `await account_lockout.reset(user)` (clears failed_count + locked_until).
  - Audit `USER_ACCOUNT_ADMIN_UNLOCKED` with `extra={"admin_user_id": ...}`.
  - Return 204 No Content. Idempotent (calling on a non-locked user is fine and still audited).
- **validation:** Integration test in T23.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T16: Admin "Unlock account" UI button
- **depends_on:** [T15]
- **location:** the admin user-detail / user-edit page in `fief/templates/admin/users/...` (find the right file)
- **description:** Add a button on the user detail page labelled "Unlock account" (only visible when `user.lockout` exists with `failed_count > 0` or `locked_until` in the future). Button POSTs to `/api/users/{id}/unlock` via htmx. Show success flash on response.
  - Match the existing admin button style.
  - Defensive UX: confirm dialog ("Reset this user's failed login counter and clear any active lockout?").
- **validation:** Manual: visit admin user page for a locked user, click button, confirm flash + counter reset.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T17: Audit log call sites
- **depends_on:** [T3, T11, T12, T13, T14, T15]
- **description:** Verify the audit log entries are emitted at the right call sites and the `extra` payloads are useful:
  - `USER_LOGIN_FAILED`: emitted in T11 on every wrong-password attempt. `extra={"email": email_normalized, "client_ip": ip_info.raw}`. **Email is NOT hashed here** — full forensic value is the point of this entry, and it's behind the existing audit-log access control. Use `ip_info.raw` (not the /64-collapsed key) so support sees exact origin.
  - `USER_RATE_LIMIT_EXCEEDED`: emitted in T11/T12/T13/T14 whenever a `RateLimitExceeded` is raised. `extra={"scope": scope, "key_hash": _hash_key(key), "endpoint": endpoint, "client_ip": ip_info.raw}`. **The `key_hash` field replaces the raw `key`** to avoid email or IP leaks at the audit level for the bucket id. Use:
    ```python
    def _hash_key(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    ```
    Same hash for emails and IPv6/64 keys; deterministic so support can correlate two log lines reporting the same bucket without ever seeing the raw email.
  - `USER_ACCOUNT_LOCKED`: emitted in T10 on ladder-threshold cross. `extra={"failed_count": n, "locked_until": ts.isoformat()}`. (`subject_user_id` already identifies the account, so no email field needed.)
  - `USER_ACCOUNT_AUTO_UNLOCKED`: emitted in T10 when an expired lockout is hit on the next attempt.
  - `USER_ACCOUNT_ADMIN_UNLOCKED`: emitted in T15. `extra={"admin_user_id": ...}`.
- **validation:** All five audit messages observed in integration tests T21/T22/T23. Tests assert `extra.key_hash` matches `_hash_key(known_key)` and that no raw email appears in `USER_RATE_LIMIT_EXCEEDED` rows.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T18: User-facing 429 / lockout copy
- **depends_on:** [T11, T12, T13, T14]
- **description:** Audit the user-visible copy on every throttled path. We DO NOT show "you are rate-limited" (that's an attacker oracle). Instead:
  - `/login` rate-limited or locked: same form-error "Invalid email or password" the existing bad-credentials path renders.
  - `/forgot-password` rate-limited: same 202 "If that email exists..." page.
  - `/register` rate-limited: form error "Something went wrong. Please try again." (deliberately vague).
  - `/verify-email` rate-limited: same as bad-code error.
  - `/mfa/totp` and `/mfa/recover`: same as bad-code error.
  - All responses set `Retry-After` header for clients that respect it (browsers don't, but APIs and our own SDKs might). Browsers ignore it on form posts → fine.
  - Add no new templates; this is a copy + header audit task.
- **validation:** Integration tests T21/T22 assert the response body never contains the words "rate", "limit", "throttle", "lockout" on any throttled path.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T19: Unit tests — RateLimiter
- **depends_on:** [T9]
- **location:** `tests/services/test_rate_limiter.py` (new)
- **description:**
  - Use `fakeredis.aioredis.FakeRedis` for the Redis dep.
  - Cases:
    - Under limit → returns count, no exception.
    - At limit → returns count, no exception.
    - Over limit → raises `RateLimitExceeded(retry_after_seconds)`.
    - Sliding window: 1 request at t=0, advance fakeredis time, 1 request at t=window+1 → first is gone, second sees count=1.
    - Bucket TTL: confirm `EXPIRE` is set so idle buckets don't accumulate.
    - Two different `(scope, key)` tuples are independent.
- **validation:** `pytest tests/services/test_rate_limiter.py` green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T20: Unit tests — AccountLockoutService
- **depends_on:** [T10]
- **location:** `tests/services/test_account_lockout.py` (new)
- **description:** In-memory fake repo. Cases:
  - 4 fails → `check_locked` no-op, no `locked_until` set.
  - 5th fail → ladder triggers `locked_until = now + 1 min`. Audit `USER_ACCOUNT_LOCKED`.
  - During the 1 min: `check_locked` raises `AccountLocked(retry_after_seconds)`.
  - At 1 min + 1s, on next `check_locked`: auto-unlocks (clears `locked_until`, NOT `failed_count`), audits `USER_ACCOUNT_AUTO_UNLOCKED`.
  - 10th fail → `now + 5 min`. 20th → 15 min. 50th → 24 h.
  - `reset` clears both fields.
- **validation:** `pytest tests/services/test_account_lockout.py` green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T21: Integration tests — /login rate limit, lockout, parity
- **depends_on:** [T11, T17, T18]
- **location:** `tests/apps/auth/routers/test_login_security.py` (new)
- **description:**
  - Exceed per-IP limit on /login: 30 attempts/min, 31st gets 401 with generic body. No "rate limit" leakage in body.
  - Exceed per-email limit: 10 attempts/min for one email from different IPs, 11th gets 401.
  - 5 wrong attempts on a real user → user.lockout.locked_until set, 6th attempt 401 (no leak), wait 1 min, retry succeeds with correct password.
  - Successful login resets the failed counter.
  - Wrong-password latency floor: assert response time on a wrong-password ≥ ~150ms (with a small tolerance).
  - Audit log entries observed for `USER_LOGIN_FAILED`, `USER_ACCOUNT_LOCKED`, `USER_ACCOUNT_AUTO_UNLOCKED`, `USER_RATE_LIMIT_EXCEEDED`.
- **validation:** Tests green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T22: Integration tests — /forgot, /register, /verify, /mfa rate limits
- **depends_on:** [T12, T13, T14]
- **location:** `tests/apps/auth/routers/test_forgot_register_verify_security.py` (new)
- **description:**
  - /forgot: hammer past per-IP and per-email limits, assert 202 always, no enumeration leak.
  - /register: per-IP exceeded → form error, no leak. Email collision with `register_silent_on_email_collision=True` → success page (no error). With flag false → existing 422 user_already_exists.
  - /verify-email: per-IP and per-email rate limits.
  - /mfa/totp POST and /mfa/recover POST: per-IP limit interacts with the existing per-LoginSession lockout (MFA-1) without conflict.
- **validation:** Tests green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T23: Integration tests — admin unlock + audit
- **depends_on:** [T15, T16]
- **location:** `tests/apps/api/routers/test_users_unlock.py` (new)
- **description:**
  - Admin unlock on a locked user: 204, lockout cleared, audit `USER_ACCOUNT_ADMIN_UNLOCKED` emitted.
  - Admin unlock on a non-locked user: 204, idempotent, audit still emitted.
  - Non-admin unlock attempt: 401.
  - Unknown user id: 404.
- **validation:** Tests green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T24: Dev rollout
- **depends_on:** [T19, T20, T21, T22, T23]
- **description:** Local + dev cluster smoke. Run `alembic upgrade head` (only the new T4 migration). Confirm `redis.asyncio.Redis.from_url(REDIS_URL)` connects. Smoke flow: cause a lockout on a test account by submitting 5 wrong passwords, verify on 6th the response is the same generic error and audit log shows the lockout. Wait 1 min; verify auto-unlock on next attempt. Trigger admin unlock from the admin UI; verify clears state.
- **validation:** All flows pass against dev. No errors in pod logs.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T25: Production rollout
- **depends_on:** [T24]
- **description:** Push the image, watch GHCR build, `kubectl rollout restart deploy/opensensor-fief`. Confirm boot logs show no Redis connection errors. Smoke: try a few wrong logins on a real test account on each brand to verify the lockout ladder; expire lockout; verify recovery. Watch metrics for false-positive lockouts in the first 24h.
- **validation:** Ladder works on all 3 brands; no support tickets about being locked out unjustly in 24h post-deploy.
- **status:** Not Completed
- **log:**
- **files edited/created:**

## Parallel Execution Groups

| Wave | Tasks                       | Notes                                                     |
|------|-----------------------------|-----------------------------------------------------------|
| 1    | T1, T2, T3                  | Foundation; all parallel                                  |
| 2    | T4, T5, T6, T7              | Schema + clients + helpers; all parallel                  |
| 3    | T8, T9, T10                 | Repos + services; T8 needs T5; T9 needs T1+T6; T10 needs T8 |
| 4a   | T11, T12, T13               | Different files (auth.py, reset.py, register.py); parallel. T11 needs T9+T10+T7+T2; T12 needs T9+T7+T2; T13 needs T9+T7+T2.|
| 4b   | T14                         | Same file as T11 (auth.py); sequential after T11. depends_on: T9+T7+T2+T11. |
| 5    | T15, T16                    | T15 first, T16 depends                                    |
| 6    | T17, T18                    | Cross-cutting; both depend on T11-T15                      |
| 7    | T19, T20, T21, T22, T23     | Tests, all parallel                                       |
| 8    | T24 → T25                   | Rollout, sequential                                       |

## Testing strategy
- Unit tests for the two services (RateLimiter, AccountLockoutService) drive correctness with fakeredis + in-memory repo fakes; fast.
- Integration tests use the existing `httpx.AsyncClient` test harness from `tests/conftest.py`. Override `get_redis` with a fakeredis instance via `app.dependency_overrides`.
- Negative paths covered: enumeration leakage in body, latency floor, ladder boundaries, auto-unlock, admin unlock idempotency.
- We deliberately do NOT add a "rate-limit-disabled" toggle in tests — tests pin `rate_limit_enabled=True` and use generous test-only limits via `monkeypatch` on settings.

## Risks & mitigations
- **Real users locked out by tight defaults.** Mitigation: defaults match the PRD's permissive numbers (30 logins/min/IP is enough for a busy office). Watch metrics for first 2 weeks; tune.
- **Redis outage = login fully blocked OR fully open?** Decision: fail-OPEN on Redis errors. The whole point is bot mitigation; locking everyone out on a Redis blip is worse than the temporary attack window. T9 specifies the `try/except redis.RedisError` placement.
- **Trusted proxy count miscounted → IP spoofable.** Mitigation: ingress is a single hop; `trusted_proxy_count=1` is correct. Add a startup log line "Rate limiter: trusting N proxy hops" so misconfiguration is visible.
- **`register_silent_on_email_collision` confuses real users who forgot they had an account.** Mitigation: ship the "your account already exists, want to reset password?" email as a follow-up so users aren't silently dropped. Track adoption via a metric.
- **Audit log volume.** Every `USER_LOGIN_FAILED` is logged. On a credential-stuffing attack at the per-IP cap, that's 30/min/IP. Acceptable; audit log is sized for it.
- **Settings are not hot-reloadable.** Tuning rate limits requires a pod restart. Acceptable for v1; if frequent tuning becomes painful, move limits into a runtime-mutable workspace setting in a follow-up.

## Plan revisions applied from subagent review (2026-05-09)
- **T1** — added note that fakeredis 2.20+ ships an API-compatible `aioredis.FakeRedis`.
- **T4** — explicit note that `ON DELETE CASCADE` handles concurrent user deletion.
- **T7** — split client-IP into `ClientIpInfo(raw, rate_limit_key)` so audit log gets exact IPv6, rate-limit key gets /64 collapse.
- **T8** — explicit choice: read-then-write inside a transaction, accept small race (locks slightly faster, correct direction).
- **T9** — explicit fail-open `try/except redis.RedisError` block; `rl:` namespace reserved.
- **T11** — explicit `email_normalized = form.email.data.strip().lower()` rule; uses `ip_info.rate_limit_key` for buckets, `ip_info.raw` for audit.
- **T12** — added missing `T2` to `depends_on`.
- **T14** — added missing `T2` and `T11` to `depends_on`; explicit decision that MFA failures do NOT trigger SEC-1 account lockout (MFA-1's session counter is the right scope).
- **T17** — explicit `_hash_key()` SHA-256 truncation spec; clarified which fields are hashed (`extra.key_hash`) vs raw (`extra.email` on `USER_LOGIN_FAILED`, `extra.client_ip`).
- **Risks** — added settings-not-hot-reloadable caveat.
- **Open questions** — added Cloudflare multi-hop caveat and the missing register-collision email template follow-up.

## Open questions deferred to implementation
- **Email "account already exists" reminder for the silent-collision path.** T13 v1 renders the success page without sending the user any email. A follow-up should add an `EmailTemplateType.REGISTER_ACCOUNT_EXISTS_HINT` template + Dramatiq actor that sends "Looks like you already have an account; sign in or reset your password" so legit forgetful users aren't silently swallowed.
- **Multi-tier proxy (Cloudflare + DOKS LB).** `trusted_proxy_count: int = 1` is correct for the current single-hop ingress. If we adopt Cloudflare or another fronting CDN, this becomes too coarse — needs a per-deployment override or an explicit "trusted IP CIDR" allowlist.
- **Panic-block on IP-wide abuse.** Whether to add a "single IP exceeding 1000 failures across endpoints in 1h gets a longer auto-block." Defer; if abuse continues post-SEC-1, add as SEC-1.5.
- **`/api/security/lockouts` admin list endpoint** so support can see who is currently locked, without checking each user individually. Not in scope; can be added in the same module if support load justifies it.
