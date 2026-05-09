# Plan: SEC-2 — HIBP breached-password check

**Generated:** 2026-05-09
**Source PRD:** `docs/prds/SEC-2-hibp-breached-password-check.md`
**Decisions locked in:**
- Enabled by default (`breached_password_check_enabled: bool = True`). Existing users keep their accounts; the check only fires when a password is being SET.
- Single integration point: HIBP check runs inside `UserManager.validate_password` (which is **already** `async` at `fief/services/user_manager.py:420`; we are extending its body, not changing its signature). All four password-set surfaces (register, change, reset, admin API) call into it.
- Per-tenant override via new `tenants.breached_password_threshold: int | None` column (null = use the global default of 1; set to e.g. 100 for a tenant that wants leniency).
- Fail-OPEN on HIBP outage / timeout / 429 / non-2xx. The whole point is a layered defence — never lock everyone out of password changes when HIBP blips or rate-limits us.
- 24 h Redis cache via the `bpc:` prefix (mirrors SEC-1's `rl:` namespace pattern). 1 s HTTP timeout. `Add-Padding: true` header per HIBP guidance.
- WTForms-level check is NOT added; the form-side error UX comes through the existing `InvalidPasswordError` machinery (now extended with a typed subclass `BreachedPasswordError` so error handlers can surface a specific copy).
- **Tenant is passed per-call** to `validate_password` — UserManager is NOT tenant-scoped state (`fief/services/user_manager.py:76-96`). Existing call sites in `create()` and `reset_password()` already have `tenant` in scope and pass it. `set_user_attributes()` does NOT take tenant today; we add a `tenant` kwarg and update its callers (auth-app dashboard `update_password`, the admin API).

## Overview
Block users from setting a password that's already in the HaveIBeenPwned password corpus, using the [k-anonymity Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords). The first 5 chars of the SHA-1 hash leave our process; the password and even the full hash never do.

Reference points (from codebase exploration):
- Existing zxcvbn validator: `fief/services/password.py:10-43` (`PasswordValidation.validate()`, sync). HIBP layers AFTER zxcvbn.
- WTForms `PasswordValidator` callable: `fief/forms.py:341-357`. We do NOT add an HIBP WTForms validator — keeping things async-clean.
- The single chokepoint: `fief/services/user_manager.py:431-453` (`set_user_attributes`) which calls `validate_password()`. Both `create()` (line 121) and `set_user_attributes()` (line 447) call it. Making it `async` means all four surfaces get HIBP for free:
  - Register: `fief/apps/auth/forms/register.py` → `user_manager.create()`
  - Change password (dashboard): `fief/apps/auth/routers/dashboard.py:248`
  - Reset password (forgot flow): `fief/services/user_manager.py:269`
  - Admin user create + update: `fief/apps/api/routers/users.py:116, 149`
- Audit log: `fief/models/audit_log.py:13`. Two new enum values get added.
- Redis client: `fief/dependencies/redis.py` (SEC-1 T6). Used for the prefix cache.
- Tenant model: `fief/models/tenant.py:46-48` (close to `mfa_required` from MFA-1). Add `breached_password_threshold` here.
- Settings: `fief/settings_class.py` (the actual class — not the loader at `fief/settings.py`).

## Prerequisites
- `httpx` is already a transitive dependency via `fastapi`; we'll declare it explicitly with a version pin (`httpx >= 0.27`) to use `httpx.AsyncClient` directly for HIBP. No new env vars or secrets — HIBP's range API doesn't require an API key.
- Redis already wired (SEC-1 T6).

## Dependency Graph

```
Wave 1 (Foundation) — parallel
  T1 deps          T2 settings          T3 audit-log enum

Wave 2 (Schema) — parallel
  T4 alembic migration       T5 Tenant.breached_password_threshold

Wave 3 (Service)
  T6 BreachedPasswordChecker (T1, T2, redis from SEC-1)

Wave 4 (Integration)
  T7 UserManager.validate_password → async + HIBP wire (T6)
  T8 Wire HIBP error response into the four password-set form/route handlers (T7)

Wave 5 (Tests) — parallel
  T9 Unit: BreachedPasswordChecker (T6)
  T10 Integration: register / change / reset / admin all reject breached passwords (T7, T8)

Wave 6 (Rollout)
  T11 Dev rollout (T9, T10)
  T12 Production rollout (T11)
```

## Tasks

### T1: Add Python dependencies
- **depends_on:** []
- **location:** `pyproject.toml`
- **description:** Pin `httpx >= 0.27` explicitly in `[project].dependencies`. It's transitively present (FastAPI/respx use it) but the explicit pin documents the use of `httpx.AsyncClient` for HIBP HTTP calls and lets dependabot track it.
- **validation:** `python -c "import httpx; print(httpx.__version__)"` returns ≥0.27.
- **reason_not_testable:** configuration; verified by import smoke
- **status:** Completed
- **log:**
  - 2026-05-09: Inserted `"httpx >=0.27"` alphabetically into `[project].dependencies` (between `furl` and `httpx-oauth`). Smoke `python -c "import httpx; print(httpx.__version__)"` printed `0.28.1` (>=0.27). Committed as `feat(sec-2): pin httpx for HIBP breached-password client`.
- **files edited/created:**
  - `pyproject.toml` (edited)

### T2: Settings — HIBP toggles
- **depends_on:** []
- **location:** `fief/settings_class.py`
- **description:** Add the following fields:
  - `breached_password_check_enabled: bool = True` — global kill switch
  - `breached_password_default_threshold: int = 1` — count ≥ this → reject. `1` = reject any sighting. Used when a tenant has `breached_password_threshold IS NULL`.
  - `breached_password_api_url: str = "https://api.pwnedpasswords.com/range"` — base URL (configurable for tests / proxy)
  - `breached_password_user_agent: str = "opensensor-auth/1.0"` — HIBP requires a non-default UA
  - `breached_password_timeout_ms: int = 1000` — HTTP timeout
  - `breached_password_cache_ttl_s: int = 86400` — Redis cache TTL (24 h)

  No startup validator needed; defaults are safe. The check is enabled by default.
- **validation:** `python -c "from fief.settings import settings; assert settings.breached_password_check_enabled"`.
- **status:** Completed
- **log:**
  - 2026-05-09: Added the six `breached_password_*` fields to `Settings` in `fief/settings_class.py` immediately after the SEC-1 enumeration/timing block, with a doc comment summarising the layered-defence intent, fail-open posture, kill-switch, and Redis `bpc:` cache namespace. Added `tests/test_settings_sec2.py` mirroring the SEC-1 schema test style: parametrised existence / default / annotation checks against `Settings.model_fields`, singleton attribute checks against `fief.settings.settings`, per-field default assertions, and two env-var override smoke tests (`BREACHED_PASSWORD_CHECK_ENABLED=false`, `BREACHED_PASSWORD_DEFAULT_THRESHOLD=100`). RED → 26 failures (no fields). GREEN after the settings edit → `pytest tests/test_settings_sec2.py -o addopts="" --no-cov` reports `26 passed`.
- **files edited/created:**
  - `fief/settings_class.py`
  - `tests/test_settings_sec2.py`

### T3: Audit-log enum additions
- **depends_on:** []
- **location:** `fief/models/audit_log.py`
- **description:** Add to `AuditLogMessage`:
  - `USER_PASSWORD_BREACHED_REJECTED` — emitted when a password-set attempt was rejected because HIBP said it's been seen ≥ threshold times.
  - `USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN` — emitted when the HIBP API errored / timed out and we let the password through (fail-open). Pair with a metric so support can spot a sustained outage.
  Match the prefix style of existing `USER_*` members.
- **validation:** `from fief.models.audit_log import AuditLogMessage; assert AuditLogMessage.USER_PASSWORD_BREACHED_REJECTED`.
- **reason_not_testable:** enum-only addition; verified by import smoke
- **status:** Completed
- **log:**
  - 2026-05-09: Added `USER_PASSWORD_BREACHED_REJECTED` and `USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN` to `AuditLogMessage` after `USER_ACCOUNT_ADMIN_UNLOCKED`, matching the StrEnum name==value style. Smoke `from fief.models.audit_log import AuditLogMessage; print(...)` printed both members.
- **files edited/created:**
  - `fief/models/audit_log.py` (edited)

### T4: Alembic migration — tenants.breached_password_threshold
- **depends_on:** []
- **location:** `fief/alembic/versions/2026-05-09f_add_tenant_breached_password_threshold.py` (new — letter `f` because `e` is already taken by the branding-origin migration)
- **description:**
  - `revision = "<new 12-char hex>"`, `down_revision = "4f8d1c5e2a9b"` (the *current* alembic head, which is `2026-05-09e_add_branding_origin_to_login_sessions.py` — NOT SEC-1's `b400430e70fc`; two later branding migrations shipped between SEC-1 and SEC-2). Pick a fresh hex.
  - `upgrade()`: `ALTER TABLE fief_tenants ADD COLUMN breached_password_threshold INTEGER NULL`. No default needed; null = "use settings.breached_password_default_threshold".
  - `downgrade()` drops the column.
  - Use the `op.get_context().opts["table_prefix"]` codemod placeholder pattern. SQLite branch via `op.batch_alter_table` if needed (mirror prior migrations).
- **validation:** Migration parser run + `alembic heads` shows the new revision as head. Live up/down/up deferred to T11 dev rollout if local DB unavailable.
- **reason_not_testable:** SQL DDL migration; verified by alembic head check + parser run
- **status:** Completed
- **log:**
  - 2026-05-09: Wrote migration `2026-05-09f_add_tenant_breached_password_threshold.py` with `revision = "2efcfe2289f4"` and `down_revision = "4f8d1c5e2a9b"` (current head, the branding-origin migration). `upgrade()` calls `op.add_column(f"{table_prefix}tenants", sa.Column("breached_password_threshold", sa.Integer(), nullable=True))`; `downgrade()` drops it. Mirrors the plain `op.add_column` pattern used by the recent `7c92e1a4d8b1` and `4f8d1c5e2a9b` migrations — no `batch_alter_table` needed for a simple nullable column add. Parser smoke printed `2efcfe2289f4 4f8d1c5e2a9b`. `alembic -c fief/alembic.ini heads` now reports `2efcfe2289f4 (head)`. Live up/down/up deferred to T11 dev rollout. Committed as `feat(sec-2): migration for tenants.breached_password_threshold`.
- **files edited/created:**
  - `fief/alembic/versions/2026-05-09f_add_tenant_breached_password_threshold.py` (created)

### T5: Tenant.breached_password_threshold — model + schema
- **depends_on:** []
- **location:** `fief/models/tenant.py`, `fief/schemas/tenant.py`
- **description:**
  - On `Tenant`: add `breached_password_threshold: Mapped[int | None] = mapped_column(Integer, default=None, nullable=True)`. Place near `mfa_required`.
  - On the read schema (`BaseTenant` or equivalent): expose the field on read.
  - On admin update/create schemas: accept the field.
- **validation:** Admin API GET `/api/tenants/{id}` returns the field; PATCH accepts it; existing tenant rows return null.
- **status:** Completed
- **log:**
  - 2026-05-09: TDD red→green. Added `breached_password_threshold: Mapped[int | None]` (Integer, default=None, nullable=True) on `Tenant` directly after `mfa_required`, and imported `Integer` from sqlalchemy. Exposed `breached_password_threshold: int | None = None` on `BaseTenant` (read), `TenantCreate` (admin create), and `TenantUpdate` (admin update). Wrote `tests/test_tenant_breached_password_threshold.py` mirroring the MFA-1 T7 pattern: 9 cases covering model column default/nullable, attribute round-trip, read-schema serialization (set + None), create/update accept + default-None. All 9 tests pass via `.venv/bin/pytest tests/test_tenant_breached_password_threshold.py -o addopts="" --no-cov`. Committed as `feat(sec-2): tenant.breached_password_threshold + schema exposure`.
- **files edited/created:**
  - `fief/models/tenant.py` (edited)
  - `fief/schemas/tenant.py` (edited)
  - `tests/test_tenant_breached_password_threshold.py` (created)

### T6: BreachedPasswordChecker service
- **depends_on:** [T1, T2]
- **location:** `fief/services/security/breached_passwords.py` (new), `fief/dependencies/security.py` (factory)
- **description:**
  ```python
  class BreachedPasswordChecker:
      """k-anonymity HIBP password check with Redis prefix cache.

      Key namespace: `bpc:<5-char-prefix>` (mirrors SEC-1's `rl:` reservation).
      """

      def __init__(
          self,
          redis: redis.asyncio.Redis,
          http_client: httpx.AsyncClient,
          audit_logger: AuditLogger,
      ): ...

      async def is_breached(self, password: str, tenant: Tenant | None) -> bool:
          """
          Returns True if the password's hash suffix appears in HIBP with a
          count >= the effective threshold (tenant override, else
          settings.breached_password_default_threshold).

          Fail-OPEN on timeout / HTTP RequestError / 429 / any non-2xx /
          malformed response body. Audits USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN
          and returns False so the password is allowed through.
          """
          if not settings.breached_password_check_enabled:
              return False

          sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
          prefix, suffix = sha1[:5], sha1[5:]
          suffixes = await self._fetch_prefix(prefix)
          count = suffixes.get(suffix, 0)
          threshold = (tenant.breached_password_threshold if tenant else None) \
                      or settings.breached_password_default_threshold
          return count >= threshold

      async def _fetch_prefix(self, prefix: str) -> dict[str, int]:
          # 1. Try Redis cache: GET bpc:<prefix>. Returns parsed dict on hit.
          # 2. On miss: GET {settings.breached_password_api_url}/{prefix} with:
          #    - headers={"User-Agent": settings.breached_password_user_agent,
          #               "Add-Padding": "true"}     # HIBP guidance — pads
          #                                           # response so size doesn't
          #                                           # leak prefix popularity.
          #    - timeout=httpx.Timeout(
          #        settings.breached_password_timeout_ms / 1000.0)
          # 3. Treat ANY of the following as fail-open
          #    (return {} → caller sees count=0 → not breached):
          #      - httpx.TimeoutException, httpx.RequestError
          #      - response.status_code == 429       # HIBP rate-limit
          #      - response.status_code >= 500 OR not 2xx
          #      - response body fails to parse as `SUFFIX:COUNT` lines
          #    On each fail-open path, audit
          #    USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN with
          #    extra={"reason": "...", "exc_class": ...} and return {}.
          # 4. On success: parse text body lines `SUFFIX:COUNT` (ignore lines
          #    with count=0 — those are HIBP's padding rows). Build dict.
          # 5. SETEX bpc:<prefix> json.dumps(dict).encode()
          #    ttl=settings.breached_password_cache_ttl_s.
  ```

  Factory in `fief/dependencies/security.py`:
  ```python
  async def get_breached_password_checker(
      redis_client: redis.asyncio.Redis = Depends(get_redis),
      http_client: httpx.AsyncClient = Depends(get_http_client),
      audit_logger: AuditLogger = Depends(get_audit_logger),
  ) -> BreachedPasswordChecker:
      return BreachedPasswordChecker(redis_client, http_client, audit_logger)
  ```

  And a tiny http-client dep in the same file:
  ```python
  _http_client: httpx.AsyncClient | None = None

  def get_http_client() -> httpx.AsyncClient:
      global _http_client
      if _http_client is None:
          _http_client = httpx.AsyncClient(timeout=httpx.Timeout(
              settings.breached_password_timeout_ms / 1000.0
          ))
      return _http_client
  ```
  Add `await _http_client.aclose()` to the lifespan shutdown alongside the existing redis close.
- **validation:** Unit tests in T9.
- **status:** Completed
- **log:**
  - 2026-05-09: TDD red→green. Implemented `BreachedPasswordChecker` at `fief/services/security/breached_passwords.py` per spec: SHA-1 + 5/35 split, Redis prefix cache (`bpc:` namespace), HIBP `Add-Padding: true` header, 1 s timeout, fail-open on `TimeoutException` / `RequestError` / 429 / non-2xx / malformed body — each path emitting `USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN` via `AuditLogger` with a distinct `reason` (`transport_error` / `hibp_rate_limited` / `hibp_non_2xx` / `malformed_body`) and `exc_class`. Padding rows (`count=0`) are filtered before caching to keep Redis tight. Tenant override threshold is honoured (null → settings default). Added `get_http_client` (process-singleton `httpx.AsyncClient` keyed off the configured timeout), `close_http_client` shutdown hook, and `get_breached_password_checker` factory in `fief/dependencies/security.py`. Lifespan in `fief/lifespan.py` now calls `await close_http_client()` after `await close_redis()` on shutdown. Tests at `tests/services/test_breached_password_checker.py` (11 cases): respx-mocked HIBP for sighted-above-threshold (True, no fail-open audit), tenant override (50 vs threshold=100 → False), missing suffix (False), cache HIT (`call_count == 1` after two queries), cache TTL bound (`0 < ttl <= settings.breached_password_cache_ttl_s`), all four fail-open paths (timeout / 5xx / 429 with `reason=hibp_rate_limited` assertion / malformed body with `reason=malformed_body` assertion), kill-switch off (zero HTTP calls), and padding-row filtering (`{suffix: 5}` only). RED first → import failure as expected; GREEN after implementation: `pytest tests/services/test_breached_password_checker.py -o addopts="" --no-cov` reports `11 passed`. No regression in `test_rate_limiter.py` / `test_account_lockout.py` / `tests/dependencies/` (42 passed).
- **files edited/created:**
  - `fief/services/security/breached_passwords.py` (created)
  - `fief/dependencies/security.py` (edited — `get_http_client`, `close_http_client`, `get_breached_password_checker` factories + imports)
  - `fief/lifespan.py` (edited — shutdown wires `await close_http_client()`)
  - `tests/services/test_breached_password_checker.py` (created)

### T7: UserManager — wire HIBP into validate_password + extend error type + thread tenant
- **depends_on:** [T6]
- **location:** `fief/services/user_manager.py`, `fief/dependencies/users.py`
- **description:** `validate_password` is **already** `async` at `fief/services/user_manager.py:420`. We are extending its body, NOT changing its signature shape. Three discrete changes:

  **(a) Define `BreachedPasswordError` subclass.** `InvalidPasswordError` today is just `class InvalidPasswordError(UserManagerError)` with a `messages: list[str]` attribute (line ~70). Don't mutate the parent — add a typed subclass so existing handlers that catch `InvalidPasswordError` keep working AND new handlers can branch on the specific case:
  ```python
  class BreachedPasswordError(InvalidPasswordError):
      """Password rejected because it appears in the HIBP breach corpus."""
      pass
  ```
  This subclass relationship means every existing `except InvalidPasswordError` site catches breached passwords too — no breakage. New T8 handlers branch on `except BreachedPasswordError as e: ...`.

  **(b) Inject the checker.** Add `breached_password_checker: BreachedPasswordChecker` to `UserManager.__init__`. Update the `get_user_manager` factory at `fief/dependencies/users.py` to inject `Depends(get_breached_password_checker)`.

  **(c) Wire into `validate_password`.** After the existing zxcvbn `PasswordValidation.validate(...)` block (which raises `InvalidPasswordError` on its own), add:
  ```python
  if await self.breached_password_checker.is_breached(password, tenant):
      self.audit_logger(
          AuditLogMessage.USER_PASSWORD_BREACHED_REJECTED,
          subject_user_id=user.id if user is not None else None,
          extra={"tenant_id": str(tenant.id) if tenant is not None else None},
      )
      raise BreachedPasswordError([
          _("This password has appeared in a known data breach. Please pick another."),
      ])
  ```
  The `tenant` arg must be available inside `validate_password`. Add it as a kwarg if it isn't already; existing call sites (`create`, `set_user_attributes`, `reset_password`) need to pass it explicitly. UserManager is NOT tenant-scoped — `tenant` is a per-call argument throughout (verified at user_manager.py:76-96).

  **(d) Thread `tenant` through `set_user_attributes`.** Today `set_user_attributes(user, **kwargs)` doesn't take `tenant`. Add a `tenant: Tenant | None = None` kwarg (default-None for back-compat). Update its callers to pass `tenant`:
  - `UserManager.update()` already has `tenant` in scope (passes it through naturally).
  - `UserManager.reset_password()` already has `tenant` locally — pass it explicitly.
  - Auth-app dashboard `update_password` (`fief/apps/auth/routers/dashboard.py:248`-ish): the route already injects `tenant: Tenant = Depends(get_current_tenant)` via `BaseContext`. Pass `tenant=tenant` in the `set_user_attributes` call.
  - Admin API `update_user` (`fief/apps/api/routers/users.py:149`-ish): the route has `user: User = Depends(get_user_by_id_or_404)`; load tenant via `user.tenant` only if eager-loaded — safer to add `tenant: Tenant = Depends(get_current_tenant)` to the route signature and pass it through.

  Audit grep confirms call sites: `grep -rn "validate_password\|set_user_attributes" fief/services fief/apps`. There are ~5 call sites in total.
- **validation:** Existing password tests still pass; new tests in T10 confirm registration / change / reset / admin API all reject breached passwords with `BreachedPasswordError` (which IS-A `InvalidPasswordError`).
- **status:** Completed
- **log:**
  - 2026-05-09: TDD red→green. (a) Added `BreachedPasswordError(InvalidPasswordError)` subclass in `fief/services/user_manager.py` — IS-A relationship verified by import (`BreachedPasswordError.__mro__` includes `InvalidPasswordError`). (b) Injected `BreachedPasswordChecker` into `UserManager.__init__` (non-default kwarg, callers must wire it explicitly). Updated `get_user_manager` factory in `fief/dependencies/users.py` to inject `Depends(get_breached_password_checker)`, and `Initializer.create_admin` (the only direct factory caller) to construct one from `get_redis()` + `get_http_client()`. (c) Extended `validate_password` body to call `await self.breached_password_checker.is_breached(password, tenant)` AFTER the existing zxcvbn block; on True, emits `USER_PASSWORD_BREACHED_REJECTED` with `subject_user_id` (when `user.id` is available) + `extra={"tenant_id": str(tenant.id) ...}` and raises `BreachedPasswordError`. Added `tenant: Tenant | None = None` kwarg with default-None for back-compat. (d) Threaded `tenant` through `set_user_attributes` (new `tenant: Tenant | None = None` kwarg → forwarded to `validate_password`); through `update()` (new `tenant` kwarg → forwarded to `set_user_attributes`); `reset_password` already had `tenant: Tenant` in scope and now passes it explicitly. Updated callers: auth-app `update_password` route in `fief/apps/auth/routers/dashboard.py:248` now passes `tenant=context["tenant"]`; admin API `update_user` in `fief/apps/api/routers/users.py:149` passes `tenant=user.tenant` (which is already joinedloaded by `get_user_by_id_or_404`). Tests at `tests/services/test_user_manager_breached_password.py` (8 cases): IS-A subclass relationship; `validate_password` raises `BreachedPasswordError` with audit when checker says True; passes when False; zxcvbn-fail short-circuits BEFORE HIBP (verified `is_breached` not awaited); legacy signature without `tenant` kwarg propagates `None`; `set_user_attributes` propagates tenant correctly to checker; `set_user_attributes` without tenant propagates None; end-to-end `set_user_attributes` with breached password caught by `except InvalidPasswordError`. Also added a `_NoopBreachedPasswordChecker` override in `tests/conftest.py` (under existing `test_client_generator`) — without it, the singleton `httpx.AsyncClient` from `get_http_client()` gets bound to the first test's event loop and breaks subsequent tests with "Event loop is closed". RED first → ImportError. GREEN: `pytest tests/services/test_user_manager_breached_password.py` reports `8 passed`. Full sweep `pytest tests/apps/ tests/services/ tests/test_apps_auth_register.py tests/test_apps_auth_reset.py` reports `17 failed, 197 passed` — verified the 17 failures are pre-existing on pristine main (same 17 fail there with `189 passed`, the +8 here are my new tests). No new regressions.
- **files edited/created:**
  - `fief/services/user_manager.py` (edited — `BreachedPasswordError` subclass, `breached_password_checker` injected, `validate_password` extended + `tenant` kwarg, `set_user_attributes` + `update()` + `reset_password` thread tenant)
  - `fief/dependencies/users.py` (edited — `get_user_manager` injects `get_breached_password_checker`)
  - `fief/services/initializer.py` (edited — `create_admin` constructs a `BreachedPasswordChecker` for the CLI factory call)
  - `fief/apps/auth/routers/dashboard.py` (edited — `update_password` route passes `tenant=context["tenant"]`)
  - `fief/apps/api/routers/users.py` (edited — admin `update_user` passes `tenant=user.tenant`)
  - `tests/conftest.py` (edited — `_NoopBreachedPasswordChecker` override on `get_breached_password_checker` in `test_client_generator`)
  - `tests/services/test_user_manager_breached_password.py` (created — 8 cases)

### T8: Add `InvalidPasswordError` catch in three handlers + admin API confirm
- **depends_on:** [T7]
- **location:** `fief/apps/auth/routers/register.py`, `fief/apps/auth/routers/reset.py`, `fief/apps/auth/routers/dashboard.py` (auth-app `update_password`), `fief/apps/api/routers/users.py` (verify only)
- **description:** **NOT a no-op.** Three of the four password-set handlers do NOT catch `InvalidPasswordError` today; without this task a `BreachedPasswordError` raise would 500 the request. Concrete edits:

  **(a) `fief/apps/auth/routers/register.py`** — currently catches only `UserAlreadyExistsError` around `registration_flow.create_user(...)` (~line 144-148). Add:
  ```python
  except InvalidPasswordError as exc:
      message = "; ".join(exc.messages)
      form.password.errors.append(message)
      return await form_helper.get_error_response(
          message,
          "password_breached" if isinstance(exc, BreachedPasswordError) else "invalid_password",
      )
  ```

  **(b) `fief/apps/auth/routers/reset.py`** — `reset_password` route catches `InvalidResetPasswordTokenError, UserDoesNotExistError, UserInactiveError` only (~line 173-186). Add the same `InvalidPasswordError` branch around the `user_manager.reset_password(...)` call. Surface the message to `form.password.errors` and use the same `password_breached` vs `invalid_password` discrimination.

  **(c) `fief/apps/auth/routers/dashboard.py`** — auth-app `update_password` route (~lines 209-255 from MFA-1's modernization). Currently no try/except around `user_manager.set_user_attributes(user, password=new_password)`. Add a try/except `InvalidPasswordError` block surfacing the error to the password field on the existing FormHelper. Same discrimination as above.

  **(d) `fief/apps/api/routers/users.py`** — already catches `InvalidPasswordError` at lines 125 (POST `/users`) and 156 (PATCH `/users/{id:uuid}`). **Verify only** that the existing 400/422 response carries the message back; no edit unless a discrimination on `BreachedPasswordError` is desired (recommend: yes — surface `error_code: "password_breached"` so admin clients can differentiate).
- **validation:** Manual smoke: try registering with `Password1` (definitely in HIBP corpus); form shows the breached-password error + other input fields are retained. T10 covers automated.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T9: Unit tests — BreachedPasswordChecker
- **depends_on:** [T6]
- **location:** `tests/services/test_breached_password_checker.py` (new)
- **description:** Use `respx` (already in dev deps) to mock HIBP HTTP responses. Use `fakeredis.aioredis.FakeRedis` for the cache layer.
  - Cases:
    - Password sighted ≥ threshold → returns True; `bpc.fail_open` metric NOT incremented.
    - Password sighted < threshold → returns False.
    - Password NOT in returned suffix list → returns False (count=0).
    - Cache HIT: same prefix queried twice → second call doesn't hit HIBP (assert via respx call count).
    - Cache MISS then SET: response is cached with the right TTL (verify `await redis.ttl(key)` is positive and ≤ settings cache TTL).
    - HIBP timeout (mock with respx side effect → `httpx.TimeoutException`): returns False (fail-open), audit emitted.
    - HIBP 5xx: returns False (fail-open).
    - HIBP malformed body: returns False (fail-open).
    - Tenant override: `tenant.breached_password_threshold = 100` and HIBP says count=50 → returns False (50 < 100).
    - Setting toggle off: `breached_password_check_enabled=False` → returns False without any HTTP call.
- **validation:** `pytest tests/services/test_breached_password_checker.py` green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T10: Integration tests — register / change / reset / admin reject breached passwords
- **depends_on:** [T7, T8]
- **location:** `tests/services/test_user_manager_breached_password.py` (new) + targeted route tests under `tests/apps/auth/routers/` and `tests/apps/api/routers/`.
- **description:**
  - Register a new user with a known-breached password (mock HIBP via respx to return count=999) → 400/422 form error with code `password_breached`.
  - Change password from dashboard → same.
  - Reset password via forgot flow → same.
  - Admin PATCH `/api/users/{id}` with breached password → 400/422.
  - Cross-check: zxcvbn-strong but breached password (e.g. mock HIBP for any input) → still rejected.
  - Cross-check: zxcvbn-weak password → rejected with the existing zxcvbn message (NOT `password_breached`); HIBP NOT called (zxcvbn fails first; verify via respx call count = 0).
- **validation:** All new tests green; existing UserManager tests unaffected.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T11: Dev rollout
- **depends_on:** [T9, T10]
- **description:** `alembic upgrade head` against dev DB. Smoke test:
  - Try registering with `Password1` → rejected with `password_breached` error. Audit log shows `USER_PASSWORD_BREACHED_REJECTED`.
  - Try registering with a strong unbreached password → accepted.
  - Simulate HIBP outage (firewall block or set `breached_password_api_url` to a dead URL via env) → password set still works, audit log shows `USER_PASSWORD_BREACHED_CHECK_FAILED_OPEN`.
  - Set `breached_password_check_enabled=False` via env → no HTTP calls, all passwords accepted as before.
- **validation:** All flows pass. No errors in pod logs.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T12: Production rollout
- **depends_on:** [T11]
- **description:** Push image, watch GHCR build, `kubectl rollout restart deploy/opensensor-fief`. The new migration adds one nullable column — fully online-safe and won't disrupt traffic. Confirm boot logs show no HIBP / Redis errors. Smoke: try registering a fresh test account on each brand with `Password1`; should be rejected. Watch `bpc.fail_open` metric for first 24 h; if non-zero, HIBP availability is dropping requests open (acceptable; still better than zxcvbn-only).
- **validation:** All 3 brands reject breached passwords; no support tickets about strong unbreached passwords being incorrectly rejected.
- **status:** Not Completed
- **log:**
- **files edited/created:**

## Parallel Execution Groups

| Wave | Tasks                       | Notes                                                            |
|------|-----------------------------|------------------------------------------------------------------|
| 1    | T1, T2, T3                  | Foundation; all parallel                                         |
| 2    | T4, T5                      | Schema; both parallel                                            |
| 3    | T6                          | Service; needs T1+T2 (and the SEC-1 redis dep, already shipped)  |
| 4    | T7                          | UserManager wiring; needs T6                                     |
| 5    | T8                          | Route-level error surface audit; needs T7                        |
| 6    | T9, T10                     | Tests, parallel                                                  |
| 7    | T11 → T12                   | Rollout, sequential                                              |

## Testing strategy
- Unit tests use `respx` (declared in dev deps) to mock HIBP responses without real HTTP. fakeredis for the cache. Fast, deterministic.
- Integration tests reuse the existing httpx.AsyncClient test harness (`tests/conftest.py:285`). Override `get_breached_password_checker` to a stub that says True/False without HTTP.
- A small sanity test: feed in `password = "Password1"` to the real HIBP endpoint (gated by an opt-in env flag, only run on demand) to confirm the implementation works end-to-end. Don't run by default.
- Cross-validate: zxcvbn-fail short-circuits before HIBP (no HTTP call when the password is too weak to bother checking).

## Risks & mitigations
- **HIBP outage = password sets fully blocked OR fully open?** Decision: fail-OPEN on timeout / 429 / 5xx / malformed body. The whole point of the check is layered defence; if HIBP is down, zxcvbn still runs. T9 covers all five fail-open paths.
- **Strong-but-breached passwords get rejected mid-rollout, surprising users.** Mitigation: the kill switch (`breached_password_check_enabled=False`) lets you turn it off in production via env without code rollback. Form-error copy ("This password has appeared in a known data breach. Please pick another.") gives users actionable feedback.
- **HIBP rate limits.** Free range API has per-IP throttling. With Redis prefix caching at 24 h, cache hit rate should be very high (>95%) within hours of deploy. 429 responses are treated as fail-open so we never block password changes when HIBP throttles us.
- **Audit log volume.** Every breached-password attempt is logged. Acceptable; this is rare and the data is forensically valuable.
- **Cache poisoning.** HIBP is HTTPS with httpx default cert validation, so an attacker can't MITM-inject corrupted suffix counts into our Redis cache.

## Plan revisions applied from subagent review (2026-05-09)
- **Lock-ins** — corrected the "make `validate_password` async" claim (it's already async at user_manager.py:420). Added explicit "tenant is passed per-call, not stored on UserManager" lock-in.
- **T4** — corrected `down_revision` to `4f8d1c5e2a9b` (current head) instead of `b400430e70fc` (SEC-1 head; two later branding migrations shipped between SEC-1 and SEC-2).
- **T6** — added explicit `Add-Padding: true` header per HIBP guidance; added 429 to the fail-open paths (was implied under "non-2xx", now explicit). Documented HIBP padding rows (count=0) get filtered before caching.
- **T7** — major rewrite. (a) Adds `BreachedPasswordError(InvalidPasswordError)` subclass instead of trying to add a `code` attribute to `InvalidPasswordError` (which has no such attribute today). (b) Threads `tenant` through `set_user_attributes` (it doesn't take tenant today). (c) Updates auth-app `update_password` and admin API `update_user` callers to pass `tenant`.
- **T8** — major rewrite. Three handlers (`register.py`, `reset.py`, auth-app `dashboard.py update_password`) do NOT catch `InvalidPasswordError` today. Specifies concrete try/except additions for each. Admin API in users.py already catches; verify-only with optional discrimination on `BreachedPasswordError`.

## Open questions deferred to implementation
- **Notify users post-hoc when their CURRENT password becomes breached.** Out of scope per PRD non-goal. Tracked separately if support gets the request.
- **Custom dictionary of banned-words on top of HIBP.** Out of scope; could be a follow-up if a customer asks.
- **Per-brand threshold (vs. just per-tenant).** Defer; brands share a tenant in our model, and tenant-level threshold is fine for v1.
