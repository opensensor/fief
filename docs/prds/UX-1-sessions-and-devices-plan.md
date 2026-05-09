# Plan: UX-1 — Active sessions & devices tab

**Generated:** 2026-05-09
**Source PRD:** `docs/prds/UX-1-sessions-and-devices.md`
**Decisions locked in:**
- **GeoIP deferred.** v1 ships IP-only — each row shows the raw IP plus UA-derived device label. No GeoLite2 download or MaxMind license accept. Geo can be added as a single follow-up.
- UA parsing via `user-agents` (cleaner Python API than `ua-parser`'s raw regex tables).
- Combined view: `fief_session_tokens` (browser dashboard sessions) and `fief_refresh_tokens` (OAuth app grants) deduped by device key `(ua_family, os_family, last_seen_ip)`. Revoking a deduped row revokes all underlying tokens.
- New routes live under the existing dashboard router at `/security/sessions` (mirrors `/security/mfa` location); not under a new `/api/me` namespace.
- "Current session" is the row whose `session_token.id` matches the cookie-resolved session loaded by the existing `get_session_token` dep — the user can revoke it but the UI confirms via a "this signs you out" dialog.

## Overview
Surface a "Devices" tab inside the modernized dashboard so users can see every place they're signed in, identify the current session, and revoke any individual session or "everything else." Pulls from data we already have (`fief_session_tokens`, `fief_refresh_tokens`); schema additions are eight nullable annotation columns total (4 per table).

Reference points (from codebase exploration):
- SessionToken: `fief/models/session_token.py:11-26` (current cols: id, token, user_id, created_at, updated_at, expires_at).
- RefreshToken: `fief/models/refresh_token.py:19-42` (id, token, scope, authenticated_at, user_id, client_id, created_at, updated_at, expires_at).
- Session-token validation dep: `fief/dependencies/session_token.py:11-39` (`get_session_token` queries via `SessionTokenRepository.get_by_token`). Insertion point for `last_seen_*` updates.
- SessionToken creation: `fief/services/authentication_flow.py:102-117` (`create_session_token`). Insertion point for `created_ip` / `created_user_agent`.
- RefreshToken creation: `fief/apps/auth/routers/token.py:79-87`. Insertion point for `created_ip` / `created_user_agent` AND `last_seen_*` on refresh-grant validation.
- Auto-revoke triggers: `fief/apps/auth/routers/dashboard.py:212` (password change), `:378` (MFA enroll confirm), `:479` (MFA disable), `fief/apps/auth/routers/auth.py:871` (MFA recovery code consumed).
- Audit log enum: `fief/models/audit_log.py:13-39`.
- Repositories: `SessionTokenRepository` (`fief/repositories/session_token.py`) and `RefreshTokenRepository` (`fief/repositories/refresh_token.py`) — currently only `get_by_token`.
- Sidebar: `fief/templates/auth/dashboard/sidebar.html:1-84` (post-MFA-1 modernization). Add "Devices" nav item next to Profile / Password / Security.

## Prerequisites
- `user-agents >= 2.2` declared in `pyproject.toml`. No new env vars or secrets.
- Migrations stack on top of SEC-2's `2efcfe2289f4` head.

## Dependency Graph

```
Wave 1 (Foundation) — parallel
  T1 deps          T2 audit-log enum

Wave 2 (Schema) — parallel
  T3 alembic migration   T4 SessionToken cols   T5 RefreshToken cols

Wave 3 (Repos) — parallel
  T6 SessionTokenRepository methods (T4)   T7 RefreshTokenRepository methods (T5)

Wave 4 (Tracking hooks) — parallel
  T8 SessionToken lifecycle hooks (T6)
  T9 RefreshToken lifecycle hooks (T7)

Wave 5 (Service)
  T10 DeviceSessionsService — combine + dedup + UA parse (T1, T6, T7)

Wave 6 (Routes)
  T11 /security/sessions GET / DELETE / sign-out-others (T10)

Wave 7 (Auto-revoke wires)
  T12 Hook delete_all_except_for_user into password-change + MFA enroll + MFA disable + recovery (T2, T6, T7)

Wave 8 (UI) — parallel
  T13 Devices tab template (T11)
  T14 Sidebar nav addition (independent — small, can run with T13)

Wave 9 (Tests) — most subsumed by TDD in upstream tasks
  T15 Service unit tests (T10)
  T16 Route integration tests (T11)
  T17 Auto-revocation tests (T12)

Wave 10 (Rollout)
  T18 Dev rollout (T15-T17)
  T19 Production rollout (T18)
```

## Tasks

### T1: Add Python dependencies
- **depends_on:** []
- **location:** `pyproject.toml`
- **description:** Add `user-agents >= 2.2` to `[project].dependencies`. The library wraps `ua-parser` with a cleaner OO API: `parse(ua_str).browser.family`, `.os.family`, `.is_mobile`, `.is_tablet`. ~50KB pure-Python, no native deps.
- **validation:** `python -c "from user_agents import parse; ua = parse('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15'); print(ua.browser.family, ua.os.family)"` prints `Safari Mac OS X`.
- **reason_not_testable:** configuration; verified by import smoke
- **status:** Completed
- **log:**
  - 2026-05-09: Added `"user-agents >=2.2"` to `[project].dependencies` in `pyproject.toml` (alphabetical, between `typer` and `uvicorn`). Installed `user-agents 2.2.0` (pulls `ua-parser 1.0.2` + `ua-parser-builtins 202605`) into `.venv`. Smoke test prints `Safari | Mac OS X | True` as expected.
- **files edited/created:**
  - `pyproject.toml` (modified)

### T2: Audit-log enum additions
- **depends_on:** []
- **location:** `fief/models/audit_log.py`
- **description:** Add three members to `AuditLogMessage`:
  - `USER_SESSION_REVOKED` — user clicked "Revoke" on a single device row.
  - `USER_SESSIONS_SIGNED_OUT_OTHERS` — user clicked "Sign out of all other sessions".
  - `USER_SESSIONS_AUTO_REVOKED` — auto-revoke fired (password change / MFA enroll / MFA disable / recovery code used). The `extra` payload identifies which trigger.

  Match the existing `USER_*` prefix style (StrEnum, name == value).

  **Audit `extra` schema (standardized for grep-ability):**
  - `revoked_session_count: int` — number of `fief_session_tokens` rows deleted.
  - `revoked_refresh_count: int` — number of `fief_refresh_tokens` rows deleted.
  - `trigger_reason: str` — only on `USER_SESSIONS_AUTO_REVOKED`. One of `"password_change"`, `"mfa_enrolled"`, `"mfa_disabled"`, `"recovery_code_used"`.
  - `device_label: str | None` — only on `USER_SESSION_REVOKED` (single-row revoke).
- **validation:** `from fief.models.audit_log import AuditLogMessage; assert AuditLogMessage.USER_SESSION_REVOKED`.
- **reason_not_testable:** enum-only addition; verified by import smoke
- **status:** Completed
- **log:** Added USER_SESSION_REVOKED, USER_SESSIONS_SIGNED_OUT_OTHERS, USER_SESSIONS_AUTO_REVOKED to AuditLogMessage with grep-able docstring comment block documenting the standardized `extra` payload schema (revoked_session_count, revoked_refresh_count, trigger_reason, device_label). Smoke import passed.
- **files edited/created:** fief/models/audit_log.py

### T3: Alembic migration — 8 annotation columns
- **depends_on:** []
- **location:** `fief/alembic/versions/2026-05-09g_add_session_token_device_annotations.py` (new — letter `g` because `f` is the last SEC-2 migration `2efcfe2289f4`)
- **description:**
  - `revision = "<new 12-char hex>"`, `down_revision = "2efcfe2289f4"` (SEC-2's `2026-05-09f_add_tenant_breached_password_threshold` — confirm via `alembic heads`).
  - Add to `fief_session_tokens`:
    - `created_ip TEXT NULL`
    - `created_user_agent TEXT NULL`
    - `last_seen_at TIMESTAMPTZ NULL`
    - `last_seen_ip TEXT NULL`
  - Add the same four columns to `fief_refresh_tokens`.
  - All columns are NULL-default — fully online-safe; existing rows simply don't have device annotations until next request lights them up.
  - **Add user_id indexes (NEW):** `fief_session_tokens.user_id` and `fief_refresh_tokens.user_id` are NOT indexed today (verified via initial migration `2023-08-28_initial_migration.py`). The new `list_by_user_id` queries (T6/T7) would full-scan without these:
    - `op.create_index(op.f(f"ix_{table_prefix}session_tokens_user_id"), f"{table_prefix}session_tokens", ["user_id"])`
    - `op.create_index(op.f(f"ix_{table_prefix}refresh_tokens_user_id"), f"{table_prefix}refresh_tokens", ["user_id"])`
    The `down()` drops these indexes before dropping columns.
  - `down()` drops both new indexes, then all eight columns in reverse order.
  - Use the `op.get_context().opts["table_prefix"]` codemod placeholder pattern. Plain `op.add_column` works on both SQLite and Postgres for nullable adds — **no `op.batch_alter_table` needed**.
- **validation:** Migration parser run + `alembic heads` shows the new revision as head. Live up/down/up deferred to T18.
- **reason_not_testable:** SQL DDL migration; verified by alembic head check + parser run
- **status:** Completed
- **log:** Created migration with `revision = "0929dd1d8a8c"`, `down_revision = "2efcfe2289f4"`. Adds the 4 nullable annotation columns (`created_ip`, `created_user_agent`, `last_seen_at`, `last_seen_ip`) to both `fief_session_tokens` and `fief_refresh_tokens`, plus `ix_*_session_tokens_user_id` and `ix_*_refresh_tokens_user_id` (T6/T7's `list_by_user_id` covering indexes). `downgrade()` drops both indexes first, then all 8 columns in reverse order. Confirmed `alembic -c fief/alembic.ini heads` reports `0929dd1d8a8c (head)`; parser smoke run prints `0929dd1d8a8c 2efcfe2289f4`. Live up/down/up deferred to T18.
- **files edited/created:** fief/alembic/versions/2026-05-09g_add_session_token_device_annotations.py

### T4: SessionToken model — add 4 columns + user_id index
- **depends_on:** []
- **location:** `fief/models/session_token.py`
- **description:** Add to the `SessionToken` model:
  ```python
  created_ip: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
  created_user_agent: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
  last_seen_at: Mapped[datetime | None] = mapped_column(
      TIMESTAMPAware(timezone=True), nullable=True, default=None
  )
  last_seen_ip: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
  ```
  Use `TIMESTAMPAware` (the project's wrapper at `fief/models/generics.py`, used elsewhere like `last_used_step` columns). Place the new fields after `expires_at` for readability.

  **Also add `index=True`** to the existing `user_id` ForeignKey column declaration so the model + DDL stay in sync with T3's `create_index` call. The runtime CREATE INDEX is owned by T3's migration; the SQLAlchemy declaration just keeps the metadata accurate.
- **validation:** `from fief.models import SessionToken; assert SessionToken.__table__.c.created_ip.nullable`. Mapper warnings clean.
- **status:** Completed
- **log:** Added `created_ip`, `created_user_agent`, `last_seen_at`, `last_seen_ip` (all nullable, default None) to `SessionToken`; added `index=True` to the existing `user_id` FK column to keep model + DDL aligned with T3's `CREATE INDEX`. Imported `Text` (sqlalchemy) and `TIMESTAMPAware` (project wrapper) following the SEC-1 `UserLockout` / `RefreshToken` pattern. TDD: 5-assertion test file (created_ip / created_user_agent / last_seen_at / last_seen_ip nullable + user_id.index is True) ran RED first, then GREEN after the model edit. Smoke import shows nullable=True and user_id.index=True.
- **files edited/created:** fief/models/session_token.py, tests/models/test_session_token_device_columns.py

### T5: RefreshToken model — add 4 columns + user_id index
- **depends_on:** []
- **location:** `fief/models/refresh_token.py`
- **description:** Same four columns (`created_ip`, `created_user_agent`, `last_seen_at`, `last_seen_ip`) on the `RefreshToken` model. Same defaults, nullability, and types as T4. Place after `expires_at`. Also add `index=True` to the existing `user_id` ForeignKey column (matches T3's CREATE INDEX).
- **validation:** `from fief.models import RefreshToken; assert RefreshToken.__table__.c.last_seen_at.nullable`. Mapper clean.
- **status:** Completed
- **log:**
  - 2026-05-09: TDD — wrote `tests/models/test_refresh_token_device_columns.py` (5 assertions: 4 nullable annotation columns + `user_id.index is True`). RED first (5 failures: `AttributeError: created_ip` and `user_id.index is None`). Added `Text` to the SQLAlchemy import, `index=True` on the `user_id` ForeignKey column, and the four new columns (`created_ip`, `created_user_agent`, `last_seen_at`, `last_seen_ip`) appended after the `client` relationship (post-`expires_at` mixin column). All 5 tests GREEN.
- **files edited/created:**
  - `fief/models/refresh_token.py` (modified)
  - `tests/models/test_refresh_token_device_columns.py` (new)

### T6: SessionTokenRepository methods
- **depends_on:** [T4]
- **location:** `fief/repositories/session_token.py`
- **description:** Add to the existing `SessionTokenRepository` (currently only has `get_by_token`):
  - `async list_by_user_id(user_id: UUID4) -> list[SessionToken]` — order by `created_at` desc.
  - `async delete_by_id_for_user(token_id: UUID4, user_id: UUID4) -> int` — DELETE WHERE `id = :id AND user_id = :uid`. Returns the row count. **Authorization defence:** the user_id scoping prevents one user from deleting another user's session. The route in T11 uses `device_key` (not raw token id) and re-lists devices server-side to find the matching set, so the bool return is informational; we standardize on `int` for consistency with `delete_all_except_for_user`.
  - `async delete_all_except_for_user(user_id: UUID4, except_ids: list[UUID4]) -> int` — DELETE WHERE `user_id = :uid AND id NOT IN :except_ids`. Returns count. Used by:
    - "Sign out of all others" button (pass `[current_session_id]`)
    - Auto-revoke triggers (pass `[current_session_id]` — we keep the current session, revoke all siblings; matches the PRD wording "all other sessions auto-revoked")
    - Pass `[]` to revoke EVERYTHING (not used in v1 but the API supports it).
  - `async touch_last_seen(token_id: UUID4, *, last_seen_at: datetime, last_seen_ip: str) -> None` — small UPDATE for the dependency to call on each request use. Keep cheap.
- **validation:** Smoke test confirms method signatures + `BaseRepository[SessionToken]` subclass.
- **status:** Completed
- **log:** Added `list_by_user_id` (filters `is_expired.is_(False)`, orders by `created_at` DESC), `delete_by_id_for_user` (returns rowcount; user_id-scoped DELETE is the authorization defence), `delete_all_except_for_user` (uses `id.notin_(except_ids)` only when `except_ids` is non-empty so `[]` revokes EVERYTHING cleanly), and `touch_last_seen` (single UPDATE statement, no SELECT round-trip). Smoke test `tests/repositories/test_session_token_repo_smoke.py` exercises all four signatures via `inspect`, plus subclass + model-binding assertions; ran RED first (4 failing), then GREEN (8/8 passing) after implementation. Real CRUD coverage deferred to service-level tests in later UX-1 tasks.
- **files edited/created:**
  - `fief/repositories/session_token.py` (modified)
  - `tests/repositories/test_session_token_repo_smoke.py` (new)

### T7: RefreshTokenRepository methods
- **depends_on:** [T5]
- **location:** `fief/repositories/refresh_token.py`
- **description:** Add the same four methods as T6 (`list_by_user_id`, `delete_by_id_for_user`, `delete_all_except_for_user(user_id, except_ids: list[UUID4])`, `touch_last_seen`) to `RefreshTokenRepository`. Mirror T6's contract exactly so the service can treat them identically. Note: refresh tokens have no concept of "the current session" the way browser sessions do, so `except_ids` passed from auto-revoke triggers is always `[]` (revoke all refresh tokens) — the user can re-authorize OAuth clients separately.
- **validation:** Smoke test confirms method signatures.
- **status:** Completed
- **log:**
  - 2026-05-09: TDD — wrote `tests/repositories/test_refresh_token_repo_smoke.py` (8 `inspect`-based assertions: importable, subclasses `BaseRepository`, model bound, `get_by_token` async, plus signature shape for the four new methods including keyword-only `last_seen_at`/`last_seen_ip` on `touch_last_seen`). RED first (4 failures: `list_by_user_id`, `delete_by_id_for_user`, `delete_all_except_for_user`, `touch_last_seen` missing). Implemented the four methods on `RefreshTokenRepository` mirroring T6 — `list_by_user_id` filters `expires_at > now()` ordered by `created_at DESC` (per spec; uses the explicit timestamp comparison rather than the `is_expired` hybrid because the auto-revoke flow needs the same predicate semantics across both repos and `expires_at` is timestamptz-comparable in PG); `delete_by_id_for_user` uses `_execute_statement` and returns `rowcount`; `delete_all_except_for_user` skips the `NOT IN` clause when `except_ids=[]` (the revoke-all path used by auto-revoke triggers since refresh tokens have no "current session"); `touch_last_seen` is a single UPDATE that does not touch `created_user_agent`. All 8 GREEN.
- **files edited/created:**
  - `fief/repositories/refresh_token.py` (modified)
  - `tests/repositories/test_refresh_token_repo_smoke.py` (new)

### T8: SessionToken lifecycle hooks — capture creation + last-seen
- **depends_on:** [T6]
- **location:** `fief/services/authentication_flow.py`, `fief/dependencies/session_token.py`, plus **all 7 callers** of `create_session_token` / `rotate_session_token` / `complete_login_after_mfa`
- **description:**
  - **Creation hook (`create_session_token`)** — at `fief/services/authentication_flow.py:107`, the `SessionToken(...)` constructor call. Add `request: Request` param to the method signature; populate `created_ip` from the existing SEC-1 `get_client_ip_info(request).raw` helper and `created_user_agent` from `request.headers.get("user-agent")`. ALSO populate `last_seen_at = now()` and `last_seen_ip = created_ip` so the row starts coherent.
  - **Last-seen update hook** — at `fief/dependencies/session_token.py:11-19`, `get_session_token` already loads the SessionToken row. After load (line 19), call `await repository.touch_last_seen(session_token.id, last_seen_at=now, last_seen_ip=ip_info.raw)`. Use `request: Request = Depends()` and `ip_info: ClientIpInfo = Depends(get_client_ip_info)` (SEC-1 dep) injected into the dependency. This adds one tiny UPDATE per protected dashboard request — negligible cost; and we keep the User-Agent in `created_user_agent` (don't update UA on refresh — it's the device identity, not the request envelope).

  **Caller cascade — `request` must be propagated through 7 sites in this single commit** so the runtime never crashes mid-rollout:
  1. `fief/services/authentication_flow.py:107` (`create_session_token`) — add `request` kwarg.
  2. `fief/services/authentication_flow.py:129` (`rotate_session_token`) — add `request` kwarg, forward to `create_session_token`.
  3. `fief/services/authentication_flow.py` `complete_login_after_mfa` (called twice from `auth.py`) — add `request` kwarg, forward to `rotate_session_token`.
  4. `fief/apps/auth/routers/register.py:195` — pass `request`.
  5. `fief/apps/auth/routers/oauth.py:164` — pass `request`.
  6. `fief/apps/auth/routers/auth.py:418` (`/login` non-MFA path) — pass `request`.
  7. `fief/apps/auth/routers/auth.py:454` (`/login` MFA-not-enrolled path).
  8. `fief/apps/auth/routers/auth.py:828, :989` (the two `complete_login_after_mfa` call sites — `/mfa/totp` POST success + `/mfa/recover` POST success).

  Confirm the full set with `grep -rn "create_session_token\|rotate_session_token\|complete_login_after_mfa" fief/`. Tests catch any missed propagation.
- **validation:** New session has `created_ip`, `created_user_agent`, `last_seen_at`, `last_seen_ip` populated. After a follow-up request, `last_seen_at` advances. All 7 caller sites compile + their existing tests still green.
- **status:** Completed
- **log:**
  - 2026-05-09: TDD — wrote `tests/services/test_authentication_flow_lifecycle.py` with 6 unit tests over fakes (no DB / FastAPI app needed): `create_session_token` populates all four device-annotation columns coherently from the SEC-1 client-IP helper + `User-Agent` header; missing UA leaves `created_user_agent=None`; `rotate_session_token` forwards `request` into the new row; the dependency calls `touch_last_seen` exactly once on a successful cookie load with the resolved IP and a UTC timestamp; the no-cookie and unknown-cookie branches do NOT call `touch_last_seen`. RED first (6 failures: TypeError — old call shape rejected `request` kwarg). Implemented: (a) `AuthenticationFlow.create_session_token` now takes `request: Request` (positional after `user_id`), reads `created_ip` from `get_client_ip_info(request).raw` and `created_user_agent` from `request.headers.get("user-agent")`, seeds `last_seen_at=now` / `last_seen_ip=created_ip` so the row starts coherent; `rotate_session_token` and `complete_login_after_mfa` each take `request` positionally and forward it (positional placement keeps the existing `session_token=` keyword-only contract intact). (b) `get_session_token` injects `request: Request` and `ip_info: ClientIpInfo = Depends(get_client_ip_info)`; after `repository.get_by_token` returns a row it issues a single UPDATE via `repository.touch_last_seen` with `datetime.now(UTC)` and `ip_info.raw` — UA is intentionally NOT updated (created_user_agent is the device's identity, not the request envelope). (c) Cascade: `register.py:195`, `oauth.py:164`, `auth.py` (4 sites — two `rotate_session_token` for /login non-MFA + MFA-required-not-enrolled, two `complete_login_after_mfa` for /mfa/totp + /mfa/recover). Existing direct-service test `test_login_mfa_branch.py::TestCompleteLoginAfterMFA` updated to construct a Starlette `Request` stub. All 166 tests in spec suite green (`tests/test_apps_auth_auth.py` + new lifecycle file + `test_login_security` + `test_login_mfa_branch` + `test_mfa_challenge`). T9 already landed concurrently on `token.py` (commit `785a9ff`); boundary respected — no overlap.
- **files edited/created:**
  - `fief/services/authentication_flow.py` (modified)
  - `fief/dependencies/session_token.py` (modified)
  - `fief/apps/auth/routers/register.py` (modified)
  - `fief/apps/auth/routers/oauth.py` (modified)
  - `fief/apps/auth/routers/auth.py` (modified)
  - `tests/apps/auth/routers/test_login_mfa_branch.py` (modified — direct-service test now passes the new `request` arg)
  - `tests/services/test_authentication_flow_lifecycle.py` (new)

### T9: RefreshToken lifecycle hooks — capture creation + last-seen on grant
- **depends_on:** [T7]
- **location:** `fief/apps/auth/routers/token.py`
- **description:**
  - **Creation hook** — at line 79-87 of `token.py`, where `RefreshToken(...)` is constructed. Populate `created_ip` from `get_client_ip_info(request).raw` (the route already has access to `request: Request`), `created_user_agent` from `request.headers.get("user-agent")`, `last_seen_at = now()`, `last_seen_ip = created_ip`.
  - **Last-seen update on refresh grant** — find the refresh-grant flow in the same file (where an existing refresh token is presented to mint a new access token). After the existing token is validated, call `await repository.touch_last_seen(refresh_token.id, last_seen_at=now, last_seen_ip=ip_info.raw)`. Don't update UA (the same device using the OAuth client may report a slightly different UA on each request; we treat first-seen UA as the device identity).
- **validation:** A new authorization-code grant produces a refresh token row with all four annotation columns populated. A subsequent refresh-token grant updates `last_seen_at` and `last_seen_ip`.
- **status:** Completed
- **log:**
  - 2026-05-09: TDD — wrote `tests/apps/auth/routers/test_token_lifecycle.py` with 4 cases: (1) auth-code grant w/ `offline_access` populates all 4 device columns on the new refresh token; (2) missing User-Agent persists `created_user_agent` as `None`/`""` (router takes whatever the request reports — does not synthesize a placeholder); (3) refresh-grant calls `RefreshTokenRepository.touch_last_seen` exactly once against the **existing** refresh token's id with timezone-aware `last_seen_at` and the resolved client IP (spied via `monkeypatch.setattr` and forwarded to the real method so SQL still executes against the test DB); (4) contract test on `touch_last_seen` keyword-only signature confirming only `last_seen_at` / `last_seen_ip` can flow through (defence against accidental `created_*` clobber). Ran RED first (auth-code created_ip is `None`), then implemented the route. Took the boundary-respecting path: added `request: Request` and a `refresh_token_form: str | None = Form(None, alias="refresh_token")` parameter to the route signature so we can re-resolve the existing token by hash (cannot expose it via `GrantRequest` without editing `dependencies/token.py`, which is out of bounds for T9). The dep's post-yield `delete()` still runs after the route returns, so the rotation behaviour is preserved (existing `test_apps_auth_token::test_valid` still asserts `old_refresh_token is None`). Creation hook hydrates `created_ip` / `created_user_agent` / `last_seen_at` / `last_seen_ip` on the new `RefreshToken(...)` constructor call inside the existing `if "offline_access" in scope:` branch. Last-seen hook fires only when `grant_request["grant_type"] == "refresh_token"` and the form-resolved token still exists (defensive None-guard against a race with the cleanup). All 4 new + 88 existing token tests GREEN.
- **files edited/created:**
  - `fief/apps/auth/routers/token.py` (modified)
  - `tests/apps/auth/routers/test_token_lifecycle.py` (new)

### T10: DeviceSessionsService — combine + dedup + UA parse
- **depends_on:** [T1, T6, T7]
- **location:** `fief/services/security/device_sessions.py` (new), `fief/dependencies/security.py` (factory)
- **description:**
  ```python
  @dataclass(frozen=True)
  class DeviceRow:
      """Render-time view of one deduped device. Underlying token ids are
      preserved so the route can map a delete back to the correct rows."""
      device_label: str            # "Safari on Mac OS X"
      device_kind: str             # "laptop" | "phone" | "tablet" | "unknown"
      first_seen: datetime
      last_seen: datetime
      last_seen_ip: str | None
      session_token_ids: list[UUID4]
      refresh_token_ids: list[UUID4]
      is_current: bool             # matches the current session cookie's row
      client_label: str | None     # "via LightNVR Web" — from refresh token's client.name (None for browser sessions)


  class DeviceSessionsService:
      def __init__(
          self,
          session_repo: SessionTokenRepository,
          refresh_repo: RefreshTokenRepository,
          client_repo: ClientRepository,
          audit_logger: AuditLogger,
      ): ...

      async def list_for_user(self, user_id: UUID4, *, current_session_id: UUID4 | None) -> list[DeviceRow]:
          # 1. Pull active session tokens (expires_at > now()) and refresh
          #    tokens (expires_at > now()) for this user.
          # 2. For each token row, parse the UA via user_agents.parse(); fall
          #    back to "Unknown device" when UA missing.
          # 3. Dedup key: (browser_family, os_family, last_seen_ip OR created_ip).
          #    Within a 24 h window of last_seen_at, treat slight IP changes as
          #    same device (helps IPv6 privacy extensions). For v1, simpler:
          #    use a stable `(browser_family, os_family, /24-of-IP)` tuple.
          # 4. Build DeviceRow per dedup group; aggregate first_seen=min,
          #    last_seen=max; collect token ids.
          # 5. Mark is_current=True on the row containing current_session_id.
          # 6. Sort by last_seen desc.

      async def revoke(self, user_id: UUID4, row: DeviceRow) -> None:
          # Delete all session_token_ids and refresh_token_ids in the row.
          # Audit USER_SESSION_REVOKED with extra={"device_label": ..., "session_count": ..., "refresh_count": ...}.

      async def sign_out_others(self, user_id: UUID4, current_session_id: UUID4 | None) -> int:
          # delete_all_except_for_user(current) on both repos.
          # Audit USER_SESSIONS_SIGNED_OUT_OTHERS with extra={"revoked_count": ...}.
          # Returns total revoked count for the success flash.

      async def auto_revoke_others(
          self, user_id: UUID4, current_session_id: UUID4 | None, *, reason: str
      ) -> int:
          # Same as sign_out_others but audit USER_SESSIONS_AUTO_REVOKED with
          # extra={"reason": reason}. Reasons: "password_change",
          # "mfa_enrolled", "mfa_disabled", "recovery_code_used".
  ```
  Add factory `get_device_sessions_service` in `fief/dependencies/security.py` next to existing factories. Inject the three repos + audit logger.

  **UA → device_kind mapping:**
  - `ua.is_mobile` → `"phone"`
  - `ua.is_tablet` → `"tablet"`
  - `ua.is_pc` → `"computer"` (covers desktops AND laptops; `user_agents.is_pc` doesn't distinguish)
  - else → `"unknown"`

  **Device label:** `f"{ua.browser.family} on {ua.os.family}"` (e.g. "Safari on Mac OS X"). Empty UA → `"Unknown device"`.
- **validation:** Unit tests in T15.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T11: /security/sessions routes
- **depends_on:** [T10]
- **location:** `fief/apps/auth/routers/dashboard.py`
- **description:** Add three new routes mounted under the existing dashboard router (so they pick up the BaseContext including `brand`, `tenant`, `user`):
  - `GET /security/sessions` (name `auth.dashboard:sessions_index`) — calls `DeviceSessionsService.list_for_user(user.id, current_session_id=session_token.id)`. Renders `auth/dashboard/security/sessions.html` (T13) with `devices: list[DeviceRow]`.
  - `DELETE /security/sessions/{device_key}` (name `auth.dashboard:sessions_revoke`) — `device_key` is `sha256(",".join(sorted(session_token_ids) + sorted(refresh_token_ids)))[:16]`, computed by the service when listing. Server side: re-list devices, find the matching key. If no match, return **404** (handles the concurrent-double-click case — two clicks on the same Revoke button → second hits a stale key, gets 404 cleanly; HTMX swallows it as a no-op). On match, call `DeviceSessionsService.revoke(...)`. If the revoked row contains the current session, return a 303 redirect to `/login` — **no explicit `delete_cookie` needed**: the cookie's session token row is gone, so the next request's `get_session_token` returns None and the user is redirected to login anyway. Use HTMX for in-page row removal in the non-current case.
  - `POST /security/sessions/sign-out-others` (name `auth.dashboard:sessions_sign_out_others`) — calls `DeviceSessionsService.sign_out_others(user.id, current_session_id=session_token.id)`. Returns 200 + flash banner with the revoked count.

  Inject `session_token: SessionToken = Depends(get_session_token_or_login)` so we know the current session id. Cross-user authorization is enforced by `DeviceSessionsService.list_for_user(user.id, ...)` filtering — only devices owned by the requester appear in the candidate set, and the device_key reverse-lookup re-uses that same filtered list.
- **validation:** Integration tests in T16.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T12: Auto-revoke wires
- **depends_on:** [T2, T6, T7]
- **location:** `fief/apps/auth/routers/dashboard.py` (password change route + mfa_totp_confirm + mfa_totp_disable), `fief/apps/auth/routers/auth.py` (mfa_recover route)
- **description:** Inject `device_sessions_service: DeviceSessionsService = Depends(get_device_sessions_service)` and `session_token: SessionToken = Depends(get_session_token_or_login)` into each route, then call `await device_sessions_service.auto_revoke_others(user.id, current_session_id=session_token.id, reason=...)` AFTER the operation succeeds, with the appropriate `reason` value:
  - `update_password` (line 212) → `reason="password_change"`
  - `mfa_totp_confirm` (line 378) → `reason="mfa_enrolled"`
  - `mfa_totp_disable` (line 479) → `reason="mfa_disabled"`
  - `mfa_recover` in auth.py (line 871) → `reason="recovery_code_used"`. NOTE: the user is mid-login here (`mfa_pending_user_id` flow); the "current session" is the session that's about to be issued via `complete_login_after_mfa()`. Wire AFTER `complete_login_after_mfa()` so the new session's id is the `except` one.

  All four call sites add the same one-liner. Document the trigger reasons in the audit log entries so support can correlate "why did my other sessions get killed?" with a specific user action.
- **validation:** Integration tests in T17.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T13: Devices tab template
- **depends_on:** [T11]
- **location:** `fief/templates/auth/dashboard/security/sessions.html` (new)
- **description:** Extends `auth/dashboard/layout.html`. Match the visual language of the modernized Profile / Password / Security pages (glass card, gradient header tile).
  - Header: gradient teal-emerald icon tile with a "device" SVG, heading "Active sessions", subtitle "All the places you're currently signed in to your account.". Right-aligned "Sign out of all other sessions" button (POSTs to `auth.dashboard:sessions_sign_out_others`) — **render only when `devices | length > 1`** (no point if user only has the current session).
  - **Empty state** when `devices | length == 0` (rare but possible — e.g. cookie expired right before render): friendly note "No active sessions found." with a small icon.
  - **Single-session state** when `devices | length == 1` AND that one is the current device: heading reads "Just this device", suppress the "Sign out of all others" button, render the single row with the "This device" badge.
  - Table-style list (the normal case), one row per `DeviceRow`:
    - Device icon (computer / phone / tablet / generic SVG) inferred from `device_kind`
    - Device label headline + tiny `client_label` pill ("via LightNVR Web") if present
    - Sub-line: `{{ row.last_seen_ip or "—" }} · Last active {{ row.last_seen | timeago }}`
    - Right side: "This device" badge if `row.is_current`, else "Revoke" button (`hx-delete` to `/security/sessions/{device_key}` with `hx-confirm="Sign out of this device?"`, plus `hx-on::error="this.disabled=false"` so a 404 from a stale key doesn't leave the button disabled).
  - Bottom note (small grey text): "Signing out of a session won't end any active app calls until the access token expires (about 60 minutes)."
  - Privacy note (small grey text): "We don't store your location, only the IP address shown above."
- **validation:** Jinja parse + visual review across all 3 brands. UI-only, no TDD.
- **reason_not_testable:** pure HTML/Tailwind/HTMX template; verified by Jinja parse + visual review
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T14: Sidebar nav addition
- **depends_on:** []
- **location:** `fief/templates/auth/dashboard/sidebar.html`
- **description:** Add a fourth nav item "Devices" alongside Profile / Password / Security. Use the same gradient-active-state pattern. Active when `current_route == 'auth.dashboard:sessions_index'` or starts with `auth.dashboard:sessions_`. Suggested icon: a small "monitor + phone" SVG. Insert after the Security item (around line 82, before `</nav>`).
- **validation:** Jinja parse; visual hand-test confirms active highlighting matches Profile / Password / Security pattern.
- **reason_not_testable:** template only
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T15: Service unit tests — DeviceSessionsService
- **depends_on:** [T10]
- **location:** `tests/services/test_device_sessions_service.py` (new)
- **description:** Use an in-memory fake repo for SessionToken / RefreshToken (mirror MFA-1's recovery-codes test style). Cases:
  - List returns empty for user with no tokens.
  - List dedups two session tokens with same UA + OS + same /24 IP into one row.
  - List collects all token ids in `session_token_ids` / `refresh_token_ids`.
  - `is_current` flag is True on the row containing the passed `current_session_id`.
  - UA parse: `Mozilla/5.0 ...Safari` → `"Safari on Mac OS X"`. Empty UA → `"Unknown device"`.
  - `device_kind` mapping: mobile UA → `"phone"`, desktop UA → `"laptop"`.
  - Sort by last_seen desc.
  - `revoke(...)` deletes all underlying tokens and audits `USER_SESSION_REVOKED`.
  - `sign_out_others(user, current=X)` deletes all rows except the one containing X. Audits `USER_SESSIONS_SIGNED_OUT_OTHERS` with `revoked_count`.
  - `auto_revoke_others(...)` audits `USER_SESSIONS_AUTO_REVOKED` with the reason in `extra`.
  Run RED first.
- **validation:** `pytest tests/services/test_device_sessions_service.py` green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T16: Route integration tests
- **depends_on:** [T11]
- **location:** `tests/apps/auth/routers/test_sessions.py` (new)
- **description:**
  - GET `/security/sessions` for an authenticated user with 2 active sessions on different devices → 200, response includes both device labels and the current device is marked.
  - GET `/security/sessions` for a user with ONLY the current session (no other devices) → 200, single-session UX rendered correctly.
  - DELETE `/security/sessions/{device_key}` for a non-current row → 204; row is gone on next GET; audit `USER_SESSION_REVOKED` emitted with `device_label` and `revoked_session_count` in `extra`.
  - DELETE for the current session → 303 redirect to `/login`; subsequent request with the (now-stale) cookie returns 401 / redirects to login.
  - DELETE with a stale `device_key` (e.g. concurrent-revoke double-click) → 404; HTMX swallows.
  - DELETE with another user's `device_key` → 404 (authorization defence; the requester's `list_for_user` doesn't include other users' devices).
  - POST `/security/sessions/sign-out-others` → 200, audit `USER_SESSIONS_SIGNED_OUT_OTHERS` with `revoked_session_count` + `revoked_refresh_count`. Other devices return 401 on next request.
  Run RED first.
- **validation:** All cases green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T17: Auto-revocation tests
- **depends_on:** [T12]
- **location:** `tests/apps/auth/routers/test_auto_revoke_sessions.py` (new)
- **description:**
  - Password change → other sessions revoked, current preserved, audit `USER_SESSIONS_AUTO_REVOKED` with `reason="password_change"`.
  - MFA enroll confirm → same with `reason="mfa_enrolled"`.
  - MFA disable → same with `reason="mfa_disabled"`.
  - Recovery code used during /mfa/recover → same with `reason="recovery_code_used"`. The "current" session is the one minted by `complete_login_after_mfa` so all PRE-recovery sessions are revoked.
  Run RED first.
- **validation:** Tests green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T18: Dev rollout
- **depends_on:** [T15, T16, T17]
- **description:** `alembic upgrade head` against dev DB. Smoke test:
  - Sign in on dev env from two different browsers; verify both appear on `/security/sessions` with correct labels.
  - Click "Revoke" on the non-current row → it disappears and the OTHER browser gets logged out on next request.
  - Click "Sign out of all other sessions" with three devices → only the current one remains.
  - Trigger a password change → all other sessions auto-revoked.
- **validation:** All flows pass on dev; no errors in pod logs.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T19: Production rollout
- **depends_on:** [T18]
- **description:** Push image, watch GHCR build, `kubectl rollout restart deploy/opensensor-fief`. The migration adds 8 nullable columns — fully online-safe, no behavior change for existing rows. Confirm boot logs show no errors. Smoke-test on each brand (lightnvr / owlbooks / opensensor): visit `/security/sessions`, verify the current session shows correctly, no 5xx errors.
- **validation:** All 3 brands render the Devices tab; current session badge correct; revoke/sign-out-others both work; no support tickets in 24 h.
- **status:** Not Completed
- **log:**
- **files edited/created:**

## Parallel Execution Groups

| Wave | Tasks                       | Notes                                                |
|------|-----------------------------|------------------------------------------------------|
| 1    | T1, T2                      | Foundation; both parallel                            |
| 2    | T3, T4, T5                  | Schema; all parallel                                 |
| 3    | T6, T7                      | Repos; both parallel after their respective models   |
| 4    | T8, T9                      | Lifecycle hooks; different files, parallel          |
| 5    | T10                         | Service; needs T1+T6+T7                              |
| 6    | T11                         | Routes; needs T10                                    |
| 7    | T12                         | Auto-revoke wires; needs T2+T6+T7                    |
| 8    | T13, T14                    | UI; T13 needs T11 done, T14 standalone (parallel)   |
| 9    | T15, T16, T17               | Tests; parallel                                     |
| 10   | T18 → T19                   | Rollout, sequential                                  |

## Testing strategy
- Service unit tests use in-memory fake repos. Fast, deterministic, good coverage on the dedup + UA-parse logic.
- Integration tests use the existing `httpx.AsyncClient` test harness with real DB-backed SessionTokens / RefreshTokens.
- Auto-revoke tests are tightly scoped: pre-create N sessions, trigger the action, assert N-1 are gone and the current one remains.
- Manual smoke at T18 against dev cluster covers the cookie-cleared-on-revoke-current edge case (hard to test cleanly in unit because httpx session cookie behaviour).

## Risks & mitigations
- **`touch_last_seen` adds an UPDATE per protected dashboard request.** Negligible cost; `fief_session_tokens` is small. If we ever observe lock contention, batch the writes via a Redis-backed dirty queue (out of scope for v1). Add observability: track session-token UPDATE throughput in metrics.
- **Storing IPs is GDPR-relevant.** Mitigation: documented privacy note in UI; data export and deletion path tracked in a future PRD.
- **`user-agents` library updates regularly.** Pin a version; periodically refresh.
- **Stale UA across browser upgrades.** `created_user_agent` is captured ONCE at session creation and never updated. If a user upgrades their browser major version mid-session, the device label keeps showing the OLD family. Acceptable for v1 (the device_kind icon stays correct; user can still match it to their device by IP + last-active). If we ever update UA on every refresh, dedup logic needs to re-key existing rows.
- **Dedup `/24-of-IP` is too aggressive when users move offices.** Within a 24 h window same UA+OS gets one row regardless of IP shift; outside the window they appear as separate rows. This is OK for v1; revisit if support burden suggests otherwise.
- **OAuth refresh-token revocation cascades to access tokens?** A revoked refresh token can't mint new access tokens; the existing access token (~60 min lifetime) keeps working until expiry. The bottom-of-page UI note already sets this expectation.

## Plan revisions applied from subagent review (2026-05-09)
- **T2** — standardized audit-log `extra` schema (`revoked_session_count`, `revoked_refresh_count`, `trigger_reason`, `device_label`).
- **T3** — added explicit `CREATE INDEX` on `(user_id)` for both `fief_session_tokens` and `fief_refresh_tokens` (verified missing from initial migration). Plain `op.add_column` works without `op.batch_alter_table` for nullable adds; clarified.
- **T4 / T5** — added `index=True` on the existing `user_id` ForeignKey to keep model + DDL in sync.
- **T6** — `delete_by_id_for_user` returns `int` (rowcount) instead of `bool` for consistency with `delete_all_except_for_user`. `delete_all_except_for_user` now takes `except_ids: list[UUID4]` instead of a single id, supporting both the "keep current" and "revoke everything" semantics cleanly.
- **T7** — mirrors T6's signature change.
- **T8** — explicit caller cascade: 7 sites (not just MFA-1's `complete_login_after_mfa`) need the new `request` kwarg propagated in the same commit. Listed all 7 with line refs.
- **T10** — `device_kind` for desktops/laptops is `"computer"` (not `"laptop"`); `user_agents.is_pc` doesn't distinguish.
- **T11** — `device_key` defined precisely (`sha256(",".join(sorted(...)))[:16]`); stale-key returns 404 (handles concurrent double-click); revoke-current returns 303 redirect with NO explicit `delete_cookie` (next request's stale cookie fails to validate and redirects naturally).
- **T13** — added empty-state and single-session-state branches; suppress "Sign out of others" button when only current device exists.
- **T16** — added test cases for empty state, stale `device_key` 404, and cross-user 404.
- **Risks** — added stale-UA-across-browser-upgrades caveat and observability note for `touch_last_seen` UPDATE throughput.

## Open questions deferred to implementation
- **GeoIP follow-up.** When/if we add MaxMind, render city + country in the row sub-line.
- **Email notification on new sign-in.** "We noticed a sign-in from a new device" emails are a separate PRD; would lean on the existing brand-aware email infrastructure.
- **Push notification / SMS on revoke.** Out of scope.
