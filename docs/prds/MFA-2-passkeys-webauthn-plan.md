# Plan: MFA-2 — Passkeys / WebAuthn (v1: registration + 2FA only)

**Generated:** 2026-05-09
**Source PRD:** `docs/prds/MFA-2-passkeys-webauthn.md`
**Decisions locked in:**
- **v1 scope = registration + 2FA challenge only.** Discoverable / passwordless flow ("Sign in with a passkey" button on /login) is deferred to MFA-2.5 follow-up. v1 is ~17 tasks, 1 sprint.
- **Single MFA flag.** `users.mfa_enabled` stays as a generic "any-MFA-method-enrolled" boolean (matches MFA-1's design). At /mfa/* challenge time, the UI lets the user pick TOTP or passkey if both are enrolled. Registering ANY passkey flips `mfa_enabled=True`; deleting the LAST passkey AND no TOTP secret flips back to False.
- **Per-brand RP scope.** `rp_id = brand.host`, `rp_name = brand.name`, `origin = f"https://{brand.host}"`. A user with credentials on lightnvr.com and owlbooks.ai has separate passkey sets — by design (matches user expectation; cross-brand is a non-goal).
- **`userVerification = "preferred"`** (keeps YubiKey-without-PIN users working).
- **`attestation = "none"`** (no attestation requested; FIDO MDS validation out of scope per PRD non-goals).
- **Challenge storage = Redis** with `webauthn:{kind}:{key}` prefix and 300 s TTL. Reuses SEC-1's `get_redis()` dependency. No new schema for ephemeral challenges.
- **CSRF on JSON endpoints**: rely on SameSite=Lax cookies (FastAPI default) + same-origin checks. WebAuthn JSON POSTs come from same-origin JS so this is sufficient.

## Overview
Add WebAuthn / passkey registration on the dashboard and passkey-as-a-second-factor at the existing `/mfa/*` challenge surface. Layers cleanly onto MFA-1's primitives: `LoginSession.mfa_pending_user_id` gates the challenge, the same audit-logger pattern carries new event types, and the same dashboard router hosts the new routes.

Reference points (from codebase exploration):
- LoginSession `mfa_pending_user_id` already exists (`fief/models/login_session.py:79-88`, MFA-1 T8).
- Existing /mfa/* challenge routes at `fief/apps/auth/routers/auth.py:734` (`/mfa/totp`) and `:873` (`/mfa/recover`). MFA-2 adds `/mfa/passkey` alongside.
- Existing /security/mfa dashboard routes at `fief/apps/auth/routers/dashboard.py:329-512`. MFA-2 adds `/security/passkeys/*` alongside.
- Existing services at `fief/services/security/{totp,recovery_codes}.py`. MFA-2 adds `webauthn.py`.
- Service factories at `fief/dependencies/security.py`. MFA-2 adds `get_webauthn_service`.
- Brand resolution: `brand.host` (e.g. `"members.lightnvr.com"`) at `fief/models/brand.py:16`, resolved via `get_current_brand` per request.
- `users.mfa_enabled` is a generic flag (MFA-1 T8); MFA-2 keeps that semantic.
- Most-recent migration head is `0929dd1d8a8c` (UX-1 T3).
- Audit log enum at `fief/models/audit_log.py:13-51`.
- JS bundling via rollup, output to `fief/static/*.bundle.js` (sources at `js/*.mjs`). Per-credential JS bridge lives there.
- Session-token validation dep auto-touches `last_seen_*` (UX-1 T8) — no impact on MFA-2.
- SEC-1 Redis client at `fief/dependencies/redis.py` for challenge storage.

## Prerequisites
- `webauthn >= 2.0` declared in `pyproject.toml`. The library is `py_webauthn` from Duo Labs (pip name `webauthn`). Mature, MIT, async-friendly.
- Redis (already wired by SEC-1).
- HTTPS in dev (passkeys do NOT work over plain HTTP except on `localhost`). Production already runs HTTPS via cert-manager. For dev rollout, `members.opensensor.dev` (or whatever local hostname) needs a working cert OR test on `localhost:port`.

## Dependency Graph

```
Wave 1 (Foundation) — parallel
  T1 deps          T2 audit-log enum

Wave 2 (Schema) — parallel
  T3 alembic migration   T4 UserWebAuthnCredential model + User relationship

Wave 3 (Repo)
  T5 UserWebAuthnCredentialRepository (T4)

Wave 4 (Service)
  T6 WebAuthnService — register/verify + sign_count rollback (T1, T5, redis from SEC-1)

Wave 5 (Dashboard register routes) — parallel
  T7 /security/passkeys routes (list / register-begin / register-finish / rename / delete) (T6)
  T8 JS bridge (webauthn.mjs → bundle) (T1)

Wave 6 (Login challenge routes)
  T9 /mfa/passkey GET + POST — adds passkey as sibling to /mfa/totp + /mfa/recover (T6)

Wave 7 (UI)
  T10 /security/passkeys page template (T7)
  T11 /mfa/passkey challenge template + "Use passkey instead" link on /mfa/totp + /mfa/recover (T9, T8)
  T12 Surface passkey enrollment on /security/mfa landing (links to /security/passkeys; small) (T7)

Wave 8 (State coherence)
  T13 mfa_enabled flag transitions (flip on first passkey registered; flip off when last passkey deleted AND no TOTP secret) (T6)
  T14 Auto-revoke other sessions on passkey register/delete (UX-1 hook) (T7, UX-1 T12 already exists)

Wave 9 (Tests) — most subsumed by upstream TDD
  T15 WebAuthnService unit tests (T6)
  T16 Dashboard register flow integration (T7, T13)
  T17 Login challenge flow integration (T9)

Wave 10 (Rollout)
  T18 Dev rollout (T15-T17)
  T19 Production rollout (T18)
```

## Tasks

### T1: Add Python dependencies
- **depends_on:** []
- **location:** `pyproject.toml`
- **description:** Add `webauthn >= 2.0, < 3` to `[project].dependencies`. The library is from Duo Labs (`py_webauthn`); pip name is `webauthn`. v2.x has a stable API: `generate_registration_options`, `verify_registration_response`, `generate_authentication_options`, `verify_authentication_response`. Pin the major to avoid silent breakage on a v3 release.
- **validation:** `python -c "import webauthn; print(webauthn.__version__)"` returns ≥2.0,<3.
- **reason_not_testable:** configuration; verified by import smoke
- **status:** Completed
- **log:**
  - 2026-05-09: Added `"webauthn >=2.0,<3"` to `[project].dependencies` between `uvicorn[standard]` and `WTForms` (alphabetical placement). Installed into the local `.venv` via `pip3 install 'webauthn>=2.0,<3'`; smoke `python -c "import webauthn; print(webauthn.__version__)"` returned `2.7.1`. Committed pyproject.toml only.
- **files edited/created:**
  - `pyproject.toml`

### T2: Audit-log enum additions
- **depends_on:** []
- **location:** `fief/models/audit_log.py`
- **description:** Add five new members to `AuditLogMessage`:
  - `USER_PASSKEY_REGISTERED` — user successfully registered a new credential.
  - `USER_PASSKEY_DELETED` — user removed a credential from their dashboard.
  - `USER_PASSKEY_VERIFIED` — successful 2FA assertion at `/mfa/passkey/verify`.
  - `USER_PASSKEY_VERIFY_FAILED` — bad assertion. `extra={"reason": "invalid_signature" | "credential_not_found" | "challenge_expired"}`.
  - `USER_PASSKEY_SIGN_COUNT_ROLLBACK` — assertion's sign_count ≤ stored. Treated as a security event (possible cloned authenticator).

  Match existing `USER_*` style. Place after the UX-1 audit-log additions.
- **validation:** Import smoke confirms the five members.
- **reason_not_testable:** enum-only addition; verified by import smoke
- **status:** Completed
- **log:**
  - 2026-05-09: Added five `USER_PASSKEY_*` members to `AuditLogMessage` after `USER_SESSIONS_AUTO_REVOKED`, with a comment block documenting `extra` shapes for `USER_PASSKEY_VERIFY_FAILED` and `USER_PASSKEY_SIGN_COUNT_ROLLBACK`. Smoke check `python -c "from fief.models.audit_log import AuditLogMessage; [print(m) for m in AuditLogMessage if 'PASSKEY' in m.name]"` prints all five.
- **files edited/created:**
  - `fief/models/audit_log.py`

**Note on cross-dialect storage in T3.** The PRD shows `transports text[]` (Postgres array). The plan uses comma-separated `TEXT` instead so SQLite tests don't need a special-case. Service code converts to/from `list[str]`. Intentional divergence from the PRD.

### T3: Alembic migration — fief_user_webauthn_credentials
- **depends_on:** []
- **location:** `fief/alembic/versions/2026-05-09h_add_user_webauthn_credentials.py` (new — letter `h` because UX-1 took `g`)
- **description:**
  - `revision = "<new 12-char hex>"`, `down_revision = "0929dd1d8a8c"` (UX-1 head).
  - Schema:
    ```sql
    CREATE TABLE fief_user_webauthn_credentials (
      id                 UUID PRIMARY KEY,
      user_id            UUID NOT NULL REFERENCES fief_users(id) ON DELETE CASCADE,
      credential_id      BYTEA NOT NULL,
      public_key         BYTEA NOT NULL,
      sign_count         BIGINT NOT NULL DEFAULT 0,
      transports         TEXT NULL,                       -- comma-separated: "internal,hybrid,usb,nfc,ble"
      aaguid             UUID NULL,
      backup_eligible    BOOLEAN NOT NULL DEFAULT false,
      backup_state       BOOLEAN NOT NULL DEFAULT false,
      label              TEXT NULL,                       -- user-chosen, e.g. "MacBook"
      attestation_obj    BYTEA NULL,                      -- raw attestation, optional
      last_used_at       TIMESTAMPTZ NULL,
      created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX ix_fief_user_webauthn_credentials_credential_id ON fief_user_webauthn_credentials(credential_id);
    CREATE INDEX ix_fief_user_webauthn_credentials_user_id ON fief_user_webauthn_credentials(user_id);
    ```
    - `credential_id` MUST be unique (it's the WebAuthn-side identifier; assertion lookup uses it).
    - `transports` stored as comma-separated text (cross-dialect; arrays only work on PG natively). Service code parses to/from `list[str]`.
  - `down()` drops indexes then table.
  - Use `op.get_context().opts["table_prefix"]` codemod placeholder. Mirror prior migrations.
- **validation:** Migration parser run + `alembic heads` shows the new revision as head. Live up/down/up deferred to T18.
- **reason_not_testable:** SQL DDL migration; verified by alembic head check + parser run
- **status:** Completed
- **log:**
  - 2026-05-09 — Created `fief/alembic/versions/2026-05-09h_add_user_webauthn_credentials.py` with `revision = "2b952240a094"` and `down_revision = "0929dd1d8a8c"` (UX-1 head). Mirrors prior migrations' `op.get_context().opts["table_prefix"]` codemod pattern. Schema matches the spec: 13 columns, FK to `fief_users(id)` ON DELETE CASCADE, unique index on `credential_id`, plain index on `user_id`. `transports` stored as comma-separated TEXT (intentional cross-dialect divergence); `aaguid` typed as the project's `GUID()` for SQLite/Postgres compatibility. All non-FK/non-bytea columns are either nullable or have server defaults — fully online-safe. Verified via parser smoke (`python -c "import importlib.util ..."`) printing `2b952240a094 0929dd1d8a8c`, and `alembic heads` reporting `2b952240a094 (head)`.
- **files edited/created:**
  - `fief/alembic/versions/2026-05-09h_add_user_webauthn_credentials.py` (new)

### T4: UserWebAuthnCredential model + User relationship
- **depends_on:** []
- **location:** `fief/models/user_webauthn_credential.py` (new), `fief/models/__init__.py` (add import + `__all__`), `fief/models/user.py` (add `webauthn_credentials` relationship)
- **description:** Standard SQLAlchemy declarative model matching T3's schema. Use `UUIDModel` + `CreatedUpdatedAt` mixins as in MFA-1's `UserTotpSecret`. Relationship: `user = relationship("User", back_populates="webauthn_credentials")` (string-based).

  On `User` (small surgical edit, like MFA-1 T8): add `webauthn_credentials: Mapped[list["UserWebAuthnCredential"]] = relationship("UserWebAuthnCredential", back_populates="user", cascade="all, delete-orphan")`.

  `transports` field: store as `Text`, expose as `list[str]` via a property (`@property def transports_list` getter) — keeps the column cross-dialect.
- **validation:** Smoke import + assert mapper resolves cleanly.
- **status:** Completed
- **log:**
  - 2026-05-09: Added `UserWebAuthnCredential` declarative model (UUIDModel + CreatedUpdatedAt mixins) at `fief/models/user_webauthn_credential.py` matching T3's schema. FK uses the project's standard `ForeignKey(User.id, ondelete="CASCADE")` idiom (mirrors `UserLockout` / `UserTotpSecret`). `transports_list` property returns `[]` for None/empty and splits comma-separated values with whitespace stripping. Added `UserWebAuthnCredential` import + `__all__` entry to `fief/models/__init__.py` (alphabetical, between `UserTotpSecret` and `Webhook`). Added `webauthn_credentials` relationship on `User` with `cascade="all, delete-orphan"` and `TYPE_CHECKING` import. TDD: wrote 21 unit tests in `tests/models/test_user_webauthn_credential_model.py` covering import, table name, column metadata (types, defaults, nullability, unique/index), `transports_list` parsing edge cases, and back-relationship resolution. RED first (ImportError), then GREEN: 21/21 pass; full `tests/models/` suite (48 tests) green.
- **files edited/created:**
  - `fief/models/user_webauthn_credential.py` (new)
  - `fief/models/__init__.py`
  - `fief/models/user.py`
  - `tests/models/test_user_webauthn_credential_model.py` (new)

### T5: UserWebAuthnCredentialRepository
- **depends_on:** [T4]
- **location:** `fief/repositories/user_webauthn_credential.py` (new), `fief/repositories/__init__.py` (export)
- **description:** Standard `BaseRepository`-derived class. Methods:
  - `async list_by_user_id(user_id) -> list[UserWebAuthnCredential]` — order by `created_at DESC`.
  - `async get_by_credential_id(credential_id: bytes) -> UserWebAuthnCredential | None` — for assertion lookup.
  - `async get_by_id_for_user(id, user_id) -> UserWebAuthnCredential | None` — for delete + rename.
  - `async delete_by_id_for_user(id, user_id) -> int` — user-scoped delete; returns rowcount.
  - `async count_for_user(user_id) -> int` — needed for "is this the last credential?" guard in T13.
  - `async update_after_assertion(credential_id: bytes, *, sign_count: int, last_used_at: datetime) -> None` — UPDATE on successful verify.
  - `async rename_by_id_for_user(id, user_id, label: str) -> int` — for the rename endpoint.
- **validation:** Smoke test confirms method signatures.
- **status:** Completed
- **log:**
  - 2026-05-09: Implemented `UserWebAuthnCredentialRepository(BaseRepository[UserWebAuthnCredential], UUIDRepositoryMixin[...])` with all seven required methods. `list_by_user_id` orders by `created_at DESC`. `get_by_credential_id` and `get_by_id_for_user` use `select` + `get_one_or_none`. `delete_by_id_for_user` and `rename_by_id_for_user` use `delete()` / `update()` core statements via `_execute_statement` and return `result.rowcount or 0` (so callers can detect 404 / rowcount==0). `count_for_user` uses `select(func.count()).select_from(...)`. `update_after_assertion` uses an `update()` core statement keyed on `credential_id` so the row update doesn't depend on a prior load. Added export to `fief/repositories/__init__.py` alphabetically (between `UserTotpSecretRepository` and `WebhookRepository`). TDD: 10 smoke tests in `tests/repositories/test_user_webauthn_credential_repo_smoke.py` covering import, `BaseRepository` subclass, model binding, and signatures (param names, async, kwarg-only flags on `update_after_assertion`, return-type annotations on rowcount/count methods). RED first (ImportError), then GREEN: 10/10 pass; full `tests/repositories/` suite (41 tests) green.
- **files edited/created:**
  - `fief/repositories/user_webauthn_credential.py` (new)
  - `fief/repositories/__init__.py`
  - `tests/repositories/test_user_webauthn_credential_repo_smoke.py` (new)

### T6: WebAuthnService — register/verify + sign_count rollback
- **depends_on:** [T1, T5]
- **location:** `fief/services/security/webauthn.py` (new), `fief/dependencies/security.py` (factory)
- **description:**
  ```python
  from webauthn import (
      generate_registration_options,
      verify_registration_response,
      generate_authentication_options,
      verify_authentication_response,
  )
  from webauthn.helpers.structs import (
      AuthenticatorSelectionCriteria,
      UserVerificationRequirement,
      RegistrationCredential,
      AuthenticationCredential,
      PublicKeyCredentialDescriptor,
  )

  class WebAuthnError(Exception): ...
  class CredentialNotFound(WebAuthnError): ...
  class SignCountRollback(WebAuthnError): ...
  class ChallengeExpired(WebAuthnError): ...
  class InvalidAssertion(WebAuthnError): ...

  class WebAuthnService:
      """Encapsulates py_webauthn so routes never touch the library directly."""

      CHALLENGE_TTL_SECONDS = 300

      def __init__(
          self,
          credential_repo: UserWebAuthnCredentialRepository,
          redis: redis.asyncio.Redis,
          audit_logger: AuditLogger,
      ): ...

      async def begin_registration(
          self,
          *,
          user: User,
          rp_id: str,
          rp_name: str,
      ) -> dict:
          """Return PublicKeyCredentialCreationOptions JSON. Stores the
          challenge in Redis at `webauthn:reg:{user.id}` with TTL=300s.
          excludeCredentials = user's existing credentials (so the same
          authenticator isn't re-registered).
          userVerification = "preferred", attestation = "none".
          """

      async def finish_registration(
          self,
          *,
          user: User,
          rp_id: str,
          origin: str,
          attestation_response: dict,
      ) -> UserWebAuthnCredential:
          """Pop challenge from Redis (or raise ChallengeExpired). Call
          verify_registration_response. Persist UserWebAuthnCredential row.
          Audit USER_PASSKEY_REGISTERED. Returns the new credential row."""

      async def begin_assertion(
          self,
          *,
          user: User,
          rp_id: str,
          login_session_id: UUID,
      ) -> dict:
          """Return PublicKeyCredentialRequestOptions JSON.
          allowCredentials = user's credentials. Stores challenge at
          `webauthn:auth:{login_session_id}` with TTL=300s."""

      async def verify_assertion(
          self,
          *,
          user: User,
          rp_id: str,
          origin: str,
          login_session_id: UUID,
          assertion_response: dict,
      ) -> UserWebAuthnCredential:
          """Pop challenge. Look up credential by credential_id (or raise
          CredentialNotFound). Call verify_authentication_response.
          Detect sign_count rollback: if response.sign_count <=
          credential.sign_count AND credential.sign_count > 0, raise
          SignCountRollback (and audit USER_PASSKEY_SIGN_COUNT_ROLLBACK).
          On success: update_after_assertion(credential_id, sign_count, now).
          Audit USER_PASSKEY_VERIFIED. Return the credential row."""

      async def list_for_user(self, user: User) -> list[UserWebAuthnCredential]: ...

      async def delete(
          self,
          *,
          user: User,
          credential_id: UUID,
      ) -> bool:
          """User-scoped delete. Returns True if a row was deleted (so the
          route can 404 on missing). Audit USER_PASSKEY_DELETED."""
  ```

  Factory in `fief/dependencies/security.py`:
  ```python
  async def get_webauthn_service(
      cred_repo: UserWebAuthnCredentialRepository = Depends(get_repository(UserWebAuthnCredentialRepository)),
      redis_client: redis.asyncio.Redis = Depends(get_redis),
      audit_logger: AuditLogger = Depends(get_audit_logger),
  ) -> WebAuthnService:
      return WebAuthnService(cred_repo, redis_client, audit_logger)
  ```

  Helper for `rp_id` / `origin` derivation (in the same module):
  ```python
  def derive_rp_params(brand: Brand | None, tenant: Tenant) -> tuple[str, str, str]:
      """Returns (rp_id, rp_name, origin)."""
      if brand and brand.host:
          return brand.host, brand.name, f"https://{brand.host}"
      # Fallback: use tenant defaults.
      return tenant.default_host, tenant.name, f"https://{tenant.default_host}"
  ```

  **`origin` matching is exact-string.** `verify_registration_response` and `verify_authentication_response` strict-compare the `origin` field in `clientDataJSON` against the value passed via `expected_origin=`. For HTTPS on default port, the canonical form is `https://members.lightnvr.com` (NO `:443`). `brand.host` already contains just the hostname (no scheme, no port, verified at `fief/models/brand.py`). Pass `f"https://{brand.host}"` exactly.

  **Concrete field mapping from `verify_registration_response`'s `VerifiedRegistration`:**
  - `verified.credential_id` → `UserWebAuthnCredential.credential_id` (bytes, raw)
  - `verified.credential_public_key` → `public_key` (bytes, COSE-encoded)
  - `verified.sign_count` → `sign_count` (int)
  - `verified.aaguid` → `aaguid` (UUID-string, cast via `uuid.UUID(...)` or None if `"00000000-..."`)
  - `verified.credential_backed_up` → `backup_state` (bool)
  - `verified.credential_device_type == "multi_device"` → `backup_eligible` (bool)
  - `transports` from the client's `attestation_response` (list → comma-joined string)

  **And from `verify_authentication_response`'s `VerifiedAuthentication`:**
  - `verified.new_sign_count` → compared against stored, then UPDATEd.

  **`generate_registration_options(...)` required args:**
  ```python
  options = generate_registration_options(
      rp_id=rp_id,
      rp_name=rp_name,
      user_id=str(user.id).encode("utf-8"),     # required as bytes in v2.x
      user_name=user.email,
      user_display_name=user.email,             # we don't track display names; reuse email
      exclude_credentials=[
          PublicKeyCredentialDescriptor(
              id=cred.credential_id,
              transports=[AuthenticatorTransport(t) for t in cred.transports_list]
                         if cred.transports else None,
          )
          for cred in existing_credentials
      ],
      authenticator_selection=AuthenticatorSelectionCriteria(
          user_verification=UserVerificationRequirement.PREFERRED,
      ),
      attestation=AttestationConveyancePreference.NONE,
  )
  ```

  **`generate_authentication_options(...)` required args:** mirror with `allow_credentials` instead of `exclude_credentials`.

  **Challenge persistence shape (Redis):**
  - On begin: `options.challenge` is `bytes`. Persist as `base64.urlsafe_b64encode(options.challenge).rstrip(b"=").decode()` (URL-safe, padding-stripped, str). Key: `webauthn:reg:{user.id}` or `webauthn:auth:{login_session_id}`. TTL = 300 s.
  - On finish: read the str, decode back to `bytes` via `base64.urlsafe_b64decode(s + "==")` (re-pad), pass as `expected_challenge=` to the verify call.

  **Sign-count handling:** py_webauthn returns the `new_sign_count`. We compare against stored `sign_count`:
  - If stored is 0 (first use) → accept, store new value.
  - If `new_sign_count > stored` → accept, update.
  - If `new_sign_count <= stored` AND stored > 0 → REJECT, audit `USER_PASSKEY_SIGN_COUNT_ROLLBACK` with `extra={"credential_id_hex": ..., "stored": ..., "received": ...}`. This usually means a cloned authenticator.
  - Apple/Google passkeys often return `new_sign_count = 0` always (they don't track) — accept these as-is and skip the rollback check.
- **validation:** Unit tests in T15.
- **status:** Completed
- **log:**
  - 2026-05-09: Implemented `WebAuthnService` (and the five typed exceptions `WebAuthnError`/`CredentialNotFound`/`SignCountRollback`/`ChallengeExpired`/`InvalidAssertion`) in `fief/services/security/webauthn.py`, plus the module-level `derive_rp_params(brand, tenant)` helper. Methods: `begin_registration` / `finish_registration` / `begin_assertion` / `verify_assertion` / `list_for_user` / `delete`. Challenge persistence uses Redis with key `webauthn:reg:{user.id}` (registration) or `webauthn:auth:{login_session_id}` (assertion), TTL 300 s, value Base64URL-encoded with padding stripped. `finish_*` deletes the challenge before invoking the verifier (one-shot replay guard). `verify_assertion` enforces sign-count rollback when `new_sign_count <= cred.sign_count` AND `cred.sign_count > 0` AND `new_sign_count != 0` (Apple/Google sync passkeys always report 0 → accepted as-is). All five `USER_PASSKEY_*` audit events fire from the right places with `subject_user_id` and the planned `extra` shapes. Wrapped `InvalidRegistrationResponse` / `InvalidAuthenticationResponse` in `InvalidAssertion` so route code never touches the upstream lib. Added `get_webauthn_service` factory in `fief/dependencies/security.py` (plus the `WebAuthnService` import and `__all__` entry). TDD: wrote 22 unit tests in `tests/services/test_webauthn_service.py` using `fakeredis.aioredis.FakeRedis` for challenge storage, `monkeypatch` of `verify_registration_response` / `verify_authentication_response` for deterministic outcomes, and an in-memory `_FakeCredentialRepo`. Cases cover the full T15 list: begin/finish registration happy path, expired challenge, one-shot replay guard, invalid attestation, begin/verify assertion happy path, unknown rawId, sign-count rollback, Apple/Google zero accept, first-use zero-stored accept, invalid signature, list/delete (real, missing, foreign), plus three `derive_rp_params` cases (brand, tenant fallback strips scheme/path/port, brand-empty-host falls through). RED first (verified by running prior to implementation files), then GREEN: 22/22 pass; full `tests/services/` suite (133 tests) green; `tests/dependencies/` (19 tests) green — no regressions in existing factories.
- **files edited/created:**
  - `fief/services/security/webauthn.py` (new)
  - `fief/dependencies/security.py`
  - `tests/services/test_webauthn_service.py` (new)

### T7: /security/passkeys dashboard routes
- **depends_on:** [T6]
- **location:** `fief/apps/auth/routers/dashboard.py`
- **description:** Add five routes:
  - `GET /security/passkeys` (name `auth.dashboard:passkeys_index`) — calls `webauthn_service.list_for_user(user)`. Renders `auth/dashboard/security/passkeys.html` (T10) with the credential list. Includes brand/tenant/user from BaseContext.
  - `POST /security/passkeys/register/begin` — JSON: returns `PublicKeyCredentialCreationOptions`. Calls `webauthn_service.begin_registration(user, rp_id=brand.host, rp_name=brand.name)`.
  - `POST /security/passkeys/register/finish` — JSON: accepts attestation response, calls `webauthn_service.finish_registration(...)`. On success: flip `user.mfa_enabled = True` if not already (T13 helper). Audit-revoke other sessions per UX-1 hook (T14). Return the persisted credential's id + label.
  - `PATCH /security/passkeys/{credential_id}` — JSON: accepts `{"label": "..."}`. Calls `credential_repo.rename_by_id_for_user(...)`.
  - `DELETE /security/passkeys/{credential_id}` — calls `webauthn_service.delete(user, credential_id)`. On success, T13 transitions `mfa_enabled` if this was the last credential AND no TOTP. Returns 204 or 404.

  **No "last credential" guard in v1.** PRD line 82 mandates a guard preventing deletion of the only second factor. v1 omits it: T13's `_recompute_mfa_enabled` flips `mfa_enabled=False` cleanly when the user removes their last factor. The user is opting out of MFA, which is their right. Re-enrollment is one click away. If support reports confusion, add the guard as a follow-up.
- **validation:** Integration tests in T16.
- **status:** Completed
- **log:**
  - Added five routes to `dashboard.py`: `GET /security/passkeys`, `POST /security/passkeys/register/begin`, `POST /security/passkeys/register/finish`, `PATCH /security/passkeys/{credential_id}`, `DELETE /security/passkeys/{credential_id}`.
  - Inlined T13's `_recompute_mfa_enabled` helper (re-derives `users.mfa_enabled` from confirmed-TOTP + WebAuthn count). T13 will lift this into a shared helper.
  - Wired T14's `auto_revoke_others` hook on register (`reason="passkey_registered"`) and delete (`reason="passkey_deleted"`).
  - `credential_id` route param typed as `UUID` so FastAPI parses + validates path segments before they reach the service/repo.
  - Tests in `tests/apps/auth/routers/test_dashboard_passkeys.py` cover: list (empty + populated), register begin (returns options JSON), register finish (persists, flips `mfa_enabled`, triggers `auto_revoke_others`), rename (204 + 404), delete (204 + 404, recomputes `mfa_enabled` to False, triggers `auto_revoke_others`). Fake `WebAuthnService` injected via `app.dependency_overrides`; persists the cred to the real repo on `finish_registration` so downstream `count_for_user` matches real-service behaviour.
- **files edited/created:**
  - `fief/apps/auth/routers/dashboard.py` (edited — added imports + five routes + `_recompute_mfa_enabled` helper)
  - `tests/apps/auth/routers/test_dashboard_passkeys.py` (new)

### T8: WebAuthn JS bridge
- **depends_on:** [T1]
- **location:** `js/webauthn.mjs` (new), `rollup.config.js` (add entry), `package.json` (add `@simplewebauthn/browser` dep)
- **description:** Tiny ES-module that wraps the browser WebAuthn API. **CSRF: drop the explicit token.** The dashboard cookie is `SameSite=Lax` (FastAPI default) and the JSON POSTs require `Content-Type: application/json` which forces a CORS preflight on cross-origin requests — the combination is sufficient defence for v1. There is no existing CSRF middleware in the codebase to plug into; adding token plumbing without server validation would be theatre.

  ```js
  // js/webauthn.mjs
  import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

  export async function registerPasskey(beginUrl, finishUrl) {
      const optionsResp = await fetch(beginUrl, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
      });
      if (!optionsResp.ok) throw new Error('begin failed');
      const options = await optionsResp.json();
      const attestation = await startRegistration(options);
      const finishResp = await fetch(finishUrl, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(attestation),
      });
      if (!finishResp.ok) throw new Error('finish failed');
      return await finishResp.json();
  }

  // For the 2FA-challenge case, options are embedded server-side so we don't fetch them.
  export async function authenticateWithEmbeddedOptions(options, finishUrl) {
      const assertion = await startAuthentication(options);
      const finishResp = await fetch(finishUrl, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(assertion),
      });
      if (!finishResp.ok) throw new Error('verify failed');
      return await finishResp.json();
  }
  ```

  Pin `@simplewebauthn/browser >= 9, < 11` in `package.json`. Add a rollup entry that bundles `js/webauthn.mjs` → `fief/static/webauthn.bundle.js` (mirror the existing `code-editor.mjs` entry pattern).
- **validation:** `npm run build` succeeds and produces `fief/static/webauthn.bundle.js`. Pinned majors align: `webauthn` (Python) v2.x is wire-compatible with `@simplewebauthn/browser` v9-10.
- **reason_not_testable:** JS bundle; verified by build success + non-empty output file
- **status:** Completed
- **log:**
  - 2026-05-09: Added `@simplewebauthn/browser` to `package.json` `dependencies` with range `>=9.0.0 <11.0.0` (the spec requested "^9.0.0" but allowing up to v10; using an explicit `>=9 <11` range is the cleanest way to express that since `^9.0.0` would cap at `<10`). Ran `npm install` to refresh `package-lock.json` (resolves `@simplewebauthn/browser@9.0.1` + transitive `@simplewebauthn/types@9.0.1`). Created `js/webauthn.mjs` exporting `registerPasskey(beginUrl, finishUrl)` and `authenticateWithEmbeddedOptions(options, finishUrl)` per spec — both use `credentials: 'same-origin'` and `Content-Type: application/json` for SameSite-Lax cookie + CORS-preflight CSRF defence (no token plumbing per locked-in decision). Added rollup entry that bundles `js/webauthn.mjs` → `fief/static/webauthn.bundle.js` mirroring the `code-editor.mjs` entry: `format: 'iife'` with `name: 'fiefWebauthn'`, plugin chain `nodeResolve()` → `babel({ babelHelpers: 'runtime' })` → `terser()`. `npm run build` succeeded; emitted `fief/static/webauthn.bundle.js` at 7,755 bytes (non-empty, minified). Bundle is gitignored via `fief/static/*.js` (existing rule), so only sources are committed.
- **files edited/created:**
  - `js/webauthn.mjs` (new)
  - `rollup.config.js`
  - `package.json`
  - `package-lock.json`

### T9: /mfa/passkey challenge route
- **depends_on:** [T6]
- **location:** `fief/apps/auth/routers/auth.py`
- **description:** Add two new routes alongside `/mfa/totp` and `/mfa/recover`:
  - `GET /mfa/passkey` (name `auth:mfa_passkey`) — same gating as `/mfa/totp`: requires LoginSession with `mfa_pending_user_id` set, cookie-bound, not locked. Renders `auth/mfa/passkey.html` (T11). Pre-fetches the assertion options server-side via `webauthn_service.begin_assertion(...)` and embeds them as a JSON-serialized object in the template — the JS bridge calls `authenticateWithEmbeddedOptions(options, "/mfa/passkey/verify")` (T8 export) instead of fetching from a separate `/begin` URL.

  **Empty-passkey-list short-circuit:** if `webauthn_service.list_for_user(user)` returns `[]`, redirect to `/mfa/totp` (or to `/login` if user also has no TOTP — but that's an inconsistent-state case caught upstream by MFA-1's defensive check). The user shouldn't have reached `/mfa/passkey` if they have no passkeys; this is a defensive redirect.
  - `POST /mfa/passkey/verify` (name `auth:mfa_passkey_verify`) — JSON. Body = WebAuthn assertion response. Calls `webauthn_service.verify_assertion(user, rp_id, origin, login_session_id, assertion_response)`.
    - On `CredentialNotFound`: increment `mfa_attempts_count` (same lockout ladder as TOTP). Audit `USER_PASSKEY_VERIFY_FAILED` with `extra={"reason": "credential_not_found"}`. Return 401.
    - On `ChallengeExpired`: 400 Bad Request with `{"error": "challenge_expired", "detail": "Please reload the page and try again."}`. (400 over 410 because JS frameworks treat 410 as fatal; 400 with a typed error code is more idiomatic.)
    - On `InvalidAssertion`: increment counter, audit. Return 401.
    - On `SignCountRollback`: do NOT increment counter (the credential is suspect, not the attempt count); audit `USER_PASSKEY_SIGN_COUNT_ROLLBACK`. Return 401 with generic error.
    - On success: clear MFA carry-state. Call `complete_login_after_mfa(...)` (the helper from MFA-1 T15) so the post-login redirect + new session match the TOTP path exactly. Audit `USER_PASSKEY_VERIFIED`.

  **No `POST /mfa/passkey/begin` route in v1**: the GET handler embeds options in the page. This avoids the JS-fetch ceremony for the 2FA case. (Discoverable flow in MFA-2.5 will need a dedicated `/begin` endpoint.)
- **validation:** Integration tests in T17.
- **status:** Completed
- **log:** Added `GET /mfa/passkey` (name `auth:mfa_passkey`) and `POST /mfa/passkey/verify` (name `auth:mfa_passkey_verify`) alongside `/mfa/totp` + `/mfa/recover`. Both share `_gate_mfa_challenge` for cookie-binding, lockout, and user-existence checks. The GET short-circuits to `/mfa/totp` when `webauthn_service.list_for_user(user)` is empty, otherwise calls `begin_assertion(user, rp_id, login_session_id)` and renders `auth/mfa/passkey.html` with `options` in the context. The POST is JSON: `CredentialNotFound` and `InvalidAssertion` increment the per-LoginSession counter (parity with TOTP) and return 401 `{"error":"invalid"}`. `SignCountRollback` returns 401 `{"error":"credential_compromised"}` WITHOUT incrementing (credential-defect, not user-attributable). `ChallengeExpired` returns 400 `{"error":"challenge_expired"}` and the counter stays. Success returns `{"redirect_to": <verify_email_request URL>}` with the new session cookie set on the JSONResponse via `complete_login_after_mfa`. Tests cover all 13 cases (gating, short-circuit, success, four failure modes, lockout) — RED-then-GREEN. Regression: `test_mfa_challenge.py` + `test_login_mfa_branch.py` still pass.
- **files edited/created:**
  - `fief/apps/auth/routers/auth.py`
  - `tests/apps/auth/routers/test_mfa_passkey.py`

### T10: /security/passkeys page template
- **depends_on:** [T7]
- **location:** `fief/templates/auth/dashboard/security/passkeys.html` (new)
- **description:** Extends `auth/dashboard/layout.html`. Match the visual language of the other Security pages.
  - Header: gradient teal-emerald icon tile (key/shield SVG) + heading "Passkeys" + subtitle "Use your fingerprint, face, or a security key to sign in without typing a code."
  - "Add a passkey" button — gradient teal-emerald. On click, runs the `registerPasskey` JS (loaded from `webauthn.bundle.js`).
  - Credential list (one row per credential):
    - Device-friendly label (`credential.label or "Passkey"` + AAGUID-mapped device name from a small static lookup, e.g. `1c8f-...` → "Apple iCloud Keychain") — fall back to "Passkey" if AAGUID unknown.
    - Sub-line: "Added {{ credential.created_at | timeago }}" + "Last used {{ credential.last_used_at | timeago or 'never' }}".
    - Right side: "Rename" (inline edit) + "Remove" (DELETE with confirmation).
  - Empty state: "You haven't set up any passkeys yet. Add one to sign in without a code."
  - Bottom note: "Passkeys are stored on your device or password manager. They work only on this site (members.{{ brand.host }})."
- **validation:** Jinja parse + visual review.
- **reason_not_testable:** pure HTML/Tailwind/HTMX template; verified by Jinja parse + visual review
- **status:** Completed
- **log:**
  - 2026-05-09: Created `fief/templates/auth/dashboard/security/passkeys.html` extending `auth/dashboard/layout.html`. Header uses the gradient teal-emerald 10x10 icon tile pattern (key-on-shield glyph) + heading + subtitle, with the "Add a passkey" CTA placed in the header row when credentials exist. Empty-state card is centered with a teal-emerald icon, friendly invitation copy, and the same primary CTA so the user has only one click to make. Credential list renders inside a glass card (`rounded-xl border border-slate-200/70 bg-white/70 backdrop-blur-sm`) with one `<li>` per row: passkey icon, label (`credential.label or _("Passkey")`), inline pencil-rename, sub-line "Added <ts> · Last used <ts>" (or "Never used") using `strftime("%Y-%m-%d %H:%M")` per the v1 fallback in the spec, and a rose Remove button on the right. Remove uses HTMX `hx-delete` against `auth.dashboard:passkeys_delete` with `hx-confirm` and `hx-on::after-request` reloading on success. Inline rename JSON-PATCHes `auth.dashboard:passkeys_rename` with `{"label": "..."}` (same-origin, JSON Content-Type — matches T8's CSRF posture). The "Add a passkey" buttons trigger an inline `<script type="module">` that imports `/static/webauthn.bundle.js` (T8 IIFE bundle exposing `window.fiefWebauthn`) and calls `fiefWebauthn.registerPasskey(beginUrl, finishUrl)`; success reloads, failure reveals a small rose flash card "Something went wrong — please try again." Bottom note shows brand-scoping copy with `brand.host` (falls back to `tenant.name` when no brand is bound). All user-visible strings wrapped in `{{ _('...') }}`. Jinja parse with the project's `i18n` extension passes (`parsed`).
- **files edited/created:**
  - `fief/templates/auth/dashboard/security/passkeys.html` (new)

### T11: /mfa/passkey challenge template + cross-method links
- **depends_on:** [T9, T8]
- **location:** `fief/templates/auth/mfa/passkey.html` (new), update `fief/templates/auth/mfa/totp.html`, update `fief/templates/auth/mfa/recover.html`
- **description:**
  - `passkey.html`: extends `auth/layout.html` (same login-page layout MFA-1 used). Embedded JSON `<script type="application/json" id="webauthn-options">{{ options | tojson }}</script>` carries the challenge. A short inline `<script type="module">` imports `/static/webauthn.bundle.js`, calls `startAuthentication(JSON.parse(...))`, POSTs the assertion to `/mfa/passkey/verify`. Show a friendly status: "Touch your authenticator..." → "Verifying..." → success/error.
  - Update `auth/mfa/totp.html`: add a footer link "Use a passkey instead" → plain `<a href="{{ tenant.url_path_for(request, 'auth:mfa_passkey') }}">`. The `LoginSession` cookie travels automatically; the gating dependency on `/mfa/passkey` reads the same `mfa_pending_user_id` set during the original `/login` POST — no query params, no token threading. Render only when the user has at least one passkey credential (server-side check via `webauthn_service.list_for_user(user)` — short-circuit for users with no credentials).
  - Update `auth/mfa/recover.html`: same footer link.
- **validation:** Jinja parse + manual smoke test in T18.
- **reason_not_testable:** pure HTML/Tailwind/JS templates; verified by Jinja parse + manual smoke test in T18
- **status:** Completed
- **log:**
  - 2026-05-09: Created `fief/templates/auth/mfa/passkey.html` extending `auth/layout.html` (matches MFA-1's TOTP/recover pages). Embeds `PublicKeyCredentialRequestOptions` via `<script type="application/json" id="webauthn-options">{{ options | tojson }}</script>`; an inline `<script type="module">` imports `authenticateWithEmbeddedOptions` from `/static/webauthn.bundle.js` (T8 bridge), parses the embedded options, and POSTs the assertion to `tenant.url_path_for(request, 'auth:mfa_passkey_verify')`. On success the script does `window.location.assign(result.redirect_to)` (matches T9's JSON `{"redirect_to": ...}` response shape). On failure it inlines a fallback link to `auth:mfa_totp`. URLs and translated error strings are emitted server-side via `{{ ... | tojson }}` so the JS source contains no nested-quote Jinja interpolations (avoids the brittle quoting in the spec snippet's catch block). Status panel shows a teal-emerald gradient avatar with a pulse animation while waiting. Footer renders cross-method links (TOTP and recovery) unconditionally per spec — the `/mfa/passkey` GET handler from T9 already short-circuits to `/mfa/totp` when the user has no passkeys, so the inverse links from totp/recover back to passkey are also harmless when clicked by users without passkeys. Updated `fief/templates/auth/mfa/totp.html` and `fief/templates/auth/mfa/recover.html` footers to add a "Use a passkey instead" link above the existing recovery/authenticator cross-link, both rendered unconditionally. Verified Jinja parse with `Environment(extensions=['jinja2.ext.i18n']) + install_null_translations(newstyle=True)` for all three templates: prints `parsed`.
- **files edited/created:**
  - `fief/templates/auth/mfa/passkey.html` (new)
  - `fief/templates/auth/mfa/totp.html`
  - `fief/templates/auth/mfa/recover.html`

### T12: Surface passkey enrollment on /security/mfa landing
- **depends_on:** [T7]
- **location:** `fief/templates/auth/dashboard/security/index.html`
- **description:** Add a small section "Passkeys" with a one-line summary ("X passkey(s) registered" or "No passkeys yet — add one") and a "Manage passkeys" link to `/security/passkeys`. This keeps the existing TOTP UX in place and lets users discover passkeys.
  - When `webauthn_credentials | length > 0`: green check + "{{ count }} passkey{{ 's' if count > 1 else '' }} registered" + manage link.
  - When zero: muted text + "Set up a passkey" CTA link.
- **validation:** Jinja parse + visual.
- **reason_not_testable:** template + small route context addition; verified by Jinja parse + manual smoke
- **status:** Completed
- **log:**
  - 2026-05-09: Added Passkeys section to `fief/templates/auth/dashboard/security/index.html` rendered in both TOTP-enabled and TOTP-disabled branches. Two states: green-check + count + "Manage passkeys" link when `passkey_count > 0`; muted invite + "Set up a passkey" CTA when zero. Both link to `auth.dashboard:passkeys_index`. Wired `mfa_index` route in `fief/apps/auth/routers/dashboard.py` to inject `WebAuthnService` and pass `passkey_count = len(await webauthn_service.list_for_user(user))`. Verified via Jinja parse (`parsed`).
- **files edited/created:**
  - `fief/templates/auth/dashboard/security/index.html`
  - `fief/apps/auth/routers/dashboard.py`

### T13: mfa_enabled flag transitions
- **depends_on:** [T6]
- **location:** `fief/services/security/webauthn.py` (extend), small helper in `fief/services/user_manager.py` if needed
- **description:** Centralize the "is this user MFA-enrolled?" calculation. After registration / deletion of a passkey, recompute:
  ```python
  async def _recompute_mfa_enabled(self, user: User) -> None:
      has_totp = await self.totp_repo.get_confirmed_by_user_id(user.id) is not None
      passkey_count = await self.credential_repo.count_for_user(user.id)
      should_be = has_totp or passkey_count > 0
      if user.mfa_enabled != should_be:
          user.mfa_enabled = should_be
          await self.user_repo.update(user)
  ```
  Inject `TotpSecretRepository` + `UserRepository` into `WebAuthnService`. Call `_recompute_mfa_enabled` from `finish_registration` and `delete`.

  **Edge case:** if a user with TOTP also has passkeys, deleting all passkeys does NOT flip `mfa_enabled=False`. Deleting the LAST passkey AND no TOTP DOES flip it. Test this explicitly.

  **Symmetric in MFA-1?** Yes — MFA-1's `TotpService.disable` already flips `mfa_enabled=False` unconditionally. That ignores the case where the user has passkeys. Update `TotpService.disable` to call the same `_recompute_mfa_enabled` (or a shared module-level helper) — small surgical change.

  **Concurrency note:** the read-then-write on `user.mfa_enabled` is not transactional. A user concurrently registering and deleting credentials in two tabs could leave a stale value (e.g. `mfa_enabled=False` when one passkey actually exists). Acceptable in v1 — the user can trigger another transition by toggling once more. Revisit if support reports inconsistency.
- **validation:** Unit tests in T15.
- **status:** Completed
- **log:**
  - Added shared :func:`recompute_mfa_enabled` in
    ``fief/services/security/mfa_state.py``. The helper consults
    ``UserTotpSecretRepository.get_confirmed_by_user_id`` and
    ``UserWebAuthnCredentialRepository.count_for_user`` and only issues
    a ``user_repo.update`` when the in-memory flag differs from the
    desired state (so unconditional callers don't issue redundant
    SQL writes).
  - ``TotpService.__init__`` now requires ``webauthn_repo``; ``disable``
    delegates to the helper instead of unconditionally flipping
    ``mfa_enabled=False``. A user disabling TOTP while a passkey is
    still registered now correctly stays MFA-enrolled.
  - ``WebAuthnService.__init__`` now requires ``totp_repo`` and
    ``user_repo``; ``finish_registration`` and ``delete`` (on a
    successful row removal) call the helper. The first passkey
    enrollment flips ``mfa_enabled=True``; deleting the last factor
    flips it False.
  - Removed the inline ``_recompute_mfa_enabled`` helper from
    ``fief/apps/auth/routers/dashboard.py`` (T7's interim) — service
    now owns the recompute, so the routes are smaller and the totp /
    user / webauthn repos no longer need to be threaded into the
    register/delete handlers.
  - Updated factory functions ``get_totp_service`` /
    ``get_webauthn_service`` in ``fief/dependencies/security.py`` to
    inject the new repos.
  - Concurrency caveat documented in the helper module docstring (v1
    accepts the read-then-write race; user can self-heal by toggling
    once more).
  - Tests: 10 new unit tests in
    ``tests/services/test_mfa_state_recompute.py`` (no factors / TOTP
    only / passkey only / both / drop-one-of-two cases / drop-both /
    add-first-passkey / idempotency / repos consulted with user.id).
    Pre-existing ``tests/services/test_totp_service.py``,
    ``tests/services/test_totp_service_email_notifications.py``,
    ``tests/services/test_webauthn_service.py``, and
    ``tests/apps/auth/routers/test_dashboard_passkeys.py`` updated to
    match the new constructor signatures and the service-owned
    recompute. All 143 service tests + 60 dashboard/MFA router tests
    green.
- **files edited/created:**
  - ``fief/services/security/mfa_state.py`` (new)
  - ``fief/services/security/totp.py`` (modified)
  - ``fief/services/security/webauthn.py`` (modified)
  - ``fief/dependencies/security.py`` (modified)
  - ``fief/apps/auth/routers/dashboard.py`` (modified)
  - ``tests/services/test_mfa_state_recompute.py`` (new)
  - ``tests/services/test_totp_service.py`` (modified — new fixture)
  - ``tests/services/test_totp_service_email_notifications.py`` (modified — new fixture)
  - ``tests/services/test_webauthn_service.py`` (modified — new fixtures)
  - ``tests/apps/auth/routers/test_dashboard_passkeys.py`` (modified — fake mirrors recompute)

### T14: Auto-revoke other sessions on passkey register/delete
- **depends_on:** [T7]
- **location:** `fief/apps/auth/routers/dashboard.py` (the new T7 routes)
- **description:** UX-1 already auto-revokes on MFA enroll / disable / password change. Mirror the same hook for passkey registration and deletion:
  - `POST /security/passkeys/register/finish` — after success, call `device_sessions_service.auto_revoke_others(user.id, current_session_id=session_token.id, reason="passkey_registered")`.
  - `DELETE /security/passkeys/{id}` — after success, `reason="passkey_deleted"`.

  UX-1's `auto_revoke_others` accepts `reason: str` (verified at `fief/services/security/device_sessions.py` — plain string, no Enum). The docstring lists four allowed values (`password_change`, `mfa_enrolled`, `mfa_disabled`, `recovery_code_used`); extend it to also document `passkey_registered` and `passkey_deleted`. No code change needed beyond the docstring update — the audit log just receives the new string in `extra.trigger_reason`.
- **validation:** Integration test in T16.
- **reason_not_testable:** docstring update; verified by ruff format + mypy if applicable.
- **status:** Completed
- **log:**
  - T7 already wired both `auto_revoke_others(reason="passkey_registered")` (after `finish_registration`) and `auto_revoke_others(reason="passkey_deleted")` (after delete) in commit `ecd7257`. Remaining T14 work was the docstring sync.
  - Extended the `auto_revoke_others` docstring in `fief/services/security/device_sessions.py` to list `passkey_registered` and `passkey_deleted` alongside the existing four reason literals. `reason: str` is plain string (no Enum), so this is purely documentation.
  - Verified via `python -c "from fief.services.security.device_sessions import DeviceSessionsService; help(DeviceSessionsService.auto_revoke_others)"` — docstring renders the new literals.
- **files edited/created:**
  - `fief/services/security/device_sessions.py` — extended `auto_revoke_others` docstring with `passkey_registered`, `passkey_deleted`.

### T15: WebAuthnService unit tests
- **depends_on:** [T6, T13]
- **location:** `tests/services/test_webauthn_service.py` (new)
- **description:** Use the project's existing fakeredis fixture (the conftest already provides one for SEC-1; reuse it). The actual class export name in fakeredis 2.x is `fakeredis.aioredis.FakeRedis` — verify against the version pinned by SEC-1's deps; if newer fakeredis renamed it, use `fakeredis.FakeAsyncRedis` instead. Mock `verify_registration_response` and `verify_authentication_response` directly so we don't need real authenticator outputs. Cases:
  - `begin_registration` returns options with the user's existing credentials in `excludeCredentials`.
  - `finish_registration` happy path persists the credential, audits, flips `mfa_enabled`.
  - `finish_registration` with expired challenge → raises `ChallengeExpired`.
  - `begin_assertion` returns options with `allowCredentials = user's credentials`.
  - `verify_assertion` happy path updates `sign_count + last_used_at`, audits.
  - `verify_assertion` with credential_id not in DB → raises `CredentialNotFound`.
  - `verify_assertion` with `new_sign_count <= stored` AND stored > 0 → raises `SignCountRollback`, audits.
  - `verify_assertion` with `new_sign_count = 0` (Apple/Google sync) → accepts (skips rollback check).
  - `delete` with multiple credentials → row removed, `mfa_enabled` stays True.
  - `delete` with last credential AND no TOTP → `mfa_enabled` flips False.
  - `delete` with last credential BUT TOTP exists → `mfa_enabled` stays True.
  - `delete` of foreign credential → returns False (not found in user-scoped query).
  Run RED first.
- **validation:** Tests green.
- **status:** Completed (delivered alongside T6 + T13 via TDD)
- **log:**
  - T6 agent shipped `tests/services/test_webauthn_service.py` with 22 cases (commit `3f94a31`) covering: register/verify happy paths, expired challenge, one-shot replay guard, invalid attestation/signature, unknown credential_id, sign-count rollback, Apple/Google zero accept, first-use zero-stored accept, list/delete (real, missing, foreign), three `derive_rp_params` cases.
  - T13 (commit `b5013c2`) refactored those tests when the service constructor changed; all 22 still green plus 10 new `test_mfa_state_recompute.py` cases covering the unified flag transitions.
- **files edited/created:** see commits `3f94a31` and `b5013c2`.

### T16: Dashboard register flow integration
- **depends_on:** [T7, T13]
- **location:** `tests/apps/auth/routers/test_dashboard_passkeys.py` (new)
- **description:** Use httpx test client + dependency overrides for `WebAuthnService` (return canned options/responses) so we don't need a real authenticator.
  - GET `/security/passkeys` lists the user's credentials.
  - POST `/security/passkeys/register/begin` returns options JSON.
  - POST `/security/passkeys/register/finish` (with mocked attestation) creates the row, flips `mfa_enabled`, audits.
  - DELETE `/security/passkeys/{id}` removes the row, transitions `mfa_enabled` per T13 logic.
  - DELETE foreign credential id → 404.
  - PATCH renames the label.
  - Passkey register triggers `auto_revoke_others` (T14 hook).
  Run RED first.
- **validation:** Tests green.
- **status:** Completed (delivered alongside T7 + T13 via TDD)
- **log:**
  - T7 agent shipped `tests/apps/auth/routers/test_dashboard_passkeys.py` with 11 cases (commit `ecd7257`): GET listing, POST register-begin/finish (cred row created + mfa_enabled flipped + audit), PATCH rename, DELETE happy + 404 + state transitions.
  - T13 (commit `b5013c2`) updated the test fake to mirror the recomputation now owned by `WebAuthnService`. All 11 still green.
- **files edited/created:** see commits `ecd7257` and `b5013c2`.

### T17: Login challenge flow integration
- **depends_on:** [T9]
- **location:** `tests/apps/auth/routers/test_mfa_passkey.py` (new)
- **description:** Test the end-to-end /mfa/passkey flow with mocked WebAuthnService:
  - GET `/mfa/passkey` renders the challenge with options embedded.
  - POST `/mfa/passkey/verify` happy path → 303 redirect to post-login destination, session cookie set, audit `USER_PASSKEY_VERIFIED`.
  - POST `/mfa/passkey/verify` with bad assertion → 401, mfa_attempts_count incremented.
  - POST `/mfa/passkey/verify` with sign_count rollback → 401, audit `USER_PASSKEY_SIGN_COUNT_ROLLBACK`, but counter NOT incremented (the cred is suspect, not the attempt).
  - GET `/mfa/passkey` without `mfa_pending_user_id` → redirect to /login.
  - GET `/mfa/passkey` for a user with NO passkeys → fallback to /mfa/totp (or 404; pick a UX).
  Run RED first.
- **validation:** Tests green.
- **status:** Completed (delivered alongside T9 via TDD)
- **log:**
  - T9 agent shipped `tests/apps/auth/routers/test_mfa_passkey.py` with 13 cases (commit `439faf2`): 5 GET (no pending user, no cookie, locked, empty-passkey short-circuit, render-with-options), 2 POST gating, 1 POST success (cookie issued + carry-state cleared + redirect_to JSON), 5 POST failure (CredentialNotFound, InvalidAssertion, SignCountRollback no-counter-increment, ChallengeExpired no-counter, 5th-strike lockout). 15 regression tests across `test_mfa_challenge.py` + `test_login_mfa_branch.py` still green.
- **files edited/created:** see commit `439faf2`.

### T18: Dev rollout
- **depends_on:** [T15, T16, T17]
- **description:** `alembic upgrade head` against dev DB. `npm run build` to produce `webauthn.bundle.js`. Smoke test on `members.opensensor.dev` (or whichever dev hostname has a working cert):
  - Sign in, visit `/security/passkeys`, click "Add a passkey".
  - Browser prompts for fingerprint / Touch ID / YubiKey. Confirm a credential row appears.
  - Sign out, sign in again. /mfa/totp shows "Use a passkey instead" link. Click it → /mfa/passkey → authenticator prompt → success.
  - Delete the credential from /security/passkeys. `mfa_enabled` should remain True if the user has TOTP, else False.
- **validation:** Full register → challenge → delete cycle works on dev.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T19: Production rollout
- **depends_on:** [T18]
- **description:** Push image, watch GHCR build, `kubectl rollout restart deploy/opensensor-fief`. Migration adds one new table — fully online-safe. Verify on each brand (lightnvr / owlbooks / opensensor):
  - Visit `/security/passkeys` → empty state.
  - Register a passkey on each brand. Confirm `rp_id` matches the brand host.
  - Sign in via the 2FA challenge.
  - Confirm cross-brand isolation: a passkey registered on lightnvr.com does NOT appear on owlbooks.ai (different rp_id, different OS keychain entries).
- **validation:** Three-brand smoke test passes; no support tickets in 24 h.
- **status:** Not Completed
- **log:**
- **files edited/created:**

## Parallel Execution Groups

| Wave | Tasks                       | Notes                                                |
|------|-----------------------------|------------------------------------------------------|
| 1    | T1, T2                      | Foundation; both parallel                            |
| 2    | T3, T4                      | Schema; both parallel                                |
| 3    | T5                          | Repo; needs T4                                       |
| 4    | T6                          | Service; needs T1+T5                                 |
| 5    | T7, T8                      | Routes + JS bridge; both parallel after T6           |
| 6    | T9                          | Login challenge route; needs T6                      |
| 7    | T10, T11, T12               | UI; T10/T12 need T7, T11 needs T9+T8                 |
| 8    | T13, T14                    | State coherence + auto-revoke hook; T13 needs T6, T14 needs T7 |
| 9    | T15, T16, T17               | Tests; parallel                                      |
| 10   | T18 → T19                   | Rollout, sequential                                  |

## Testing strategy
- Unit tests use mocked `verify_registration_response` / `verify_authentication_response` so we don't need a real authenticator. The library's behaviour is well-tested upstream; we test our integration glue (challenge storage, sign_count tracking, mfa_enabled transitions, audit emissions).
- Integration tests use httpx test client + `app.dependency_overrides[get_webauthn_service]` to inject a stub that returns canned responses.
- Manual smoke test in T18 covers the real browser → real authenticator path.
- Cross-brand isolation tested in T19 by registering on each brand and confirming no leakage.

## Risks & mitigations
- **WebAuthn implementation is fiddly.** Mitigation: lean on `py_webauthn` lib + `@simplewebauthn/browser` JS lib. Both are mature and stable. Don't roll our own crypto.
- **Sign-count rollback false positives** (Apple/Google passkeys return 0). Mitigation: skip the rollback check when `new_sign_count == 0`. Documented in T6.
- **Cross-brand confusion.** A user might wonder why their lightnvr.com passkey doesn't work on owlbooks.ai. Mitigation: copy on the /security/passkeys page makes brand scoping explicit ("They work only on this site").
- **HTTPS required for WebAuthn.** Production already runs HTTPS; dev environment needs a working cert. Document in T18.
- **Recovery-code escape hatch still valid.** A user who loses all passkeys AND TOTP can still use recovery codes from MFA-1. Verify in T17.
- **Browser compatibility.** WebAuthn is supported in all modern browsers (>96% global). For older browsers, the registration button is hidden via `if (!window.PublicKeyCredential)`.
- **Redis ephemeral challenges.** If Redis blips between begin and finish, the user gets `ChallengeExpired` and re-tries. Acceptable.

## Plan revisions applied from subagent review (2026-05-09)
- **T1** — pinned `webauthn>=2.0,<3` (avoid silent breakage on a v3 release).
- **T3** — explicit note that `transports` as comma-separated TEXT is an intentional cross-dialect divergence from the PRD's `text[]`.
- **T6** — concrete `VerifiedRegistration` field mapping spelled out (credential_id / public_key / sign_count / aaguid / backup_state / backup_eligible). Required `generate_registration_options` args spelled out (`user_id` as bytes, `user_name`, `user_display_name`, `exclude_credentials` shape, attestation/userVerification enums). `origin` exact-string match documented. Challenge persistence shape standardized on Base64URL-stripped str in Redis. `excludeCredentials` / `allowCredentials` shape with `PublicKeyCredentialDescriptor` + `AuthenticatorTransport`.
- **T7** — explicit "no last-credential guard in v1" decision documented.
- **T8** — dropped phantom `X-CSRF-Token` (no server validation existed); rely on SameSite-Lax cookies + Content-Type forced preflight. Pinned `@simplewebauthn/browser>=9,<11`. Renamed JS export to `authenticateWithEmbeddedOptions(options, finishUrl)` for the 2FA case (matches the embed-in-template approach in T11).
- **T9** — empty-passkey-list short-circuit redirects to `/mfa/totp`. ChallengeExpired changed from 410 to 400 with typed `error: "challenge_expired"`.
- **T11** — explicit note that the "Use a passkey instead" link is a plain `<a>` — `LoginSession` cookie carries automatically.
- **T13** — concurrency caveat documented (read-then-write on `mfa_enabled` non-transactional; acceptable in v1).
- **T14** — `auto_revoke_others.reason` is plain `str` (no Enum); update only the docstring to add `passkey_registered` and `passkey_deleted`.
- **T15** — fakeredis class name caveat noted (`FakeRedis` vs `FakeAsyncRedis` depending on lib version).

## Open questions deferred to implementation
- **AAGUID → device name mapping.** A small static lookup of common AAGUIDs (Apple iCloud Keychain, 1Password, Yubikey 5, etc.) for friendly device labels. Defer; ship "Passkey" as the default label. Could be a follow-up commit.
- **Discoverable / passwordless flow (MFA-2.5).** Out of scope for v1 per the locked-in decision. Will need a dedicated `/auth/passkey/begin` route, login-page button, and a way to resolve user from `credential_id` alone.
- **Conditional UI hints (autocomplete=webauthn).** Browser shows passkeys in the username autocomplete dropdown. Out of scope for v1; would need the discoverable flow.
- **FIDO MDS / attestation enforcement.** Explicit non-goal per PRD. If a customer ever requires FIPS-140, that's a separate PRD.
