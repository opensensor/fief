# Plan: MFA-1 — TOTP MFA + Recovery Codes

**Generated:** 2026-05-09
**Source PRD:** `docs/prds/MFA-1-totp-recovery-codes.md`
**Decisions locked in:**
- Tenant-level enforcement only (`tenants.mfa_required`); no per-brand override in v1.
- TOTP secrets encrypted at rest with Fernet via `MFA_SECRET_ENCRYPTION_KEY` env var.
- Failed-attempt rate limiting carried on the existing `LoginSession` (no Redis dependency; SEC-1 ships rate-limit infra later).

## Overview
Insert a TOTP second-factor step into the existing Fief login flow. Reference points (from codebase exploration):

- Login flow today: `fief/apps/auth/routers/auth.py:141` (`/login` route) → password validated by `user_manager.authenticate()` (line 172) → `authentication_flow.rotate_session_token()` (lines 184-189) issues the final session.
- We will branch **between** "credentials valid" and `rotate_session_token()`: if the user is enrolled, we mark the login session as MFA-pending and redirect to `/mfa/totp`; the verify route there calls `rotate_session_token()` only on success.
- Carry-vehicle for MFA state: existing `LoginSession` model (`fief/models/login_session.py:18`); we add a few nullable columns rather than introducing a new table.
- Audit logger: `fief/logger.py:45` invoked as `self.audit_logger(AuditLogMessage.X, subject_user_id=...)` — pattern used in `user_manager.py:340`. Five new enum values get added.
- Form/route conventions follow `reset_password` (`fief/apps/auth/routers/reset.py:54`, `fief/apps/auth/forms/reset.py:13`).
- Dashboard nav home for new pages: `fief/apps/auth/routers/dashboard.py:28` (the same router we modernized for the My Profile UI).

## Prerequisites
- `pyotp >= 2.9` (TOTP RFC 6238) and `segno >= 1.6` (QR PNG generation) added to `pyproject.toml`.
- `cryptography` already in transitive deps; we use `cryptography.fernet`.
- `MFA_SECRET_ENCRYPTION_KEY` provisioned in dev + production envs (Kubernetes secret) before T26 ships.
- Mailjet-verified senders unchanged (we already have brand-aware sender resolution).

## Dependency Graph

```
Wave 1 (Foundation) — parallel
  T1  deps          T2  crypto helper          T3  audit-log enum          T4  settings env
       │                 │                         │                            │
       ↓                 ↓                         ↓                            ↓
Wave 2 (Schema + models) — parallel, independent of Wave 1
  T5 alembic migration   T6 totp/recovery models   T7 tenant column   T8 login_session columns
       │                 │                         │                  │
       └────────┬────────┘                         │                  │
                ↓                                  ↓                  ↓
Wave 3 (Repos + forms)
  T9  Repos: totp + recovery (uses T6)             T10 Forms (uses T8)
                │                                  │
                └─────────────────┬────────────────┘
                                  ↓
Wave 4 (Services)
  T11 TotpService (T1, T2, T9)        T12 RecoveryCodeService (T9)
                                  │
                                  ↓
Wave 5 (Routes)
  T13 Dashboard setup routes (T10, T11, T12)
  T14 Login-time challenge routes /mfa/totp, /mfa/recover (T8, T10, T11, T12)
  T15 Login flow branch — defer rotate_session_token (T8 only — does not invoke TotpService)
  T16 Tenant enforcement gate (T7, T8 — orthogonal to T15)
                                  │
                                  ↓
Wave 6 (Templates) — parallel
  T17 setup templates (T13)
  T18 challenge templates (T14)
  T19 recovery codes display template (T13)
                                  │
                                  ↓
Wave 7 (Cross-cutting wiring) — parallel
  T20 Audit log call sites (T3, T13, T14, T15, T16)
  T21 Wire admin "force re-enroll" API endpoint (T9)
  T22 Optional notification email on enroll/disable (deferable; T13)
                                  │
                                  ↓
Wave 8 (Tests) — parallel
  T23 unit: TotpService + RecoveryCodeService (T11, T12)
  T24 unit: Fernet helper (T2)
  T25 integration: enroll → login → verify → success (T13, T14, T15)
  T26 integration: lockout + recovery + tenant enforcement (T14, T16)
                                  │
                                  ↓
Wave 9 (Rollout)
  T27 dev env secret + smoke test (T23-T26)
  T28 production env secret + deploy + post-deploy verification (T27)
```

## Tasks

### T1: Add Python dependencies
- **depends_on:** []
- **location:** `pyproject.toml`
- **description:** Add `pyotp >= 2.9` and `segno >= 1.6` to the `[project]` `dependencies` array. Run `pip install -e .` (or hatch equivalent) and verify imports.
- **validation:** `python -c "import pyotp, segno"` succeeds; `pyproject.toml` diff shows the two additions only.
- **reason_not_testable:** configuration-only; verified by import smoke check
- **status:** Completed
- **log:**
  - Added `pyotp >=2.9` and `segno >=1.6` to `[project].dependencies` in `pyproject.toml` (placed alphabetically between `pwdlib` and `sendgrid`).
  - Installed both packages in an isolated venv (`pip install pyotp>=2.9 segno>=1.6`); full `pip install -e .` blocked by pre-existing psycopg2 build env (unrelated to this change).
  - Verified imports: `python -c "import pyotp, segno; print(...)"` ran cleanly. `pyotp` 2.9.0 does not expose `__version__`; both versions confirmed via `pip show` (pyotp 2.9.0, segno 1.6.6) and a live `pyotp.TOTP(...).now()` call returned a 6-digit code.
- **files edited/created:**
  - `pyproject.toml` (modified)

### T2: Fernet encryption helper
- **depends_on:** []
- **location:** `fief/services/security/encryption.py` (new), `fief/services/security/__init__.py` (new)
- **description:** Module exposing `encrypt(secret: str) -> bytes` and `decrypt(blob: bytes) -> str`, backed by `cryptography.fernet.MultiFernet`. Reads keys from `settings.mfa_secret_encryption_key` (single key) or `settings.mfa_secret_encryption_keys` (list, current key first — supports rotation). Raises a typed `MfaSecretDecryptionError` on failure so callers can return a generic 500 without leaking detail.
- **validation:** Round-trip unit test in T24 passes; encrypted output is bytes (not str); two consecutive `encrypt()` calls of the same plaintext yield distinct ciphertexts.
- **status:** Completed
- **log:**
  - 2026-05-09: Implemented `encrypt`/`decrypt` backed by `cryptography.fernet.MultiFernet`, with a lazy `getattr`-based settings accessor so the module loads cleanly before T4 wires the matching settings fields. `MfaSecretDecryptionError` wraps `InvalidToken`; missing-config calls raise `RuntimeError("MFA encryption key not configured")`. Smoke tests in `tests/services/test_encryption_smoke.py` cover round-trip, distinct-ciphertext, tampered-ciphertext rejection, and missing-key guard — full coverage suite remains owned by T24.
- **files edited/created:**
  - `fief/services/security/__init__.py` (new)
  - `fief/services/security/encryption.py` (new)
  - `tests/services/__init__.py` (new)
  - `tests/services/test_encryption_smoke.py` (new)

### T3: Audit-log enum additions
- **depends_on:** []
- **location:** `fief/models/audit_log.py` (the `AuditLogMessage` enum at lines 13-24)
- **description:** Add `USER_MFA_ENROLLED`, `USER_MFA_DISABLED`, `USER_MFA_VERIFIED`, `USER_MFA_VERIFY_FAILED`, `USER_MFA_RECOVERY_CODE_USED`, `USER_MFA_RECOVERY_CODES_REGENERATED`, `USER_MFA_FORCE_REENROLLED`, `USER_MFA_STATE_INCONSISTENT` (the last is fired by T11/T14 when ciphertext can't be decrypted or the `users.mfa_enabled` flag is set without a confirmed secret row). Keep value strings consistent with the `USER_*` prefix style.
- **validation:** Existing audit-log tests still pass; new enum members are imported successfully.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T4: Settings — add MFA encryption key
- **depends_on:** []
- **location:** `fief/settings.py`, `fief/app/initializer.py` (or wherever the FastAPI lifespan/startup hook lives)
- **description:** Add `mfa_secret_encryption_key: str | None = None` and `mfa_secret_encryption_keys: list[str] | None = None` (latter wins if set; comma-separated env). Validation runs **unconditionally at app startup** (lifespan event) — once the MFA routes are merged, they are always registered, so guarding the check on "are MFA routes registered" is meaningless. Raise `EnvironmentError("MFA_SECRET_ENCRYPTION_KEY must be set")` immediately if neither env is populated. No tenant flag here — it lives on the model in T7.
- **validation:** App boot fails fast with a clear message when neither env is set; passes when set. Boot logs include "MFA encryption: 1 active key" (or N if rotation list).
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T5: Alembic migration — new tables + columns
- **depends_on:** []
- **location:** `fief/alembic/versions/2026-05-09_add_mfa_tables_and_columns.py` (new)
- **description:** Single migration covering:
  - `CREATE TABLE fief_user_totp_secrets` (id uuid pk, user_id uuid fk → users on delete cascade, secret_encrypted bytea NOT NULL, confirmed_at timestamptz null, last_used_step bigint null, created_at timestamptz NOT NULL, unique (user_id))
  - `CREATE TABLE fief_user_mfa_recovery_codes` (id uuid pk, user_id uuid fk → users on delete cascade, code_hash text NOT NULL, used_at timestamptz null, created_at timestamptz NOT NULL, index (user_id, used_at))
  - `ALTER TABLE fief_users ADD COLUMN mfa_enabled boolean NOT NULL DEFAULT false`
  - `ALTER TABLE fief_tenants ADD COLUMN mfa_required boolean NOT NULL DEFAULT false`
  - `ALTER TABLE fief_login_sessions ADD COLUMN mfa_pending_user_id uuid null fk → users, ADD COLUMN mfa_attempts_count integer NOT NULL DEFAULT 0, ADD COLUMN mfa_locked_until timestamptz null`
  - `down()` reverses cleanly. Use the existing `table_prefix` codemod placeholder pattern (see `fief/alembic/table_prefix_codemod.py:7`).
- **validation:** `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` succeeds locally against the dev DB. Migration head matches `pyproject.toml` / `Makefile` declared head if present.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T6: SQLAlchemy models — UserTotpSecret + UserMfaRecoveryCode
- **depends_on:** []
- **location:** `fief/models/user_totp_secret.py` (new), `fief/models/user_mfa_recovery_code.py` (new), `fief/models/__init__.py` (add imports only)
- **description:** Two SQLAlchemy declarative models matching the schema in T5. Use the existing `UUIDModel`, `CreatedUpdatedAt` base mixins as in other models (e.g. `fief/models/refresh_token.py`). Each new model declares its **own side** of the relationship via string-based reference: `user = relationship("User", back_populates="totp_secret")` (and `..."mfa_recovery_codes"`). **Do NOT touch `fief/models/user.py`** — the matching back-relationships and the `mfa_enabled` column are owned by T8 (file-ownership boundary so T6 and T8 can run in parallel).
- **validation:** `from fief.models import UserTotpSecret, UserMfaRecoveryCode` imports clean. (Mapper warnings about missing back-populates may surface until T8 lands; that is expected and resolved when T8 commits.)
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T7: Tenant model — add mfa_required
- **depends_on:** []
- **location:** `fief/models/tenant.py` (around line 47, beside `registration_allowed`)
- **description:** Add `mfa_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)`. Update tenant Pydantic schema in `fief/schemas/tenant.py` to expose the field on read AND admin-update endpoints.
- **validation:** Admin API GET `/api/tenants/{id}` returns the new field; PATCH accepts it; default value false on existing rows.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T8: LoginSession + User model edits — MFA carry-state columns, mfa_enabled, back-relationships
- **depends_on:** []
- **location:** `fief/models/login_session.py`, `fief/models/user.py`
- **description:** **Owns all edits to `fief/models/user.py`** (T6 deliberately stays out of this file).
  - On `LoginSession`: add `mfa_pending_user_id: Mapped[uuid.UUID | None]`, `mfa_attempts_count: Mapped[int] = mapped_column(default=0)`, `mfa_locked_until: Mapped[datetime | None]`.
  - On `User`: add `mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)` (denormalized; flipped by enroll/disable/recovery flows so the `/login` route does a single boolean read instead of joining the secrets table on every request).
  - On `User`: add the two back-relationships using string-based references so we don't depend on import order: `totp_secret = relationship("UserTotpSecret", back_populates="user", uselist=False, cascade="all, delete-orphan")` and `mfa_recovery_codes = relationship("UserMfaRecoveryCode", back_populates="user", cascade="all, delete-orphan")`.
- **validation:** Models import; existing `LoginSession` callers compile. After T6 also lands, the SQLAlchemy mapper resolves both sides without warnings.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T9: Repositories — UserTotpSecretRepository + UserMfaRecoveryCodeRepository
- **depends_on:** [T6]
- **location:** `fief/repositories/user_totp_secret.py` (new), `fief/repositories/user_mfa_recovery_code.py` (new), `fief/repositories/__init__.py` (export)
- **description:** Standard `BaseRepository`-derived classes. Methods:
  - `UserTotpSecretRepository`: `get_by_user_id`, `get_confirmed_by_user_id`, `delete_by_user_id`.
  - `UserMfaRecoveryCodeRepository`: `list_by_user_id` (with `used_at IS NULL` flag), `delete_by_user_id`, `mark_used`.
- **validation:** Imported by services in T11/T12 without circular-import errors; basic CRUD works against an in-memory SQLite test DB if the repo testing harness exists, else verified via T23 unit tests.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T10: WTForms — TOTP confirm / verify / disable / recover
- **depends_on:** [T8]
- **location:** `fief/apps/auth/forms/mfa.py` (new)
- **description:** Four `CSRFBaseForm`-derived classes:
  - `TotpEnrollConfirmForm` (single 6-digit `code` IntegerField with `Length(6,6)`, numeric validator)
  - `TotpVerifyForm` (same shape; reused for login challenge)
  - `TotpDisableForm` (current password StringField + 6-digit code OR recovery code)
  - `MfaRecoveryForm` (recovery code field — accepts both `xxxx-xxxx` and `xxxxxxxx`)
- **validation:** Forms render with the existing `forms.html` macros via T17/T18 templates; validation rejects malformed input.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T11: TotpService
- **depends_on:** [T1, T2, T9]
- **location:** `fief/services/security/totp.py` (new)
- **description:** Encapsulates all TOTP logic so routes don't touch pyotp directly:
  - `begin_enrollment(user, brand_or_tenant_label) -> EnrollmentBundle(secret_b32, otpauth_uri, qr_png_data_uri)`. **Upsert behaviour:** if an *unconfirmed* row (confirmed_at IS NULL) exists for this user, replace it (delete + insert). If a *confirmed* row exists, raise `MfaAlreadyEnrolledError` — the caller (T13 disable route) must wipe the existing one first. Generates `pyotp.random_base32()`; encrypts via T2; persists row with `confirmed_at=null`. Issuer name comes from `brand.name if brand else tenant.name` so the entry in user authenticators reads correctly per brand.
  - `confirm_enrollment(user, code) -> bool`. Validates code with `pyotp.TOTP(secret).verify(code, valid_window=1)`; on success sets `confirmed_at=now()`, flips `users.mfa_enabled=true`, stores `last_used_step` to refuse replay, returns True.
  - `verify(user, code) -> VerifyResult`. Same verify with `valid_window=1`; refuses if `last_used_step >= proposed_step`. Returns enum {SUCCESS, INVALID, REPLAY, INCONSISTENT_STATE}. **Decryption hardening:** wraps the Fernet `decrypt` call in try/except `MfaSecretDecryptionError`; on failure, returns `INCONSISTENT_STATE` AND emits a structured log entry with `user_id` AND fires audit log `USER_MFA_STATE_INCONSISTENT` (added in T3). Same for the orphan case where `users.mfa_enabled=true` but no confirmed row exists.
  - `disable(user)`. Deletes row + recovery codes; flips `users.mfa_enabled=false`.
- **validation:** T23 covers all four methods including drift, replay, invalid, INCONSISTENT_STATE on tampered ciphertext, and double-begin-enrollment replacing the unconfirmed row.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T12: RecoveryCodeService
- **depends_on:** [T9]
- **location:** `fief/services/security/recovery_codes.py` (new)
- **description:** Generates and verifies 10 single-use recovery codes per user.
  - Format: 10 codes, each `XXXX-XXXX` where `X` is uppercase base32 alphabet. Display them in the `XXXX-XXXX` form; accept both formatted and unformatted on input.
  - `generate_for(user) -> list[str]`. Replaces any existing rows; stores hashes via `passlib.hash.bcrypt.hash()` directly (do **not** route through the existing `password_helper`; recovery-code hashing must be independent of any future password-hash migration the project does).
  - `consume(user, code) -> bool`. Lowercases & strips dashes; iterates user's unused codes; uses `passlib.hash.bcrypt.verify()` (constant-time) so timing doesn't leak which codes are still valid; marks the matched row `used_at=now()`.
- **validation:** T23 covers consume-then-replay (rejected), case-insensitive matching, and exhaustion.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T13: Dashboard setup routes
- **depends_on:** [T10, T11, T12]
- **location:** `fief/apps/auth/routers/dashboard.py`
- **description:** New routes mounted under the existing dashboard router (so they pick up the brand context already wired in our modernization):
  - `GET /security/mfa` (name `auth.dashboard:mfa_index`) — landing page; shows enrollment state, links to setup or list recovery codes.
  - `POST /security/mfa/totp/begin` — calls `TotpService.begin_enrollment` and renders the QR page.
  - `POST /security/mfa/totp/confirm` — `TotpEnrollConfirmForm`; on success generates recovery codes via `RecoveryCodeService.generate_for` and renders the codes page **once** (T19); on failure re-renders QR with field error.
  - `POST /security/mfa/totp/disable` — `TotpDisableForm`; password re-prompt; on success disables.
  - `POST /security/mfa/recovery-codes/regenerate` — re-issues codes; renders the same once-only display page.
- **validation:** Each route returns the expected templates with brand/tenant context populated.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T14: Login-time challenge routes — /mfa/totp + /mfa/recover
- **depends_on:** [T8, T10, T11, T12]
- **location:** `fief/apps/auth/routers/auth.py` (new routes; pattern from `reset_password` at line 54)
- **description:**
  - **Cookie binding (anti-hijack):** Every handler below must verify the `LoginSession` cookie ID resolves to the same row whose `mfa_pending_user_id` is set. If the cookie is missing, doesn't decode, or the resolved login session has no `mfa_pending_user_id` (or expired), redirect to `/login` with a generic flash. Do NOT leak that an MFA challenge is pending for a different cookie.
  - **Defensive state check:** On `GET /mfa/totp` and `GET /mfa/recover`, look up the user; if `user.mfa_enabled=true` BUT no confirmed `UserTotpSecret` exists (orphan), call `TotpService.disable` to self-heal, audit `USER_MFA_STATE_INCONSISTENT`, and redirect to `/login` with a clear "Please sign in again" message.
  - `GET /mfa/totp` (name `auth:mfa_totp`) — requires a `LoginSession` with `mfa_pending_user_id` set, cookie-bound, not locked, and consistent state; renders the challenge form.
  - `POST /mfa/totp` — `TotpVerifyForm`; calls `TotpService.verify`. On SUCCESS: clears `mfa_pending_user_id` AND `mfa_attempts_count` AND `mfa_locked_until`, calls `authentication_flow.complete_login_after_mfa()` (helper added in T15), proceeds to original post-login redirect. On INVALID: increments `mfa_attempts_count`; at 5 sets `mfa_locked_until = now()+10min` and forces user back through `/login`. On REPLAY: same as INVALID plus audit log `USER_MFA_VERIFY_FAILED` with `extra={"reason":"replay"}`. On INCONSISTENT_STATE: same path as the GET defensive check (self-heal + redirect).
  - `GET /mfa/recover` — same gating + defensive check.
  - `POST /mfa/recover` — calls `RecoveryCodeService.consume`. On success: calls `TotpService.disable` (force re-enroll on next login), completes the session via `complete_login_after_mfa()`, audit-logs `USER_MFA_RECOVERY_CODE_USED`. On invalid: same lockout counter as TOTP.
- **validation:** Manual smoke + T25/T26 (which now includes the cookie-hijack scenario per T26 update).
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T15: Login flow branch — defer session-token rotation when MFA enrolled
- **depends_on:** [T8]
- **location:** `fief/apps/auth/routers/auth.py` (the `login` route around line 184) and `fief/services/authentication_flow.py:100-116`
- **description:** After `user_manager.authenticate()` returns valid user, read the `user.mfa_enabled` boolean (column added in T8) — does NOT need TotpService:
  1. **Always clear stale MFA carry-state** at the start of a fresh `/login` POST: zero out `mfa_pending_user_id`, `mfa_attempts_count`, `mfa_locked_until` on the `LoginSession`. (Defends against reusing a session that already had pending state.)
  2. If `user.mfa_enabled`: set `login_session.mfa_pending_user_id = user.id`, persist, redirect to `tenant.url_for(request, "auth:mfa_totp")`. **Do NOT call `rotate_session_token()`.**
  3. Else: existing path unchanged — `rotate_session_token()` immediately.
  Add a small helper `complete_login_after_mfa(login_session, user, request)` in `authentication_flow.py` that the verify route (T14) calls; it does the `rotate_session_token` and clears MFA carry-state.
- **validation:** Login with non-MFA user: unchanged behavior. Login with MFA user: never receives a session cookie until /mfa/totp succeeds. Stale carry-state from a prior abandoned MFA challenge is wiped on the next /login POST.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T16: Tenant enforcement gate
- **depends_on:** [T7, T8]
- **location:** `fief/apps/auth/routers/auth.py` (login route) + `fief/apps/auth/routers/dashboard.py` (`get_base_context` or a new dependency)
- **description:** When `tenant.mfa_required is true` and the user is *not* `mfa_enabled`, after primary credentials succeed, redirect to `/security/mfa` (the enrollment landing) with a flash banner "Your account requires two-factor authentication. Please enroll to continue." The user can use the dashboard normally for enrollment, but every dashboard route checks `tenant.mfa_required and not user.mfa_enabled` via a small dependency — if true and the request path is not `/security/mfa/*`, force redirect.
- **validation:** Toggle `mfa_required=true` on a test tenant; existing user without MFA gets the redirect; user already enrolled is unaffected.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T17: Setup templates
- **depends_on:** [T13]
- **location:** `fief/templates/auth/dashboard/security/index.html` (new), `setup.html` (QR + confirm), `disable.html` — all extending the modernized `auth/dashboard/layout.html`
- **description:** Match the visual language of the recently-shipped Profile/Password pages: glass card, gradient icon tile (lock/shield), gradient submit button. The QR page shows the encoded secret as a copyable manual-entry string under the QR. Add a `Security` nav item to `auth/dashboard/sidebar.html` so the new section is discoverable.
- **validation:** Hand-test rendering across the 3 brands; brand logo + name appear correctly via the existing brand context.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T18: Challenge templates
- **depends_on:** [T14]
- **location:** `fief/templates/auth/mfa/totp.html` (new), `fief/templates/auth/mfa/recover.html` (new) — extending `auth/layout.html` (the login-page glass layout)
- **description:** Single 6-digit input (use the existing `verify_email.html` macro pattern at `fief/templates/macros/verify_email.html` — same per-digit boxes work great for TOTP). Recovery template uses a single text field with auto-format `XXXX-XXXX`. Both pages link to the other ("Lost your device? Use a recovery code." / "Have your authenticator? Enter a code instead.").
- **validation:** Form submits cleanly, error states render, brand hero panel shows for tenants that have one.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T19: Recovery codes display template
- **depends_on:** [T13]
- **location:** `fief/templates/auth/dashboard/security/recovery_codes.html` (new)
- **description:** Two-column grid of the 10 codes, monospaced. Buttons: "Download .txt", "Copy all", "Print". Strongly-worded warning: "These codes are shown only once. Store them in a safe place." Reload of the page does NOT re-display the codes (server doesn't store plaintext).
- **validation:** Cmd-P prints cleanly; download produces `recovery-codes-{slug}.txt` where `slug` is `slugify(brand.name) if brand else slugify(tenant.name)` — slugify via Python `re.sub(r"[^a-z0-9]+", "-", name.lower())` template filter (add to `fief/services/templates.py` if not already present).
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T20: Audit log call sites
- **depends_on:** [T3, T13, T14, T15, T16]
- **location:** all four route files updated in T13-T16
- **description:** Wire `self.audit_logger(AuditLogMessage.USER_MFA_*, subject_user_id=user.id)` at:
  - enroll confirm (success only) → `USER_MFA_ENROLLED`
  - disable (success) → `USER_MFA_DISABLED`
  - login challenge verify (success) → `USER_MFA_VERIFIED`
  - login challenge verify (failure / replay / lockout) → `USER_MFA_VERIFY_FAILED` (with `extra={"reason": ...}`)
  - recovery code consumed → `USER_MFA_RECOVERY_CODE_USED`
  - regenerate → `USER_MFA_RECOVERY_CODES_REGENERATED`
  - admin force-re-enroll (T21) → `USER_MFA_FORCE_REENROLLED`
- **validation:** Audit log table receives the new rows during T25/T26 integration tests.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T21: Admin "force re-enroll" API endpoint
- **depends_on:** [T9]
- **location:** `fief/apps/api/routers/users.py`
- **description:** New `POST /api/users/{id}/mfa/reset` (admin-only) — wipes the user's TOTP secret + recovery codes, sets `mfa_enabled=false`. Pairs with the existing admin password-reset capability for support workflows. Audit-logged via T20.
- **validation:** API integration test using existing admin auth fixtures; non-admin gets 403.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T22: Notification email on enroll/disable (deferable)
- **depends_on:** [T13]
- **location:** `fief/services/email_template/types.py`, `fief/services/email_template/templates/mfa_enabled.html` (new), `fief/services/email_template/templates/mfa_disabled.html` (new), `fief/tasks/mfa.py` (new)
- **description:** Add `EmailTemplateType.MFA_ENABLED` and `MFA_DISABLED`. Two short brand-aware emails ("Two-factor authentication was turned on/off for your <brand> account. Wasn't you? <reset link>"). Triggered by Dramatiq actor `on_mfa_state_changed(user_id, state, brand_id)` enqueued from T13 routes. Same brand-id flow already proven for welcome/verify/forgot — `brand_id` is sourced from the existing dashboard request context (already populated by the `get_current_brand` dependency wired in our recent modernization PR).
- **validation:** Manual: enable/disable on a test user; both emails arrive with correct brand sender + masthead.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T23: Unit tests — TotpService + RecoveryCodeService
- **depends_on:** [T11, T12]
- **location:** `tests/services/test_totp.py` (new), `tests/services/test_recovery_codes.py` (new)
- **description:** Cover happy paths + drift + replay + invalid + decryption failure (corrupt ciphertext) + recovery-code consume/replay/case-insensitive match/exhaustion + one-shot regenerate invalidates prior set.
- **validation:** `pytest tests/services/test_totp.py tests/services/test_recovery_codes.py` green; coverage on the two service modules ≥ 90%.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T24: Unit tests — Fernet helper
- **depends_on:** [T2]
- **location:** `tests/services/test_encryption.py` (new)
- **description:** Round-trip; key rotation via `MultiFernet` (decrypt with old key, re-encrypt with new); raises `MfaSecretDecryptionError` on tampered ciphertext.
- **validation:** Tests green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T25: Integration — full enroll → verify happy path
- **depends_on:** [T13, T14, T15]
- **location:** `tests/auth/test_mfa_enrollment.py` (new), `tests/auth/test_mfa_login.py` (new)
- **description:** Use existing httpx test client + TestSessionToken fixture. Walk:
  1. user logs in (no MFA) → dashboard reachable
  2. POST /security/mfa/totp/begin → returns QR + ephemeral secret
  3. POST /security/mfa/totp/confirm with valid code (computed via pyotp from the same secret) → recovery codes returned, `users.mfa_enabled=true`
  4. logout
  5. POST /login again → 302 to /mfa/totp, no session cookie
  6. POST /mfa/totp with valid code → session cookie issued, redirect to original destination
- **validation:** Tests green; assertions on cookie presence/absence at each step.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T26: Integration — lockout, recovery, tenant enforcement, hijack defense, orphan self-heal
- **depends_on:** [T14, T16]
- **location:** `tests/auth/test_mfa_lockout.py` (new), `tests/auth/test_mfa_recovery.py` (new), `tests/auth/test_mfa_tenant_enforcement.py` (new), `tests/auth/test_mfa_security.py` (new)
- **description:**
  - 5 wrong codes within window → login session locked → 6th attempt 403; restart from /login allowed.
  - valid recovery code: revokes TOTP secret, logs user in, forces re-enroll on next login.
  - tenant `mfa_required=true` + user without MFA: blocked from any dashboard route except `/security/mfa/*` until enrolled.
  - **Cookie hijack:** request to `GET /mfa/totp` with a `LoginSession` cookie that does NOT match the session whose `mfa_pending_user_id` is set → redirect to `/login`, no cookie/state leakage.
  - **Orphan self-heal:** force `users.mfa_enabled=true` while no confirmed `UserTotpSecret` row exists → `GET /mfa/totp` audits `USER_MFA_STATE_INCONSISTENT`, calls `disable`, redirects to `/login`.
- **validation:** Tests green.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T27: Dev environment rollout
- **depends_on:** [T23, T24, T25, T26]
- **location:** local + dev cluster
- **description:** Generate a fresh Fernet key (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`), set as `MFA_SECRET_ENCRYPTION_KEY` in dev env. Run `alembic upgrade head` against dev. Smoke test: enroll Matt's account on members.opensensor.io (dev), verify, regenerate codes, disable.
- **validation:** All flows pass against dev. Audit log shows expected entries. No errors in pod logs.
- **status:** Not Completed
- **log:**
- **files edited/created:**

### T28: Production rollout
- **depends_on:** [T27]
- **location:** Kubernetes secret + `whitewhale/opensensor-fief` deployment
- **description:** Order matters — the new image will fail-fast at boot if the env var isn't present (per T4). Execute strictly in this order:
  1. `kubectl -n whitewhale patch secret opensensor-fief --patch='{"stringData":{"MFA_SECRET_ENCRYPTION_KEY":"<NEW_KEY>"}}'` (key generated as in T27, stored in 1Password vault first).
  2. Confirm: `kubectl -n whitewhale get secret opensensor-fief -o jsonpath='{.data.MFA_SECRET_ENCRYPTION_KEY}' | base64 -d` returns the key.
  3. Trigger the deploy: push the image build (or `kubectl rollout restart deploy/opensensor-fief` if image is `:latest`).
  4. Watch `kubectl rollout status` and pod logs for the "MFA encryption: 1 active key" startup line. If you see `EnvironmentError: MFA_SECRET_ENCRYPTION_KEY must be set`, abort and revisit step 1.
  5. Smoke-test enrollment on a real account on each of lightnvr / owlbooks / opensensor; verify QR issuer label = brand name; verify works; recovery works.
- **validation:** End-to-end on all 3 brands. Pod logs show no MFA-related errors for 24 h.
- **status:** Not Completed
- **log:**
- **files edited/created:**

## Parallel Execution Groups

| Wave | Tasks                          | Can start when                           |
|------|--------------------------------|------------------------------------------|
| 1    | T1, T2, T3, T4                 | Immediately                              |
| 2    | T5, T6, T7, T8                 | Immediately (independent of Wave 1)      |
| 3    | T9, T10                        | T6 done (T9), T8 done (T10)              |
| 4    | T11, T12                       | T9 + T2 + T1 (T11), T9 (T12)             |
| 5    | T13, T14, T15, T16             | T11+T12 done (T13, T14); T15 and T16 can run in parallel with T13/T14 since they only need T7/T8 |
| 6    | T17, T18, T19, T21, T22        | T13/T14 done                             |
| 7    | T20                            | T13-T16 done                             |
| 8    | T23, T24, T25, T26             | Services + routes done                   |
| 9    | T27 → T28                      | All tests green                          |

Practical agent assignment: 4 agents in Wave 1+2 simultaneously (T1, T2, T3+T4 group, schema group). 2 agents through Waves 3-4. 1-2 agents through Waves 5-7. Tests parallel.

## Testing Strategy
- **Service-level unit tests** (T23, T24) drive coverage on TotpService, RecoveryCodeService, and the Fernet helper. These are pure-Python and run in milliseconds.
- **Integration tests** (T25, T26) exercise the full HTTP flow with real DB + LoginSession state. Mirror the existing `tests/auth/` structure.
- **Manual rollout test** (T27, T28) on each of the 3 production brands; QR issuer label is the brand name (so `LightNVR (you@x.com)` shows in Authy/1Password).
- **Negative paths covered:** invalid code, replayed code, expired drift window, lockout, locked-then-restart, recovery exhaustion, recovery code reuse, tenant enforcement bypass attempt.

## Risks & Mitigations
- **Fernet key loss = total MFA wipeout for all users.** Treat as an in-cluster secret with off-cluster backup (1Password vault). Document recovery procedure in `docs/runbooks/mfa-key-rotation.md` (out of scope here, file as a follow-up task).
- **Schema migration on a populated `fief_users` and `fief_tenants` table.** Both new columns default to `false`; migration is online-safe. Confirm migration timing on production matches our existing pattern.
- **`LoginSession` row growth.** Existing table is already cleaned up by TTL; new columns are nullable so no extra storage when MFA isn't in use.
- **QR PNG generation latency.** `segno` is in-memory and fast; embed as a `data:image/png;base64` URI directly in the response — no separate fetch.
- **Pyotp default of 30s window with valid_window=1** allows ±30s drift. Keep this; mainstream authenticators are accurate to a few seconds.
- **Brand issuer label leakage.** Whatever name we pass becomes the user's authenticator entry. We pass `brand.name` (already public-facing); no PII concern.
- **Backwards compatibility.** Existing logged-in users without MFA: zero impact. Existing logged-in users who later enroll: their current session continues (no force-logout); next sign-in goes through MFA.

## Plan revisions applied from subagent review (2026-05-09)
- **T4** — startup validation runs unconditionally (not gated on "MFA route registered"); explicit boot log added.
- **T11** — `begin_enrollment` upserts unconfirmed rows; raises on already-confirmed; verify path catches `MfaSecretDecryptionError` and returns INCONSISTENT_STATE with audit-log + structured log.
- **T12** — recovery code hashing uses `passlib.hash.bcrypt` directly (independent of project password-hash migrations).
- **T14** — added cookie-binding (anti-hijack) check + orphan self-heal on the GET handlers.
- **T15** — dropped `T11` dep (only needs T8); now also clears stale MFA carry-state at start of every fresh `/login` POST; helper renamed to `complete_login_after_mfa`.
- **T16** — dropped `T15` dep (only needs `[T7, T8]`); merge-coordinate at code-review time with T15.
- **T19** — recovery-codes filename uses a slugify filter; brand_slug is not assumed to exist on the model.
- **T22** — explicit note about `brand_id` source from existing dashboard request context.
- **T26** — added cookie-hijack and orphan-self-heal integration tests as `tests/auth/test_mfa_security.py`.
- **T28** — converted production rollout into a strictly-numbered preflight (secret first, deploy second).

## Open questions deferred to implementation
- Whether to mark `users.mfa_enabled=true` only after the *first successful login challenge* rather than at enrollment-confirm time (would prevent a half-enrolled state where the user closes the page before saving recovery codes). Recommended: keep at confirm time — it's clearer UX and the code handles the "no recovery codes" edge gracefully.
- Whether `/api/users/{id}/mfa/reset` should require an admin to provide a reason (audit metadata). Defer; add to the audit log enum's `extra` field if/when needed.
