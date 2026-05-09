# MFA-1 — TOTP MFA + Recovery Codes

**Status:** Draft · **Owner:** TBD · **Tier:** 1 · **Depends on:** —

## Summary
Add a second authentication factor based on TOTP (RFC 6238) with one-time recovery codes. Users opt-in from the dashboard "Security" tab; admins can require it per-tenant.

## Why now
- Today there is no second factor at all on `members.*`. A leaked password is full account compromise.
- It is a credibility / security-review checkbox for every B2B customer of OwlBooks.
- It is the foundation for the WebAuthn flow (MFA-2): both share the same "challenge after primary credential" surface.

## Goals
1. Users can enroll a TOTP authenticator (Google Authenticator, 1Password, Authy, etc.) with a QR code.
2. After enrollment, sign-in requires the 6-digit code as a second step.
3. 10 single-use recovery codes are generated at enrollment, regeneratable.
4. Tenant-level setting `mfa_required` enforces enrollment on next login.
5. Audit-logged: enroll, disable, successful 2FA, failed 2FA, recovery-code use.

## Non-goals
- SMS OTP (deliberately excluded; weaker than TOTP).
- Push-based MFA.
- Per-role MFA enforcement (postpone until ORG-1).
- Risk-based / adaptive MFA.

## Data model

```
fief_user_totp_secrets
  id                uuid pk
  user_id           uuid fk users (unique)
  secret_encrypted  bytea          -- AES-GCM with KMS key, never plaintext
  confirmed_at      timestamp null -- null until first valid code submitted
  last_used_at      timestamp null
  created_at        timestamp

fief_user_mfa_recovery_codes
  id                uuid pk
  user_id           uuid fk users
  code_hash         text           -- bcrypt or argon2 of code
  used_at           timestamp null
  created_at        timestamp
  index (user_id, used_at)
```

`tenants.mfa_required` (bool, default false) — when true, users without `confirmed_at` are forced into enrollment after primary credential.

## Flows

### Enrollment (from dashboard `/security/mfa`)
1. POST `/security/mfa/totp/begin` → server generates secret, stores row with `confirmed_at = null`, returns `otpauth://` URI + QR PNG.
2. User scans, enters first 6-digit code → POST `/security/mfa/totp/confirm` → server validates with ±1 step drift, sets `confirmed_at`, generates 10 recovery codes, returns them in the response **once**.
3. Recovery codes shown in a "download / print" view; reload removes them.

### Sign-in
1. Primary credential succeeds → if user has `confirmed_at IS NOT NULL`, redirect to `/mfa/totp` (carrying the login session ID).
2. User enters code → server validates current ± previous step.
3. On 5 failures within 10 min for the same login session, lock that login session (must restart from primary).

### Recovery
- "Lost your device?" link on the TOTP prompt → `/mfa/recover`.
- Enter recovery code → consumed (set `used_at`), TOTP secret revoked, user is logged in and forced to re-enroll.

### Disable
- From dashboard with current password re-prompt. Wipes both tables.

## Endpoints

| Method | Path                                     | Purpose                                |
|--------|------------------------------------------|----------------------------------------|
| POST   | `/security/mfa/totp/begin`               | Start enrollment                       |
| POST   | `/security/mfa/totp/confirm`             | Confirm + generate recovery codes      |
| POST   | `/security/mfa/totp/disable`             | Disable (requires password)            |
| POST   | `/security/mfa/recovery-codes/regenerate`| Regenerate (invalidates previous)      |
| GET    | `/mfa/totp`                              | Login-time challenge page              |
| POST   | `/mfa/totp/verify`                       | Submit 6-digit code                    |
| GET    | `/mfa/recover`                           | Recovery code entry                    |
| POST   | `/mfa/recover`                           | Consume recovery code                  |

## UX

New left-rail nav item in the modernized dashboard: **Security**. Sections: TOTP, Recovery codes, (later) Passkeys, (later) Sessions.

## Edge cases
- Clock drift: accept window `[now-30s, now+30s]` plus current.
- Replay: store `last_used_at` step counter, refuse the same step twice.
- User changes password while MFA enrolled — keep MFA, no re-enrollment.
- User deletes account — cascade.
- Account in tenant where `mfa_required` flips from false → true: gate next login on enrollment.

## Risks
- Encryption key for `secret_encrypted` — current Fief code encrypts at rest? Audit before deploying. If not, add an `MFA_SECRET_KEY` env (Fernet) or KMS handle.
- Recovery codes stored hashed — irreversibly lose them if user doesn't save.

## Telemetry
- Counters: `mfa.totp.enroll.success`, `mfa.totp.verify.{success,failure}`, `mfa.recovery.consumed`.
- Audit log entries on every MFA state change.

## Open questions
- Do we offer TOTP at sign-up, or only post-signup? (Recommend: post-signup only.)
- Does an admin "force re-enroll for user" make sense for support? (Recommend yes; goes in admin API.)

## Sequencing
~1 sprint. Enrollment + verify in week 1, recovery codes + tenant enforcement + UI polish in week 2.
