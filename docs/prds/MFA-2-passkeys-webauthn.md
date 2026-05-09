# MFA-2 — Passkeys / WebAuthn

**Status:** Draft · **Owner:** TBD · **Tier:** 1/2 · **Depends on:** MFA-1 (shares "Security" UI surface)

## Summary
Support [WebAuthn](https://www.w3.org/TR/webauthn-2/) credentials — passkeys synced via iCloud / Google Password Manager, plus platform authenticators (Touch ID, Windows Hello) and roaming security keys (YubiKey). Use cases:

1. As a **second factor** alongside password (immediate value).
2. As a **primary, passwordless** auth method via discoverable credentials (the future).

## Why now
- Apple, Google, and Microsoft are aggressively normalizing passkeys; 2026 users expect them.
- The strongest phishing-resistant factor available without proprietary hardware.
- Big differentiator for OpenSensor's brand promise (security-conscious products).

## Goals
1. Users can register one or more passkeys from the dashboard "Security" tab.
2. On sign-in, after primary credential, user can choose passkey instead of TOTP.
3. Discoverable credential / "passwordless" flow: a "Sign in with a passkey" button on the login page that skips email entry.
4. Per-credential metadata (label, last used, transport) visible in the dashboard.
5. Audit log for register / verify / delete.

## Non-goals
- Attestation enforcement / FIDO MDS validation (defer to a separate PRD if a customer requires FIPS).
- Server-side conditional UI hints.
- Passkey-only accounts (we always keep a recovery option — TOTP, password, or recovery codes).

## Library
Use [`webauthn`](https://pypi.org/project/webauthn/) (Duo Labs / py_webauthn). Mature, async-friendly, MIT.

## Data model

```
fief_user_credentials
  id                uuid pk
  user_id           uuid fk users
  credential_id     bytea           -- raw, indexed
  public_key        bytea
  sign_count        bigint
  transports        text[]          -- ["internal","hybrid","usb","nfc","ble"]
  aaguid            uuid null
  backup_eligible   bool
  backup_state      bool
  label             text            -- user-chosen, e.g. "MacBook"
  attestation_obj   bytea null      -- raw, optional retention
  last_used_at      timestamp null
  created_at        timestamp
  index (credential_id)             -- lookup on auth
  index (user_id)
```

## Configuration (per Relying Party)

```
WEBAUTHN_RP_ID = "members.lightnvr.com"   -- per-brand
WEBAUTHN_RP_NAME = "LightNVR"             -- per-brand
WEBAUTHN_ORIGINS = ["https://members.lightnvr.com"]
```

`rp_id` is computed from the **brand host** at request time (so members.opensensor.io, members.lightnvr.com, members.owlbooks.ai each have distinct credential scopes — no cross-brand passkey sharing on purpose; matches user expectation).

## Flows

### Registration
1. POST `/security/passkeys/begin-registration` → server generates `PublicKeyCredentialCreationOptions` (challenge stored in session, 5 min TTL), `excludeCredentials = user's existing credentials`, `userVerification = "preferred"`.
2. Browser invokes `navigator.credentials.create()`.
3. POST `/security/passkeys/finish-registration` with attestation response → server validates, persists row, returns the credential's user-facing label-edit form.
4. Audit log + UI shows new entry.

### Authentication (2FA mode)
1. After password (and possibly TOTP fallback choice), GET `/mfa/passkey` → server creates `PublicKeyCredentialRequestOptions` with `allowCredentials = user's credentials`.
2. `navigator.credentials.get()`.
3. POST `/mfa/passkey/verify` → server validates signature, increments sign_count, sets last_used_at, completes login.

### Discoverable / passwordless
1. Login page: "Sign in with a passkey" button → POST `/auth/passkey/begin` (no user identifier) → server returns options with `allowCredentials = []`.
2. `navigator.credentials.get({ mediation: "conditional" })` triggers OS UI.
3. POST `/auth/passkey/finish` → server resolves user from `credential_id`, validates, signs them in directly (subject still goes through MFA enforcement: passkey IS the strong factor, so done).

### Delete
- Dashboard list row → "Remove" → confirm with current password (or another passkey) → soft delete the row.
- Cannot delete the last credential if it is the user's *only* second factor; show a guard.

## Endpoints

| Method | Path                                       | Purpose                                |
|--------|--------------------------------------------|----------------------------------------|
| POST   | `/security/passkeys/begin-registration`    |                                        |
| POST   | `/security/passkeys/finish-registration`   |                                        |
| PATCH  | `/security/passkeys/{id}`                  | Rename label                           |
| DELETE | `/security/passkeys/{id}`                  |                                        |
| POST   | `/mfa/passkey/begin`                       | 2FA challenge for known user           |
| POST   | `/mfa/passkey/verify`                      |                                        |
| POST   | `/auth/passkey/begin`                      | Discoverable / passwordless start      |
| POST   | `/auth/passkey/finish`                     |                                        |

## Edge cases
- `sign_count` rollback (cloned authenticator) — log a security event, surface to admin, reject the auth.
- User has multiple passkeys for same `aaguid` (iCloud-synced across devices) — fine, they share `credential_id` on roaming, distinct on platform.
- Different brand hosts → distinct rp_id → distinct credentials. A user with lightnvr.com and owlbooks.ai accounts has separate passkeys per host — by design.
- Browser without WebAuthn — feature-detect; fall back to TOTP.
- User loses all passkeys and TOTP — recovery codes from MFA-1 still work.

## Telemetry
- `webauthn.register.{success,failure}`, `webauthn.auth.{success,failure}`, `webauthn.passwordless.success`, `webauthn.sign_count_rollback`.

## Risks
- Implementation correctness — WebAuthn is fiddly. Mitigation: lean on `webauthn` lib, write thorough integration tests with the [virtual-authenticator chrome devtools API](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/).
- Cross-brand confusion — clarify in copy that passkeys are scoped to the site they were created on.

## Open questions
- Default `userVerification` setting — `preferred` (most permissive) vs. `required`? Recommend `preferred` to keep YubiKey-without-PIN users working.
- Allow registration without a password set on the account? (For SAML-only users in future.) Defer to ENT-1 follow-up.

## Sequencing
~2 sprints. Sprint 1: registration + 2FA verify + UI. Sprint 2: discoverable / passwordless flow + multi-credential management + sign_count rollback handling.
