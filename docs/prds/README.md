# Auth Platform PRDs

These PRDs describe the path from "credible OIDC IdP" to "auth platform we never need to migrate off of." They are scoped to the OpenSensor / LightNVR / OwlBooks product portfolio.

| # | ID    | Title                                              | Tier  | Depends on           |
|---|-------|----------------------------------------------------|-------|----------------------|
| 1 | MFA-1 | TOTP + recovery codes                              | 1     | —                    |
| 2 | SEC-1 | Auth-endpoint rate limiting, lockout, enumeration  | 1     | —                    |
| 3 | SEC-2 | HIBP breached-password check                       | 1     | SEC-1 (shared infra) |
| 4 | ORG-1 | Organizations as a first-class layer               | 2     | —                    |
| 5 | ORG-2 | Email invitations                                  | 2     | ORG-1                |
| 6 | MFA-2 | Passkeys / WebAuthn                                | 1/2   | MFA-1 (UI surface)   |
| 7 | ENT-1 | SAML SSO (per-organization Service Provider)       | 2     | ORG-1                |
| 8 | ENT-2 | SCIM 2.0 provisioning                              | 2     | ORG-1, ENT-1         |
| 9 | UX-1  | Active sessions & devices tab                      | 3     | —                    |

**Tier 1** — security/credibility table-stakes. Ship before any new product launch.
**Tier 2** — B2B unlock for OwlBooks (and any future enterprise sale).
**Tier 3** — trust UX & ops polish.

Suggested execution order: **MFA-1 → SEC-1 → SEC-2 → UX-1 → ORG-1 → ORG-2 → MFA-2 → ENT-1 → ENT-2.**
MFA-2 (passkeys) can run on a parallel track once MFA-1 is in production.
