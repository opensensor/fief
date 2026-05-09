# ENT-1 — SAML SSO (per-organization Service Provider)

**Status:** Draft · **Owner:** TBD · **Tier:** 2 · **Depends on:** ORG-1

## Summary
Become a SAML 2.0 Service Provider so enterprise customers can configure their IdP (Okta, Entra ID / Azure AD, Google Workspace, OneLogin, JumpCloud, Ping) to sign their users into our products. Each Organization configures its own IdP; users from that org can SP-initiated or IdP-initiated sign in, with **just-in-time provisioning** into the org.

## Why now
- This single feature is the gate to every enterprise sale above ~$30k ACV. Auth0 charges per-user explicitly because of this.
- OwlBooks accounting customers (firms) increasingly require SSO with their existing IdP.
- Builds on ORG-1: the IdP config attaches to an Organization, not a Tenant.

## Goals
1. Per-org SAML configuration: entity ID, SSO URL, X.509 cert, NameID format, attribute mapping.
2. SP metadata endpoint per org (`/saml/{org_slug}/metadata.xml`) for IdP setup.
3. SP-initiated login from `members.<brand>.com/saml/{org_slug}/login`.
4. IdP-initiated login at the ACS endpoint.
5. JIT provisioning: if the IdP-asserted user does not yet exist, create them and add to the org.
6. Attribute mapping for email, given name, family name, role.
7. SAML-only org enforcement: optional flag — users in this org cannot use password login.
8. Audit logged.

## Non-goals
- IdP-side metadata auto-discovery / metadata refresh polling (manual paste / re-upload is fine for v1).
- Encrypted SAML assertions (signing only). Add later if a customer requires.
- SAML logout (Single Logout). Defer; logout from our side is sufficient.
- WS-Federation. (Don't.)

## Library
[`python3-saml`](https://github.com/SAML-Toolkits/python3-saml) (OneLogin) — battle-tested, used by Auth0 fork projects, GitLab, etc. AGPL-incompatible? It's MIT — fine.

## Data model

```
fief_organization_saml_configs
  id                  uuid pk
  organization_id     uuid fk organizations  unique
  enabled             bool default false
  idp_entity_id       text                 -- IdP's entity URI
  idp_sso_url         text                 -- IdP's SSO endpoint (HTTP-Redirect or HTTP-POST)
  idp_slo_url         text null
  idp_x509_cert       text                 -- PEM
  name_id_format      text default 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
  attr_email          text default 'email'
  attr_given_name     text default 'given_name'
  attr_family_name    text default 'family_name'
  attr_role           text null            -- e.g. "groups"; mapped via role_mapping
  role_mapping        jsonb default '{}'   -- {"firm-admin":"admin","firm-member":"member"}
  default_role_id     uuid fk roles
  enforce_saml_only   bool default false   -- users in this org cannot password-login
  jit_provisioning    bool default true
  created_at          timestamp
  updated_at          timestamp
```

SP signing key (one per environment, not per org) lives in env / KMS.

## Endpoints

### SP metadata + auth
| Method | Path                                          | Purpose                                |
|--------|-----------------------------------------------|----------------------------------------|
| GET    | `/saml/{org_slug}/metadata.xml`               | SP metadata (consumed by IdP)          |
| GET    | `/saml/{org_slug}/login`                      | SP-initiated AuthnRequest redirect     |
| POST   | `/saml/{org_slug}/acs`                        | Assertion Consumer Service             |
| GET    | `/saml/{org_slug}/sls`                        | (Future) SLO endpoint                  |

### Admin
| Method | Path                                                           | Purpose                                 |
|--------|----------------------------------------------------------------|-----------------------------------------|
| GET    | `/api/organizations/{id}/saml`                                 | Read config                             |
| PUT    | `/api/organizations/{id}/saml`                                 | Upsert (XML metadata or fields)         |
| DELETE | `/api/organizations/{id}/saml`                                 | Disable                                 |
| POST   | `/api/organizations/{id}/saml/test`                            | Generate a fresh AuthnRequest URL       |

## Flows

### SP-initiated
1. User visits `members.<brand>.com/saml/acme/login`.
2. We redirect to IdP with a signed AuthnRequest.
3. IdP authenticates user, POSTs SAMLResponse to ACS.
4. We validate signature, in-response-to ID, audience, NotOnOrAfter, NotBefore.
5. Resolve user by email; create if `jit_provisioning` and missing.
6. Add to org with `default_role_id` (overridden by `role_mapping[asserted_role]`).
7. Issue our session + redirect to original destination.

### IdP-initiated
- IdP posts to `/saml/{org_slug}/acs` directly. We validate, treat exactly like SP-initiated minus the InResponseTo check.

### JIT user creation
- Email is the unique key.
- Email auto-marked verified (the IdP is authoritative).
- No password set; `password_hash` is null. If `enforce_saml_only`, user can never set a password through our flows.

### SAML-only enforcement
- When org has `enforce_saml_only = true` and a user tries to log in via password:
  - If they have any membership where the org enforces SAML, redirect them to that org's `/saml/{slug}/login`.
  - Edge: user is in two orgs, one enforced and one not — block password if **all** their orgs enforce; otherwise allow but the SAML org session won't activate without SSO.

## Org admin UI
Inside ORG-1's "Organization" tab, new "Single sign-on" sub-page:
1. Step-by-step: copy our SP metadata URL → paste it in your IdP → upload IdP metadata XML or paste fields → test login → flip "Enabled" toggle.
2. Show a clear banner if SP signing key is rotated.

## Edge cases
- IdP cert rotation — admin re-uploads. We do not auto-fetch (yet).
- Clock skew — `python3-saml` allows tolerance; expose as `SAML_CLOCK_SKEW_SECONDS` env (default 60).
- Replay — store last seen response IDs for 10 minutes; reject duplicates.
- User's email asserted via SAML differs from their existing account email — match on the asserted email only; if user must merge, support intervenes.
- Brand → tenant → org match — the request hostname determines the tenant/brand; the URL slug determines the org. Mismatch = 404.

## Security
- Sign all AuthnRequests.
- Require signed assertions; reject unsigned.
- Validate audience = our SP entity ID.
- Validate ACS URL = the request URL.
- Reject if IdP cert PEM doesn't parse or doesn't match assertion signature.

## Telemetry
- `saml.authnrequest.sent`, `saml.acs.{success,failure}`, `saml.jit_provisioned`, `saml.replay_blocked`, `saml.signature_mismatch`.

## Risks
- python3-saml uses `xmlsec` C lib; deployment dependency. Already common; small operational risk.
- Misconfigured IdP — most failures will be at setup time. Mitigation: a verbose `/saml/{slug}/test` endpoint that surfaces parse errors to the admin.

## Open questions
- Multiple IdPs per org? Defer (uncommon).
- IdP discovery for users on a public login page? Use email-domain hint: if email matches `acme.com` and an org has SAML enforced for that domain, redirect. Track as separate "Domain capture" PRD.

## Sequencing
~2-3 sprints. Sprint 1: schema + metadata + AuthnRequest + ACS happy path. Sprint 2: JIT + role mapping + admin UI. Sprint 3: SAML-only enforcement, edge cases, hardening, customer pilot.
