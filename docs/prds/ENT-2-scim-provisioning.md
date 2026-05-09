# ENT-2 — SCIM 2.0 provisioning

**Status:** Draft · **Owner:** TBD · **Tier:** 2 · **Depends on:** ORG-1, ENT-1

## Summary
Expose a SCIM 2.0 ([RFC 7642 / 7643 / 7644](https://datatracker.ietf.org/doc/html/rfc7644)) endpoint per organization so customer IdPs (Okta, Entra, JumpCloud, OneLogin) can auto-provision and de-provision users and groups. The IdP authenticates with a per-org bearer token; supported resources are **Users** and **Groups** (groups → org roles).

## Why now
- Pairs with ENT-1. Enterprise customers want both: SAML for sign-in and SCIM so removing someone from the IdP automatically revokes their access in our products.
- Without it, customer admins must manually deprovision in our UI — a deal-breaker for any compliance-conscious buyer.

## Goals
1. Per-org SCIM endpoint with bearer-token auth.
2. CRUD on Users.
3. CRUD on Groups, mapping `Group.displayName` → an org role (configurable mapping reused from ENT-1).
4. PATCH operations (RFC 7644 §3.5.2) for active flag, name attrs, email, group memberships.
5. Filtering for `userName eq` and `displayName eq` (the two filters Okta/Entra actually use).
6. Pagination (`startIndex`, `count`).
7. Schema discovery endpoints.
8. Deprovisioning: `active=false` PATCH terminates all sessions and refresh tokens for that user in that org.
9. Audit logged.

## Non-goals
- SCIM filter language fully (just the few operators IdPs use).
- Bulk operations endpoint (RFC 7644 §3.7) — defer.
- ETags / If-Match concurrency control — defer.
- Schema extensions (we'll only expose `User`, `Group`, `EnterpriseUser`).

## Library
- Don't pull in a heavy SCIM library — none in Python ecosystem are great. Implement directly with FastAPI + a small `scim/schemas.py` module. ~600 LOC total.
- Reference: Okta and Entra agents both stick close to the spec; test against both.

## Data model

```
fief_organization_scim_tokens
  id              uuid pk
  organization_id uuid fk organizations
  token_hash      text                       -- SHA-256
  label           text                       -- e.g. "Okta production"
  last_used_at    timestamp null
  created_at      timestamp
  revoked_at      timestamp null
  index (organization_id, revoked_at)

fief_organization_scim_external_ids
  id                  uuid pk
  organization_id     uuid fk organizations
  resource_type       enum('user','group')
  resource_id         uuid                    -- user_id or role_id
  external_id         text                    -- IdP-assigned ID
  unique (organization_id, resource_type, resource_id)
  unique (organization_id, resource_type, external_id)
```

We map SCIM Groups to existing org roles. A new Group call creates a role within the org's tenant if one doesn't already exist (configurable behavior).

## Endpoints (all under `/scim/v2/orgs/{org_slug}/...`)

| Method | Path                                | Notes                                          |
|--------|-------------------------------------|------------------------------------------------|
| GET    | `/ServiceProviderConfig`            | Capabilities                                   |
| GET    | `/Schemas`                          | Schema list                                    |
| GET    | `/ResourceTypes`                    |                                                |
| GET    | `/Users`                            | Filter, paginate                               |
| POST   | `/Users`                            | Create (or 409 if exists)                      |
| GET    | `/Users/{id}`                       |                                                |
| PUT    | `/Users/{id}`                       | Replace                                        |
| PATCH  | `/Users/{id}`                       | RFC 7644 patch ops                             |
| DELETE | `/Users/{id}`                       | Soft-deactivate (sets `active=false`)          |
| GET    | `/Groups`                           |                                                |
| POST   | `/Groups`                           |                                                |
| GET    | `/Groups/{id}`                      |                                                |
| PUT    | `/Groups/{id}`                      |                                                |
| PATCH  | `/Groups/{id}`                      | Common: add/remove members                     |
| DELETE | `/Groups/{id}`                      |                                                |

## Schemas (subset)

### User
- `userName` → email (lowercase, unique within tenant)
- `name.givenName`, `name.familyName`
- `emails[primary=true].value` → email (must equal userName)
- `active` → soft-deactivate flag
- `externalId` → IdP-assigned
- `groups` (read-only listing of role memberships within the org)

### Group
- `displayName` → role name within the org's role table
- `members[].value` → user IDs
- `externalId`

## Auth
- Bearer token in `Authorization: Bearer <token>`. Token is opaque (random 40 bytes), stored as SHA-256 hash, scoped to the org in the URL.
- Token created in admin UI, copyable once on creation, never again.

## Behaviour details

### Create user (`POST /Users`)
- If a user with `userName` exists in the tenant: attach to org if not already, return 200/201.
- Else create new user with `active=true`, email-verified (asserted by IdP), no password.
- Add membership with the org's `default_role_id`.
- Honor any `groups` array by also adding/removing role memberships.

### Deactivate (`PATCH active=false`)
- Remove user's membership from this org.
- Revoke all refresh tokens issued to this user that carry this `org_id` claim.
- Invalidate active session tokens with this `org_id`.
- Do NOT delete the user account; they may still belong to other orgs.

### Group membership PATCH
- Standard ops `add`, `remove`, `replace` on `members`.
- Each membership change writes an audit log entry.

### Filtering
- Support: `userName eq "x"`, `displayName eq "x"`, `externalId eq "x"`. Reject other filters with 400 + `scimType=invalidFilter`.

## Error format
All errors per RFC 7644 §3.12: JSON body with `schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"]`, `status`, `detail`, optional `scimType`.

## Edge cases
- IdP sends a User with `userName=Alice@FIRM.com` but our store has `alice@firm.com` — normalize to lowercase on both sides; document this clearly.
- Group with same `displayName` as an existing role — match by name; if mismatch on `externalId`, treat as conflict.
- User exists in two orgs: deactivation in one doesn't touch the other.
- IdP-driven creation race with self-serve invitation acceptance — last-write-wins on attributes; `externalId` once set is sticky.

## Telemetry
- `scim.request.{resource}.{op}.{status}`, `scim.user.deprovisioned`, `scim.group.member_changed`.
- Surface in admin UI: "Last sync from Okta: 14 min ago, 3 changes."

## Risks
- Spec compliance bugs that block customer onboarding. Mitigation: run [Okta SCIM compatibility test suite](https://developer.okta.com/docs/guides/scim-provisioning-integration-prepare/main/) and Entra "Validate SCIM" tool before each release.
- Token theft → org-wide write access. Mitigation: tokens are per-org-scoped; UI shows last-used IP and timestamp; revoke is immediate.

## Open questions
- Auto-create roles for unknown groups, or 400? Default: auto-create with no permissions (admin must grant). Configurable.
- Should SCIM be enabled-by-default once the org has SAML configured? Recommend explicit opt-in.

## Sequencing
~2 sprints after ENT-1. Sprint 1: ServiceProviderConfig + User CRUD + filtering + tests against Okta. Sprint 2: Group CRUD + PATCH + Entra compatibility + UI for token management.
