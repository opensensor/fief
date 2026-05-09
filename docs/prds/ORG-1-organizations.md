# ORG-1 — Organizations as a first-class layer

**Status:** Draft · **Owner:** TBD · **Tier:** 2 · **Depends on:** —

## Summary
Introduce **Organization** as a first-class entity sitting between `Tenant` and `User`. Users may belong to multiple organizations; roles and permissions become **organization-scoped**. JWTs carry an active `org_id`. Existing single-user accounts continue to work via an auto-created "personal" organization.

## Why now
- OwlBooks accounting workflows are inherently multi-user-per-firm. Without organizations, a firm's bookkeeper, accountant, and admin can't share state.
- Current roles/permissions are global per-user and tenant-wide; this prevents per-org admin separation ("Alice is admin of Firm A, member of Firm B").
- ORG-1 is the gating decision for the entire B2B feature track (ORG-2 invitations, ENT-1 SAML, ENT-2 SCIM).

## Goals
1. New `fief_organizations` table; `fief_organization_memberships` joins users to orgs with a per-org `role_id`.
2. Active org concept: a user with multiple memberships chooses one (carried in session + JWT claim `org_id`).
3. Existing users get an auto-created personal org as part of the migration; their existing role becomes the role on that org membership.
4. Roles and permissions are now scoped: a user can have role X in org A and role Y in org B.
5. Authorization API: `user_has_permission(user, permission, org_id)`.
6. Admin API + UI: list/create/update/delete orgs, list members, change member role.
7. Compatible with the existing brand routing (a brand resolves to a tenant; org is independent).

## Non-goals
- Hierarchical orgs (org → sub-org). Flat for v1.
- Cross-tenant org membership. Each org belongs to one tenant.
- Per-org branding (a future extension; defer).
- Billing entity tied to org (different system).

## Data model

```
fief_organizations
  id              uuid pk
  tenant_id       uuid fk tenants
  name            text
  slug            text                           -- URL-safe, unique within tenant
  is_personal     bool default false             -- auto-created for solo users
  created_at      timestamp
  unique (tenant_id, slug)

fief_organization_memberships
  id              uuid pk
  organization_id uuid fk organizations
  user_id         uuid fk users
  role_id         uuid fk roles                  -- role within this org
  joined_at       timestamp
  unique (organization_id, user_id)

-- Existing tables: roles & permissions stay unchanged in shape, but
-- semantically a role is now applied per-membership rather than per-user.

-- Drop or deprecate: users.role_id (current global role)
```

A nullable `users.default_organization_id` lets us remember which org to set as active on next login.

## JWT claims

```jsonc
{
  "sub": "<user_uuid>",
  "iss": "https://members.lightnvr.com",
  "aud": "<client_id>",
  "tenant_id": "<tenant_uuid>",
  "org_id": "<active_org_uuid>",          // NEW
  "org_slug": "acme-bookkeeping",         // NEW
  "org_role": "admin",                    // NEW (string codename)
  "permissions": ["accounts:read", ...],  // permissions resolved for that role
  // ... existing claims
}
```

## Endpoints

### User-facing
| Method | Path                                       | Purpose                                |
|--------|--------------------------------------------|----------------------------------------|
| GET    | `/api/me/organizations`                    | List orgs the user belongs to          |
| POST   | `/api/me/organizations/active`             | Switch active org → re-issue tokens    |
| POST   | `/api/me/organizations`                    | Create a new org (becomes admin)       |

### Admin
| Method | Path                                       | Purpose                                |
|--------|--------------------------------------------|----------------------------------------|
| GET    | `/api/organizations`                       | Tenant-wide list                       |
| POST   | `/api/organizations`                       | Create                                 |
| PATCH  | `/api/organizations/{id}`                  | Update name/slug                       |
| DELETE | `/api/organizations/{id}`                  | Soft delete                            |
| GET    | `/api/organizations/{id}/members`          | List members                           |
| POST   | `/api/organizations/{id}/members`          | Add (post-ORG-2 prefer invitation)     |
| PATCH  | `/api/organizations/{id}/members/{user_id}`| Change role                            |
| DELETE | `/api/organizations/{id}/members/{user_id}`| Remove                                 |

## UX
- Dashboard top-right gets an **org switcher dropdown** showing current org + list. Switching POSTs to `/api/me/organizations/active` and refreshes tokens.
- New "Organization" tab in dashboard sidebar (when admin role): name, slug, members table.
- Sign-up creates a personal org by default; user can rename.

## Migration plan

```
-- alembic up
1. create fief_organizations, fief_organization_memberships
2. for each user with a tenant_id: create personal org "{user.email}'s org"
3. for each user: insert membership (org=personal_org, role=existing user.role_id)
4. set users.default_organization_id = personal_org.id
5. (do NOT drop users.role_id yet — back-compat for one release)
```

Two-phase: first release writes both `users.role_id` and the new membership table; second release deprecates the old column once readers are migrated.

## Authorization changes
- Replace `has_permission(user, perm)` with `has_permission(user, perm, org_id=None)`. If `org_id is None`, fall back to active org from session.
- Update `permissions` claim builder to resolve via membership.

## Risks
- Big surface area — every endpoint that touches "current user's role" needs an audit. Plan: codemod + grep for `user.role` and `has_permission(`.
- Refresh tokens hold `org_id` — switching active org invalidates and re-issues. Existing tokens issued before migration must continue to work; gate via a `claims_version` field in refresh_tokens.
- Personal-org bloat: one row per user. Acceptable; fold into delete cascade.

## Telemetry
- `org.created`, `org.member.added`, `org.member.removed`, `org.role.changed`, `org.switched`. All audit-logged.

## Open questions
- Should an account be deletable while sole admin of a non-personal org? Decision: block; require ownership transfer. (Mirror Slack/Linear behavior.)
- Should we emit `org_id` claim even when a user is in a single org? Decision: yes — clients should never have to special-case.

## Sequencing
~2 sprints. Sprint 1: schema + migration + auth resolver + JWT claim plumbing + tests. Sprint 2: admin UI + org switcher + dashboard "Organization" tab + invitation hooks (handed off to ORG-2).
