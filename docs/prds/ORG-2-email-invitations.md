# ORG-2 — Organization email invitations

**Status:** Draft · **Owner:** TBD · **Tier:** 2 · **Depends on:** ORG-1

## Summary
Let an org admin invite people to their organization by email, with a chosen role. Existing users join with one click; new users complete a short signup that auto-attaches to the org. Tokens are signed, single-use, and time-bound.

## Why now
- ORG-1 introduces orgs but the only way in is admin-adds-by-email. Real B2B onboarding requires self-serve invites.
- Brand-aware email infrastructure already exists; we plug in one new template type.

## Goals
1. Admins can send invitations to any email; existing users or not.
2. Invitations are: pending → accepted | revoked | expired.
3. Invite emails are brand-aware (use the dashboard's brand for sender + masthead, just like other transactional emails).
4. Acceptance link is single-use; reusing returns "already used" without leaking state.
5. Bulk invite: paste up to 50 addresses, one role for the batch.
6. Resend (re-issues a fresh token, invalidates the old).
7. Audit log entries for send, accept, revoke, expire.

## Non-goals
- "Invite via Slack / shareable link" (track separately if asked).
- Org admin approval workflow ("user requested to join"). Defer.
- Domain-claim auto-join ("anyone @lightnvr.com auto-joins LightNVR org"). Defer to a separate "Domain capture" PRD.
- SCIM-driven membership (covered by ENT-2).

## Data model

```
fief_organization_invitations
  id              uuid pk
  organization_id uuid fk organizations
  invited_email   text                          -- normalized lowercase
  role_id         uuid fk roles
  invited_by      uuid fk users
  token_hash      text                          -- SHA-256 of token
  status          enum('pending','accepted','revoked','expired')
  expires_at      timestamp                     -- default now() + 7 days
  accepted_at     timestamp null
  accepted_by     uuid null fk users
  created_at      timestamp
  index (organization_id, status)
  index (invited_email, status)
```

Token is a 32-byte random URL-safe string. We store only its SHA-256 to avoid leaking on DB compromise.

## Email template

New `EmailTemplateType.ORGANIZATION_INVITATION`. Subject:
`{{ inviter.name }} invited you to {{ organization.name }} on {{ brand.name if brand else tenant.name }}`

Body block:

> {{ inviter.name }} invited you to join **{{ organization.name }}** as **{{ role.name }}** on {{ brand.name }}. This invitation expires in 7 days.
>
> [Accept invitation] (CTA → `{{ accept_url }}`)

Render path: same as the existing welcome / verify-email templates so brand sender / masthead apply automatically.

## Endpoints

### Admin
| Method | Path                                                                   | Purpose                                |
|--------|------------------------------------------------------------------------|----------------------------------------|
| POST   | `/api/organizations/{org_id}/invitations`                              | Single or bulk send                    |
| GET    | `/api/organizations/{org_id}/invitations`                              | List (filter by status)                |
| POST   | `/api/organizations/{org_id}/invitations/{id}/resend`                  | Reissue token                          |
| DELETE | `/api/organizations/{org_id}/invitations/{id}`                         | Revoke                                 |

### Public accept flow
| Method | Path                                                                   | Purpose                                |
|--------|------------------------------------------------------------------------|----------------------------------------|
| GET    | `/invitations/{token}`                                                 | Landing page (preview org + role)      |
| POST   | `/invitations/{token}/accept`                                          | Accept                                 |

## Accept flows

### Already a user, signed in with matching email
Single click → membership created → redirect to dashboard with org switched.

### Already a user, signed in with different email
Banner: "This invitation was sent to alice@firm.com. Sign in as that user to accept." Disallow accept.

### Already a user, signed out
Redirect through login (preserving the invitation token), then accept.

### Not a user
Show a streamlined registration form pre-filled with `invited_email` (locked). On signup, auto-create the user, mark email verified (the invitation IS the verification), create membership, sign in.

## Edge cases
- User accepts after expiry → 410 Gone, "This invitation has expired."
- User accepts after revoke → 410 Gone, generic.
- Same email invited twice while pending → upsert; second send invalidates the first token.
- Email of pending invitation matches an existing user — fine; we still send the invite, accept just creates membership.
- User changes the email associated with their account between invite and accept — accept allowed only if either current OR original email matches the invitation.
- Bulk invite with 50 addresses: validate first, atomic-ish insert per row, return per-row results.

## Rate limiting
- Per-tenant: max 1000 invitations per 24 h.
- Per-admin user: max 100 per hour.
- Per-recipient email: max 1 invitation per org per hour (prevents spam).
Wired through SEC-1.

## Telemetry
- `org.invitation.sent`, `org.invitation.accepted`, `org.invitation.expired`, `org.invitation.revoked`.
- Surface `acceptance_rate` per org in the admin UI.

## Risks
- Mass-invite as a spam vector. Mitigation: rate limits + must be tenant admin or org admin.
- Email deliverability — already on Mailjet with verified domains, fine.
- Race: two admins simultaneously invite the same email → unique constraint on (org, invited_email, status='pending'); second errors with "already invited."

## Open questions
- Auto-expire pending invitations after 7 days via cron, or lazily on access? Recommend lazily on access + a periodic cleanup task.
- Do we send a "you've been added" email if an admin adds a user directly (no invite)? Recommend yes; reuses welcome template.

## Sequencing
~1 sprint after ORG-1. Schema + send + accept in week 1. UI (list table, bulk paste) + edge cases + tests in week 2.
