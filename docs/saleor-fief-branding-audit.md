# opensensor-fief — Branding Extension Audit & Design Proposal for Saleor App Integration

**Task reference:** `fief-app-plan.md` T46 (audit phase only).
**Companion task:** `saleor-apps/apps/fief` T15 — branding-origin signer (TS side).
**Status:** Audit complete. Implementation deferred pending user review.
**Scope:** Audit-only — no Python sources modified, no pytest tests added in this task.

---

## 1. What Exists Today — Branding Surface in opensensor-fief

The Fief fork already ships a working multi-brand whitelabel system. Brand
selection today is **purely host-based** (the value of `request.url.hostname`
on whatever request is being served).

### 1.1 Data model

- **`fief/models/brand.py`** — `Brand` SQLAlchemy model (`brands` table).
  Key fields:
  - `host: str` — unique, indexed; the lookup key.
  - `name`, `application_url`, `logo_url`, `hero_url`.
  - `is_default: bool` — fallback brand when host doesn't match.
  - `tenant_id: FK` (cascade delete from `Tenant`).
  - `theme_id: FK` (set-null) — optional themed CSS.
  - `email_from_email`, `email_from_name`, `email_domain_id` — per-brand
    transactional email sender.
  - `Brand.get_email_sender(fallback_tenant=…)` — sender resolution helper.

- **`fief/schemas/brand.py`** — `BrandEmailContext` Pydantic model exposed
  to email templates (id, name, host, application_url, logo_url).

- **`fief/alembic/versions/2026-05-02_add_brand_model.py`** (rev
  `b3d8a2f47c1e`, down `a736fe95ec4f`) — creates the `brands` table.
  Subsequent brand-related migrations:
  - `2026-05-02_brandify_email_templates.py`
  - `2026-05-02_set_brand_email_senders.py`
  - `2026-05-02_set_owlbooks_logo.py`
  - `2026-05-02_add_brand_hero_url.py`
  Current alembic head (`fief/alembic/versions/2026-05-09c_add_user_lockouts.py`,
  rev `b400430e70fc`).

### 1.2 Repository

- **`fief/repositories/brand.py`** — `BrandRepository(BaseRepository[Brand])`.
  Two relevant methods:
  - `get_by_host(host: str) -> Brand | None` — exact match on `Brand.host`.
  - `get_default() -> Brand | None` — fallback (`is_default == True`).

### 1.3 Brand selection (the "branding extension")

- **`fief/dependencies/brand.py` `get_current_brand()`** — the single
  source of brand selection in the auth flow:
  ```python
  async def get_current_brand(
      request: Request,
      repository: BrandRepository = Depends(BrandRepository),
  ) -> Brand | None:
      host = request.url.hostname
      if host:
          brand = await repository.get_by_host(host)
          if brand is not None:
              return brand
      return await repository.get_default()
  ```
  No query-string input. No verification. Trusts whatever host the request
  happens to arrive on.

- **`fief/dependencies/branding.py` `get_show_branding()`** — unrelated to
  per-brand selection; reads the global `settings.branding` boolean
  (powers/hides the "Powered by Fief" footer).

- **`fief/dependencies/auth.py` lines 357–378** — `BaseContext` TypedDict
  (`request, tenant, theme, brand, show_branding`) and `get_base_context()`
  dependency, which is consumed by every auth-flow router (login, register,
  consent, dashboard, MFA flows, password reset).

### 1.4 Brand consumers (where the brand actually surfaces)

- **`fief/apps/auth/routers/dashboard.py`** — passes `brand` into post-login
  dashboard pages, MFA setup/disable flows, and recovery code generation
  (`_mfa_label(brand, tenant)` helper, lines 278–286).
- **`fief/services/user_manager.py` `_get_brand_id_from_request()`**
  (lines 329–337) — host-based brand resolution again, used to tag
  outgoing tasks (register / verify-email / forgot-password) with a
  `brand_id` so transactional emails render under the correct brand.
- **`fief/tasks/base.py` `_get_brand()`** (lines 115–121) — loads brand by
  id (with `email_domain` eager-loaded) for celery email tasks.
- **`fief/tasks/{register,email_verification,forgot_password,mfa}.py`** —
  consume `brand_id` to drive the brand-aware email templates.
- **`fief/templates/auth/layout.html`** — the visible payoff. Renders
  `brand.hero_url`, `brand.logo_url`, `brand.name`, `brand.application_url`.
  Falls back to tenant logo + `"OpenSensor"` literal + `https://opensensor.io`
  when `brand` is None.
- **`fief/templates/auth/dashboard/{layout.html,sidebar.html}`,
  `fief/templates/auth/dashboard/security/recovery_codes.html`,
  `fief/templates/auth/base.html`** — same pattern (brand title, brand
  application URL).

### 1.5 OIDC client model — current shape

**`fief/models/client.py` `Client`** (table `clients`) has:
- `name`, `first_party`, `client_type`, `client_id`, `client_secret`
- `redirect_uris: JSON list[str]`
- `encrypt_jwk: Text | None`
- token lifetimes (`authorization_code_lifetime_seconds`,
  `access_id_token_lifetime_seconds`, `refresh_token_lifetime_seconds`)
- `tenant_id: FK Tenant`

There is **no per-client signing key** for branding-origin verification
today. The closest existing per-secret-on-client surface is
`client_secret` (used for token-endpoint authentication).

### 1.6 Authorize endpoint surface

- **`fief/apps/auth/routers/auth.py` lines 112–186** — `GET /authorize`
  is the entrypoint. Today it accepts: `response_type, client_id,
  redirect_uri, response_mode, scope, prompt, screen, code_challenge*,
  nonce, state, login_hint, requested_acr, lang`. **No `branding_origin`
  parameter is read or persisted.** The handler then redirects to the
  tenant's `auth:login`/`register:register`/`auth:consent` route and
  drops a `LoginSession` cookie pointing at a row in `login_sessions`
  (see `fief/services/authentication_flow.py:50` `create_login_session`).
- **`fief/dependencies/auth.py:32 get_authorize_client`** — looks up the
  client by `client_id` + tenant. Has the `Client` instance available
  (this is the natural place to read a per-client signing key for
  HMAC verification).

### 1.7 Existing HMAC/cryptographic primitives we can reuse

- **`fief/services/webhooks/delivery.py`** — uses `hmac.new(secret,
  payload, sha256).hexdigest()` already. Good prior-art and library
  choice (stdlib `hmac` + `hashlib.sha256`).
- **`fief/crypto/token.py`** — token generation utility (also uses
  `hmac`).
- **`fief/crypto/verify_code.py`** — HMAC-based verify codes.

The codebase already standardises on stdlib `hmac` + `sha256` — the
T15 signer (Saleor side) likewise uses HMAC-SHA256, so the two sides
align without introducing a new dependency on the Fief side.

---

## 2. Current Behavior on `branding_origin`

**Direct answer: nothing.** No file under `/home/matteius/mattscoinage/opensensor-fief/`
mentions `branding_origin`. Verified via `rg -l "branding_origin"` (no
matches). The brand is selected entirely from `request.url.hostname` —
which is the public hostname Fief itself was reached on, **not** the
storefront the user came from.

### Why this is wrong for the Saleor integration

When a user clicks "log in" on, say, `shop-a.example.com`, the storefront
sends them to **Fief's** authorize URL on **Fief's** host (e.g.
`auth.opensensor.io`). With the current `get_current_brand()` logic,
`request.url.hostname == "auth.opensensor.io"` for **every** storefront,
so Fief renders whichever Brand row matches that hostname (or the
default brand) — never the storefront's brand. The Saleor PRD §5.5 (F5.2)
calls this out: the authorize URL must carry a signed `branding_origin`
naming the storefront; the Fief side must decode it and switch brand
accordingly.

---

## 3. Gap Analysis — What's Missing for Signed `branding_origin` Flow

Mapped against T46's contract and the T15 token shape
(`"{origin}.{nonce}.{expiry}.{sig}"`, HMAC-SHA256, 5-min expiry, allowlist):

| # | Gap | Where it bites today |
|---|-----|----------------------|
| G1 | No persisted per-OIDC-client signing key. | `fief.models.Client` has no `branding_signing_key` (or equivalent) column. Without this, Fief cannot verify the HMAC produced by the Saleor app's `branding/origin-signer.ts` (T15). |
| G2 | No allowlist of acceptable storefront origins. | Even if HMAC verifies, "did the operator approve this origin?" has no answer. T15 does the allowlist enforcement on the Saleor side, but the Fief side must also enforce (defence-in-depth, per R5 in the plan). |
| G3 | Authorize endpoint does not read or validate `branding_origin`. | `fief/apps/auth/routers/auth.py:112` ignores the param. |
| G4 | `get_current_brand` keys on Fief's host, not the storefront origin. | Even if the param were read, brand selection wouldn't honour it. |
| G5 | The selected origin does not survive past `/authorize`. | The browser is redirected to `/<tenant_slug>/login` (and later `/consent`, `/register`, MFA flows). Each of those re-runs `get_current_brand` against `request.url.hostname` — the verified origin must be persisted somewhere that survives the redirect chain (login session is the natural store). |
| G6 | No tests cover host-based brand selection, let alone signed-origin selection. | `rg -li "brand" tests/` finds no functional brand-selection tests. The two test files that mention "brand" do so only in pass-through assertions about `brand_id` propagation in MFA email enqueues. |
| G7 | Failure-mode policy is not documented. | The T46 description specifies "reject unsigned/invalid silently (fall back to default brand)" — no mechanism exists for this and it must be implemented intentionally so an attacker tampering with the signed param cannot phish a different brand's UI. |
| G8 | No alembic migration adds the new column. | Schema change required (see §4.5). |

---

## 4. Design Proposal — Signed `branding_origin` Support on opensensor-fief

### 4.1 Where the parameter is read

Add the read at the authorize endpoint:
- **File:** `fief/apps/auth/routers/auth.py` — extend the `authorize()`
  handler signature with `branding_origin: str | None = Query(None)`.
- **Verification dependency:** add `get_verified_branding_origin` to
  `fief/dependencies/auth.py`. It depends on `get_authorize_client`
  (so the per-client signing key is available) and returns either the
  verified origin string, or `None` (meaning "use default brand").

```
async def get_verified_branding_origin(
    branding_origin: str | None = Query(None),
    client: Client = Depends(get_authorize_client),
) -> str | None:
    if branding_origin is None or client.branding_signing_key is None:
        return None
    ok = BrandingOriginVerifier(client).verify(branding_origin)
    return ok if ok is not None else None  # silent fallback
```

### 4.2 Persisting the verified origin across the redirect chain

The verified origin must survive the `auth:authorize` → `auth:login`
→ `auth:consent` → user form submissions chain. Two options:

**Option A (recommended): persist on `LoginSession`.**
- Add `branding_origin: Mapped[str | None]` column on `LoginSession`
  (`fief/models/login_session.py`).
- `AuthenticationFlow.create_login_session()` accepts `branding_origin`
  and stores it on the row.
- New brand resolver `get_current_brand_for_login(login_session, request,
  brand_repo)` consults `login_session.branding_origin` first, falling
  back to host-based lookup, then default.
- `get_base_context` gets a variant (`get_login_base_context`?) that
  threads the login session through. Where there is no login session
  (e.g. dashboard pages after authentication is complete), we keep the
  current host-based behaviour — those pages are reached on
  `account.<brand-host>.example` already, so host lookup is correct
  there.

**Option B: short-lived signed cookie.**
- Issue a `branding_origin` cookie at `/authorize` and read it in
  `get_current_brand`. Simpler, but cookies leak across tabs/sessions
  and don't co-locate with the `LoginSession` lifecycle. Rejected.

We recommend **Option A**; it co-locates branding state with the rest
of the in-flight authn state and is auto-cleaned on login-session
deletion.

### 4.3 HMAC verification — wiring the per-client signing key

**Schema change.** Add to `Client`:

```python
# fief/models/client.py
branding_signing_key: Mapped[str | None] = mapped_column(
    String(length=128), nullable=True, default=None
)
```

- 32-byte secret hex-encoded → 64 chars; `String(128)` leaves headroom
  for future key formats.
- **Optional** (nullable): existing clients (admin SDK, dashboard) don't
  use signed branding, so a null value means "branding-origin disabled
  for this client" → silently ignore any `branding_origin` query param.
- Generated by the **Saleor app** (T17 — `CreateConnectionUseCase`) when
  the operator provisions a per-install OIDC client; the app PUTs it on
  the Client at creation. Coordination point: T15 owns key generation
  and its shape; T46 owns key persistence.

**Verifier service.** Land a single module:
`fief/services/branding/origin_verifier.py` with:

```python
@dataclass
class VerifiedBrandingOrigin:
    origin: str  # the storefront origin we will brand for

class BrandingOriginVerifier:
    def __init__(self, client: Client) -> None:
        self._signing_key = client.branding_signing_key
        self._allowed_redirect_hosts = {
            urlparse(uri).hostname for uri in client.redirect_uris
        }

    def verify(self, token: str) -> str | None:
        # 1. parse "<origin>.<nonce>.<expiry>.<sig>"
        # 2. constant-time HMAC-SHA256(signing_key, "<origin>.<nonce>.<expiry>")
        # 3. expiry not in past (5-min window)
        # 4. origin host in allowlist (see 4.4)
        ...
```

Use `hmac.compare_digest()` for constant-time signature comparison
(matching `fief/services/webhooks/delivery.py`).

### 4.4 Allowlist enforcement on the Fief side

The Saleor app already enforces an allowlist (T15). We **must** also
enforce on the Fief side — the signing key alone tells you the **client**
that issued the token, but not whether the origin it names is one the
operator approved for that client.

**Recommended source of truth:** the Client's existing `redirect_uris`
list. The hostnames in `redirect_uris` are precisely the storefronts
this OIDC client is authorised to log into; if the signed origin's
host doesn't match any redirect-URI host, reject.

This avoids a second config surface and stays consistent with how
Fief already enforces redirect-URI safety
(`get_authorize_redirect_uri` in `fief/dependencies/auth.py:50`). If
ops wants to brand for a host that isn't a redirect URI (unlikely),
add a dedicated `branding_allowed_origins` JSON column later — design
for the common case first.

### 4.5 Failure mode

Per T46 spec: **silent fallback to default brand** for any of the
following:
- Missing signing key on the client.
- Missing or empty `branding_origin`.
- Malformed token.
- Bad signature.
- Expired token (older than 5 minutes).
- Origin not in allowlist.

Rationale: an attacker who can flip a brand to a different brand's UI
on a legitimate authorize URL has a phishing primitive (R5). Silently
falling back to the default brand denies them control without giving
them feedback they can iterate against. **Log** every failure path at
WARN with structured fields (`client_id`, `failure_reason`, hashed
origin) so ops sees abuse but the user just sees the default brand.

**Do not** raise `AuthorizeException` on a bad branding param — that
would block legitimate logins if the storefront's signer regresses.

### 4.6 Migration / schema change required

- New alembic revision: `add_branding_signing_key_to_clients`,
  down-revision `b400430e70fc` (current head — see
  `fief/alembic/versions/2026-05-09c_add_user_lockouts.py`).
- `op.add_column("fief_clients", sa.Column("branding_signing_key",
  sa.String(length=128), nullable=True))`.
- Optional second revision (Option A above) adds
  `branding_origin String(2048) NULL` to `fief_login_sessions`. (2048
  matches `redirect_uri` since they share a domain.)
- Both columns nullable / `server_default=None` so existing rows are
  fine — no data backfill needed.

### 4.7 Testing plan

Add `tests/services/test_branding_origin_verifier.py` covering the
verifier in isolation, plus integration coverage at the authorize
endpoint:

| Case | Expected |
|------|----------|
| Valid signed token, origin in redirect-uri allowlist, not expired | `verify()` returns the origin; `/authorize` persists it on `LoginSession`; subsequent `/login` renders the correct `Brand`. |
| Missing `branding_origin` query param | `verify()` returns `None`; default brand renders. |
| Token with a tampered origin segment | `verify()` returns `None`; default brand renders; WARN logged with `failure_reason="signature_mismatch"`. |
| Token with a tampered signature | Same as above. |
| Expired token (`expiry` 6 minutes in the past) | `verify()` returns `None`; default brand; `failure_reason="expired"`. |
| Unknown origin (HMAC valid but origin host not in client's `redirect_uris`) | `verify()` returns `None`; default brand; `failure_reason="origin_not_allowed"`. |
| Client with `branding_signing_key=None` and any token | `verify()` returns `None`; default brand. (Backward-compat path for non-Saleor clients.) |
| Cross-client replay (token signed by client A presented to client B) | `verify()` returns `None` because client B's key fails to match; `failure_reason="signature_mismatch"`. |

End-to-end: pair with **T42** (full SSO + bidirectional sync E2E, which
already declares `T46` as a dependency). Manual smoke: provision a
Saleor connection per T17 → click "log in" on the test storefront →
inspect rendered HTML and confirm brand-correct hero, logo, and title.

### 4.8 Touch-list (estimated, for the implementation task)

Files to **create**:
- `fief/services/branding/__init__.py`
- `fief/services/branding/origin_verifier.py`
- `fief/alembic/versions/<rev>_add_branding_signing_key_to_clients.py`
- `fief/alembic/versions/<rev>_add_branding_origin_to_login_sessions.py`
- `tests/services/test_branding_origin_verifier.py`
- `tests/test_apps_auth_authorize_branding_origin.py` (integration)

Files to **modify**:
- `fief/models/client.py` — add `branding_signing_key` column.
- `fief/models/login_session.py` — add `branding_origin` column.
- `fief/services/authentication_flow.py` — accept `branding_origin`
  in `create_login_session()`.
- `fief/dependencies/auth.py` — add `get_verified_branding_origin`
  dependency; thread it through `BaseContext` /
  `get_base_context` for in-flight login pages.
- `fief/dependencies/brand.py` — add a login-aware variant
  (`get_current_brand_for_login_session`) that prefers
  `login_session.branding_origin` over `request.url.hostname`.
- `fief/apps/auth/routers/auth.py` — read the dep on `/authorize` and
  pass through to `create_login_session`.

**Out of scope for this task** (T46): admin UI to set the
`branding_signing_key` from the Fief dashboard. The Saleor app sets it
at provisioning time (T17) via Fief's admin API; the manual UI can
land later if/when needed.

---

## 5. Open Questions for Product / Security

1. **Allowlist source.** Is reusing the Client's `redirect_uris`
   acceptable as the per-client allowlist (§4.4), or do we want a
   dedicated `branding_allowed_origins` JSON column? Reusing
   `redirect_uris` keeps the surface small but couples the two
   concepts; a dedicated list is more flexible if branding-only
   subdomains (e.g. a marketing landing page that isn't an OAuth
   client) ever need to brand the login UI.

2. **Key rotation.** Should `Client.branding_signing_key` support a
   two-key window (current + previous) for zero-downtime rotation,
   matching the dual-secret pattern T17 uses for `client_secret`?
   PRD §5.5 doesn't call this out explicitly; recommend yes for
   parity with R10 (secret-rotation risk).

3. **Logging.** Per T50 in the plan, the **Saleor-app** logger redacts
   the `branding_origin` signature segment. Should the Fief side adopt
   the same redaction for its own `failure_reason` logs (i.e. log a
   hash of the origin, not the origin itself)? Or is logging the full
   origin acceptable on the Fief side because we're inside the
   trust boundary?

4. **Fallback brand identity.** When verification fails and we render
   the default brand, should the URL the user sees in the browser
   change (e.g. strip the `branding_origin` param from the URL with
   a 302) so a refresh doesn't re-trigger the same WARN? Pure UX
   concern; the security posture is unchanged either way.

5. **5-minute window adequacy.** T15 commits to a 5-minute expiry to
   skip replay-cache infrastructure. If a user takes >5 minutes to
   complete a multi-step login (MFA prompt, email-verify, etc.), the
   brand still surfaces because we persist the verified origin on the
   `LoginSession` once at authorize time; the expiry only gates the
   token at the `/authorize` boundary. Confirm this is the intended
   semantics with the T15 author.

6. **Multiple clients on the same storefront.** If a single Saleor
   install ever provisions more than one OIDC client (today: one per
   install), do they all share the same signing key, or does each
   client get its own? Recommend per-client (one-to-one with the
   `clients` row) to keep blast-radius small on key compromise.

---

## 6. Cross-Task Dependencies — Surface to User

T46 is a **leaf** dependency for two downstream tasks:

- **T19 — `AUTH_ISSUE_ACCESS_TOKENS` handler + first-login provisioning**
  (`saleor-apps/apps/fief/...`). T19's `depends_on` includes T15; the
  full SSO loop is only correct end-to-end once Fief honours the signed
  param (T46). T19 can be implemented before T46 lands, but the
  storefront will render the default Fief brand until then.
- **T42 — E2E test (full SSO + bidirectional sync round trip).** T42
  explicitly declares T46 in its `depends_on`. The E2E **cannot pass**
  the "branding renders correctly" assertion without T46 implementation
  shipped to opensensor-fief.

Implication: this audit is **not** sufficient on its own — a follow-up
implementation task must run before the Saleor app's branding flow can
ship to production and before T42 turns green.

---

## 7. Summary

- **Branding-by-domain exists today** in opensensor-fief: full `Brand`
  model, `BrandRepository.get_by_host`, host-based dependency
  `get_current_brand`, brand-aware Jinja templates, brand-tagged
  transactional emails. Multi-brand whitelabel works for native Fief
  storefronts.
- **Signed-origin support does not exist.** No code reads
  `branding_origin`; brand is keyed on `request.url.hostname`, which
  is always Fief's host for Saleor-driven logins. Eight gaps
  (G1–G8) enumerated.
- **Proposal** (§4): add `Client.branding_signing_key` column, add
  `LoginSession.branding_origin` column, add a verifier service in
  `fief/services/branding/`, add an `/authorize` dependency that does
  HMAC + 5-min-expiry + allowlist check, fall back silently on
  failure, and persist the verified origin on the login session so it
  survives the redirect chain into login/consent/MFA pages. Two
  alembic migrations. Eight pytest cases covering valid /
  unsigned / tampered / expired / unknown-origin / cross-client-replay
  / null-key / no-token paths.
- **Open questions** (§5) exist around allowlist source, key
  rotation, logging redaction, fallback UX, and multi-client
  semantics — flagged for product/security review before
  implementation begins.
