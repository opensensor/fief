# Fief maintenance follow-ups

- [ ] Add explicit product attribution to authentication history. Fief already
  records user-to-client grants and session timestamps, but token audit events
  omit the client ID. Include the client ID in those events and define a stable
  mapping from clients to products. The portal must distinguish a new login,
  token refresh, and actual product activity; a grant or token issuance alone
  must not be presented as evidence that someone used a product. Add coverage
  for attribution and event classification before exposing this history.

- [ ] Maintain or replace `fief-client` so HTTPX can move beyond 0.27.2. Its
  current release requires HTTPX below 0.28; validate admin OAuth callbacks,
  token validation, and refresh behavior before changing that constraint.
- [ ] Revisit Python 3.15 when `zxcvbn-rs-py` publishes compatible wheels or
  updates its PyO3 dependency. Keep the supported range explicit until then.
- [ ] Track the remaining Debian image advisories and rebuild as fixes land.
  CI reports all findings and rejects fixable high/critical vulnerabilities.
- [ ] Address the existing Ruff backlog and enable repository-wide lint gating.
