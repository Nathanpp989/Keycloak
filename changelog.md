# Changelog

All notable changes to the Auth Broker are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and the
project aims to follow [Semantic Versioning](https://semver.org/). Dates are
release dates; entries within a version are grouped by kind.

## [1.0.0] - 2026-09-24

First consolidated release. The broker authenticates users through Keycloak with
Auth0 federation, provides a full token/authorization API, machine-to-machine
access control, a Traefik ForwardAuth gateway, OpenBao-backed secrets, and a
monitoring stack. 728 tests; CI runs the unit suite plus a live smoke test.

### Added — token & authorization API
- `POST /token` — password-grant login. Now also returns `refresh_token` and
  `expires_in` when Keycloak provides them.
- `POST /token/refresh` — exchange a refresh token for a fresh access token.
- `POST /token/client` — client-credentials (M2M) tokens.
- `POST /token/introspect` — RFC 7662-style introspection; returns only
  allow-listed, non-sensitive claims.
- `POST /token/revoke` — revoke a refresh token (logout); idempotent.
- `GET /userinfo` — OIDC UserInfo (the authenticated user's profile claims).
- `GET /protected/audience` — audience-guarded resource using `require_audience`.
- Role, scope, and audience guards (`require_role`, `require_scope`,
  `require_audience`) for endpoint authorization.
- Multi-tenant model: role-based authz, tenant/org scoping, org isolation, an
  optional superadmin bypass.

### Added — API-key authentication
- `ak_<id>_<secret>` keys for simple service clients; only the SHA-256 hash is
  stored, plaintext is shown once, verification is constant-time with O(1)
  lookup.
- Admin endpoints: `POST/GET /admin/api-keys`, `DELETE /admin/api-keys/{id}`;
  a `require_api_key` dependency and a `/protected/apikey` demo route.
- Pluggable storage: in-process by default, or persisted in OpenBao KV v2 with
  `API_KEY_BACKEND=openbao` (survives restarts, shared across replicas).
- Traefik ForwardAuth accepts `X-API-Key` as an alternative to a Bearer token.

### Added — account protection
- Per-user failed-login tracking with temporary lockout (`account_lockout.py`),
  defeating distributed brute-force that dodges per-IP rate limits. Tunable via
  `LOCKOUT_MAX_FAILURES` / `LOCKOUT_WINDOW_SECONDS`; disable with
  `LOCKOUT_ENABLED=false`. A Keycloak outage does not count as a failed login.
- Rate limiting: separate limiters for login, registration, M2M, and
  token-validation operations, each independently tunable; optional Redis
  backend for shared limits across replicas.

### Added — secrets, PKI & auto-unseal (OpenBao)
- Secrets resolved from Azure Key Vault and OpenBao, with AppRole login
  (least-privilege, token caching) so the app needs no root token.
- OpenBao as an internal certificate authority: root CA, issuing role, safe
  certificate rotation (issue-before-overwrite), Traefik TLS wiring.
- Persistent OpenBao: file storage with auto-unseal on boot; init reused across
  restarts (same CA).
- Production auto-unseal support (`BAO_AUTO_UNSEAL`): seal-backed init with
  recovery keys, no persisted unseal key. Verified end to end locally with a
  transit seal; an Azure Key Vault seal template is provided (needs a real Vault
  to run). Also `BAO_UNSEAL_KEY` for an externally-provided unseal key.

### Added — edge, gateway & web-API
- Traefik ForwardAuth gateway (`/auth/forward`): fail-closed Bearer/API-key
  validation, sanitized `X-Auth-*` identity headers for upstreams.
- `.test.local` / `.localhost` routing with browser-trusted TLS from the
  internal CA.
- Configurable CORS (`CORS_ALLOW_ORIGINS`), off by default.
- OpenAPI metadata (title/description/version) with docs gated by
  `DOCS_ENABLED`; GZip compression for large responses.
- Security response headers; per-request `X-Request-ID` correlation.

### Added — observability
- Prometheus metrics: request counts/latency, token issuance, ForwardAuth
  decisions, token-validation ops (`auth_token_ops_total`), upstream Keycloak
  latency (`auth_upstream_op_duration_seconds`), account lockouts
  (`auth_account_lockouts_total`).
- Alert rules: service down, high token-error / forward-deny / 5xx / latency
  rates, plus `HighAccountLockoutRate`, `HighUpstreamAuthLatency`,
  `HighTokenOpErrorRate`. Grafana + Alertmanager wired.
- Structured audit log (`audit` logger): token issued/denied/refreshed/revoked,
  introspect, userinfo, ForwardAuth allow/deny with reason, API-key
  create/revoke — never logging token values or secrets.
- Structured access log (`access` logger): method, path, status, latency,
  request id per request.

### Added — tooling
- `bootstrap.sh` — one-command full-stack bring-up: cert issuance, optional
  `--provision`, and a `.env` preflight.
- `provision.sh` — idempotent OpenBao AppRole + KV provisioning, writing creds
  to `.env`.
- `doctor.sh` — one-shot stack health check (Docker, containers, OpenBao seal
  state, app health, Keycloak/Auth0 discovery, cert, `.env`).
- `check-env.sh` — validate `.env` (catches wrapped secrets, placeholders,
  empty required values).
- `verify-sync.sh` — flag broker files that have drifted from a committed
  manifest.
- `stack-up.sh` / `free-port.sh` — clear port conflicts (stray containers and
  host processes) and bring the stack up.
- CI: unit suite across Python versions plus a live smoke-test job (Keycloak +
  app + the 9-check curl suite).

### Changed
- Runs on the latest Python (3.14); container base image and CI updated. The suite passes on Python 3.12, 3.13, and 3.14 (all 728 tests). Pinned dependencies verified to install and work on 3.14.
- Dependencies pinned to exact tested versions (`==`) for reproducible builds.
- `/token/introspect`, `/token/revoke`, and `/userinfo` use a dedicated,
  more-generous token-ops rate limiter instead of the strict login limiter, so
  heavy token validation cannot exhaust the login budget.
- Traefik gates routing to the app on a loadbalancer health check, closing the
  startup 404 window without coupling Traefik's own startup to the app.

### Fixed
- `cmd_approle` passed an invalid keyword to `configure_approle`; provisioning
  crashed. Fixed with a regression test.
- `configure_approle` did not enable the KV engine it grants access to, so a
  persistent OpenBao 404'd on secret reads. Now enables KV v2 idempotently.
- OpenBao PKI: idempotency bug that silently minted a new CA on re-run;
  `allow_bare_domains` missing so bare SANs were rejected.
- `/register` (public, unauthenticated) leaked raw upstream exception detail on
  502; now logs server-side and returns a generic message.
- Order-dependent test flake: the shared rate limiter leaked state across tests,
  causing intermittent 429s. Fixed with an autouse reset fixture.
- `check-env.sh` false-positive that flagged legitimate secrets containing
  "PASTE"/"REPLACE" substrings.
- Entrypoint: `set -e` killed the boot on an intentional non-zero `bao status`;
  multi-line unseal-key extraction; scheme-less `OPENBAO_ADDR` now errors
  clearly.

### Security
- Authentication fails closed everywhere: the ForwardAuth gateway and protected
  routes deny on any error; unhandled exceptions surface as non-2xx (deny).
- Rate limiting does not trust `X-Forwarded-For` unless
  `RATE_LIMIT_TRUST_PROXY=true`; the rate limiter is thread-safe under
  contention (verified: exactly N allowed).
- Edge input validation on `/register`; control characters stripped from
  ForwardAuth identity headers.
- No token values, passwords, or secrets are written to logs (audit or access).
- API keys and OpenBao unseal keys: hashes/recovery-only storage; production
  hardening checklist documented (KMS auto-unseal, finite AppRole secret_id TTL,
  raft storage, org-signed CA).

### Known limitations
- Account-lockout state and (by default) API keys and registered users are
  in-process; for multi-replica use OpenBao (API keys) or Redis (lockout,
  rate limits). Documented in the README production section.
- Azure Key Vault auto-unseal is scaffolded and the seal plugin is confirmed
  present, but running it requires a real Vault; the mechanism is proven locally
  via a transit seal.
- Keycloak-OIDC login to OpenBao's own UI is configured correctly server-side; a
  browser-side issue remains unresolved.

[1.0.0]: https://github.com/Nathanpp989/Keycloak/releases/tag/v1.0.0
