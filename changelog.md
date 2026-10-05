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
- Auth0 org-sync: `POST /admin/org-sync` mirrors Auth0 Organizations into Keycloak groups (one-way, adopt-and-link; `auth0_org_sync.py`). `test-org-sync.sh` proves it end to end against a real tenant. Needs the M2M app scoped for `read:organizations` (and `create:organizations` for the live test).
- `POST /admin/org-sync/members` adds Auth0 org members to their Keycloak group (matched by email). Add-only by default; `remove_absent=true` reconciles (removes members no longer in the Auth0 org — opt-in, revokes access). `test-org-membership.sh` proves it end to end. Needs `read:organization_members` (+ user scopes for the test).
- `GET /admin/users/{id}/sessions` and `POST /admin/users/{id}/logout` — list a user's active Keycloak sessions and force-logout (revoke all sessions) for compromise/offboarding response (admin only).
- `POST /token/exchange` — RFC 8693 token exchange (delegation to a target audience; needs Keycloak token-exchange enabled).
- `/token/introspect` now surfaces `amr`/`acr` (MFA/auth-level) claims.
- OpenBao `get_secret_wrapped()` — response-wrapped secret delivery (a single-use unwrap token instead of the plaintext value).
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
- Azure Key Vault auto-unseal scaffolding: `openbao/config.azure.hcl.example` (env-driven seal), `compose.azure-kms.yaml` overlay, and `check-azure-kms.sh` preflight (verifies the Vault/key before boot). Mechanism proven via the transit seal; the Azure path is verify-on-your-Key-Vault.
- Dynamic database secrets: `openbao_dynamic_secrets.py` (engine API), `compose.postgres.yaml` (opt-in Postgres), `provision_dynamic_secrets.py` (wires OpenBao->Postgres), and `test-dynamic-secrets.sh` (end-to-end lease lifecycle proof on a real stack).
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
- mTLS (activatable): `traefik/dynamic/mtls.yml` serves a separate `mtls.test.local` host requiring client certs; `enable-mtls.sh` reissues the server cert to cover it + issues a client cert; `test-mtls.sh` proves the handshake. Separate host avoids Traefik's per-SNI tls.options limit. Original scaffolding: `issue_client_cert()` + `--client-cert` issue a client cert from the internal CA; `traefik/dynamic/mtls.yml.example` requires client certs on a route; `test-mtls.sh` proves the handshake (rejected without a cert, accepted with) on a real stack.
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
  (`auth_account_lockouts_total`), API-key auth (`auth_api_key_total`).
- Alert rules: service down, high token-error / forward-deny / 5xx / latency
  rates, plus `HighAccountLockoutRate`, `HighUpstreamAuthLatency`,
  `HighTokenOpErrorRate`. Grafana + Alertmanager wired.
- Structured audit log (`audit` logger): token issued/denied/refreshed/revoked,
  introspect, userinfo, ForwardAuth allow/deny with reason, API-key
  create/revoke — never logging token values or secrets.
- Structured access log (`access` logger): method, path, status, latency,
  request id per request.

### Added — tooling
- Kubernetes manifests (`k8s/`): schema-validated Deployment/Service/Ingress/ConfigMap/Secret + kustomization for the broker app (non-root, health probes, readonly rootfs). Dependencies (Keycloak/OpenBao/Postgres) use upstream charts/managed services. Verify-on-cluster.
- MCP server (`mcp_server.py`, optional — own deps in requirements-mcp.txt): exposes safe operational tools (health, token introspection, API-key management, user sessions, org-sync) to an AI assistant via the Model Context Protocol. Does NOT expose password-grant login. `mcp-config.example.json` shows how to register it.
- `live-test.sh` — one command runs every live proof against the running stack (health -> smoke -> dynamic secrets -> mTLS) and prints a pass/fail summary. `disable-mtls.sh` deactivates the opt-in mTLS route.
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
- CI hardened: a `lint-scripts` job runs shellcheck on all `*.sh` (catches quoting / SC2015 / unquoted-expansion bugs the Python suite can't), and a `validate-k8s` job schema-checks the k8s manifests. Both pass on the current tree.
- Certificate process: `openbao_traefik_cert.py --check` reports cert expiry (read-only, no OpenBao); `doctor.sh` warns when the Traefik cert is expiring; the PKI role's key algorithm is configurable (OPENBAO_CERT_KEY_TYPE/BITS — RSA-2048 default, ECDSA opt-in).
- Runs on the latest Python (3.14); container base image and CI updated. The suite passes on Python 3.12, 3.13, and 3.14 (all 728 tests). Pinned dependencies verified to install and work on 3.14.
- Dependencies pinned to exact tested versions (`==`) for reproducible builds.
- `/token/introspect`, `/token/revoke`, and `/userinfo` use a dedicated,
  more-generous token-ops rate limiter instead of the strict login limiter, so
  heavy token validation cannot exhaust the login budget.
- Traefik gates routing to the app on a loadbalancer health check, closing the
  startup 404 window without coupling Traefik's own startup to the app.

### Fixed
- Coverage-driven test pass: added 12 tests for previously-untested edge cases and error paths — nameless orgs / emailless members skipped, member pagination, non-numeric lockout env fallback, disabled-lockout no-op, sliding-window prune, Redis-backend selection + fallback, OpenBao api-key store graceful degradation, dynamic-secrets enable error. All passed (the paths were correct but unverified); coverage of the core modules now ~93%.
- Test coverage: `test_api_keys.py`, `test_account_lockout.py`, and `test_openbao_traefik_cert.py` were missing from pytest.ini's `python_files` allow-list, so ~28 tests never ran in the full suite / CI. Now collected (suite: 731 -> 759).
- Auth0: the API audience is cached instead of fetched from the secret store on every token verification (was a network round-trip per request).
- OpenBao/Traefik: TLS cert/key files are written atomically (temp + rename), so Traefik can't hot-reload a half-written cert during rotation.
- Missing/blank bearer credentials now return 401 (was 403): a consistent authentication failure. `container_check.py` no longer leaks file handles (uses `Path.read_text()`); stdlib detection works on older interpreters too.
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
