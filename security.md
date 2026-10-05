# Security posture

How the auth broker defends itself and what it assumes. Every control below maps
to actual code; the "Production hardening" and "Out of scope" sections are the
honest limits — read them before deploying.

## What this is

A broker that authenticates users through **Keycloak** (with **Auth0**
federation), issues and validates tokens, gates resources by role/scope/audience,
and acts as a **Traefik ForwardAuth** gateway. Secrets come from **Azure Key
Vault** / **OpenBao**; TLS from an internal **OpenBao PKI**.

## Trust boundaries

- **Untrusted:** end users and their tokens, inbound HTTP, anything crossing the
  edge (Traefik). All of it is validated before it reaches a protected route.
- **Semi-trusted:** the internal network between broker, Keycloak, OpenBao,
  Postgres. Harden with mTLS (`traefik/dynamic/mtls.yml.example`) where it may be
  observed.
- **Trusted:** the secret stores (Key Vault / OpenBao) and the Keycloak realm
  config. Compromise of these compromises the system — they get least-privilege
  access and auditing, not blind trust.

## Threat model — what it defends against

| Threat | Control (in code) |
|---|---|
| Forged / tampered / expired tokens | Keycloak introspection + Auth0 JWKS RS256 verification; fails closed |
| Credential stuffing / brute force (per IP) | Per-route rate limiting (`rate_limit.py`) |
| Distributed brute force against one account | Per-user lockout (`account_lockout.py`) |
| Privilege escalation / cross-tenant access | Role/scope/audience guards + tenant scoping (`require_role/scope/audience`) |
| Token replay beyond scope | Audience enforcement; scope checks; introspection (not blind trust) |
| API-key theft | SHA-256 hashed storage (plaintext shown once), constant-time compare, optional expiry + scopes |
| Secret leakage at rest / in config | Secrets in Key Vault/OpenBao, not in images or Git; AppRole (not root) |
| Secret leakage in transit (internal) | OpenBao response-wrapping; mTLS option on the edge |
| Header spoofing via ForwardAuth | Inbound `X-Auth-*` ignored; identity headers sanitized (control chars stripped) |
| Information disclosure via errors | Public endpoints return generic errors; details logged server-side only |

## Defense in depth (verified against the implementation)

- **Fail closed, everywhere.** The ForwardAuth gateway and protected routes deny
  on any error; unhandled exceptions surface as non-2xx. (~50 explicit 401/403/503
  denials in `main.py`.)
- **Authentication.** Keycloak token introspection (RFC 7662) and Auth0 RS256 via
  cached JWKS with key-rotation handling. Missing/blank bearer → 401 (not 403).
- **Authorization.** `require_role`, `require_scope`, `require_audience`, plus
  multi-tenant org scoping with an optional superadmin bypass (~38 guard sites).
- **Rate limiting + lockout.** Separate limiters for login / registration / M2M /
  token-validation; per-user lockout for distributed brute force. Both have
  optional shared (Redis) backends for multi-replica correctness.
- **Least privilege to secrets.** OpenBao access via **AppRole** (not a root
  token), KV-read-only policy, token caching; PKI issuance constrained by role.
- **API keys.** `ak_<id>_<secret>`, only the SHA-256 hash stored, constant-time
  (`hmac.compare_digest`) verification, optional TTL and scopes.
- **Edge hygiene.** Input validation on `/register`; ForwardAuth strips control
  characters from identity headers and never trusts inbound `X-Auth-*`; rate
  limiter trusts `X-Forwarded-For` only when `RATE_LIMIT_TRUST_PROXY=true`.
- **TLS.** Browser-trusted certs from the internal CA; optional **mutual TLS** on
  a dedicated host; safe cert rotation (issue-and-validate before overwrite,
  atomic file writes).
- **Auditing.** Structured audit log (token issued/denied/refreshed/revoked,
  introspect, userinfo, ForwardAuth allow/deny with reason, API-key and org-sync
  events) and per-request access log.

## Logging and secrets

Audit and access logs are built from **allow-listed fields** and never include
token values, passwords, or API-key secrets. Note: this is by *design*, not by an
automatic redaction filter — code that logs a raw credential would not be caught
automatically, so keep that discipline in new log lines. Introspection responses
return only allow-listed, non-sensitive claims.

## Production hardening (do these before relying on it)

The dev/compose defaults are convenient, not production-safe:

- **Replace all dev defaults** — `change-me*` passwords, `admin/admin`, any
  `REPLACE_*`. `check-env.sh` flags wrapped/placeholder values.
- **OpenBao:** move off dev file-storage + Shamir unseal to **raft + KMS
  auto-unseal** (`openbao/config.azure.hcl.example`, `check-azure-kms.sh`); give
  the AppRole `secret_id` a finite TTL; use an org-signed or offline-rooted CA.
- **TLS:** some internal listeners use `tls_disable = true` for dev — terminate
  real TLS at the edge/proxy, and enable mTLS on sensitive internal hops.
- **Shared state:** for multi-replica, set `RATE_LIMIT_BACKEND=redis`,
  `LOCKOUT_BACKEND=redis`, `API_KEY_BACKEND=openbao` (otherwise limits/lockout are
  per-replica and API keys don't persist).
- **Docs surface:** set `DOCS_ENABLED=false` in production.
- **Account lockout is a DoS trade-off:** per-username lockout lets an attacker
  lock a victim out. Defaults are lenient (5 / 15 min); tune or disable per your
  risk.

## Out of scope / known limitations

- Not a WAF or DDoS mitigation — put one in front at the edge.
- No automatic log redaction (see above).
- `get_group_members` pagination: membership sync may re-issue idempotent adds for
  groups with >~100 members (state stays correct; the summary may over-count).
- The Keycloak realm config, Auth0 tenant config, and the secret stores are
  trusted inputs — securing *them* is the operator's responsibility.

## Reporting

Report suspected vulnerabilities privately to the repository owner; do not open a
public issue with exploit details.
