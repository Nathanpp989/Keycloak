# Configuration Reference

Every environment variable the Auth Broker reads, grouped by subsystem, with
defaults. Unset variables use the default shown. Booleans accept
`1/true/yes/on` (case-insensitive); anything else is false.

For the HTTP API surface, see the interactive docs at `/docs` (or `/openapi.json`)
when `DOCS_ENABLED=true`.

## Server / app

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in a container). |
| `PORT` | `8000` | Listen port. |
| `APP_VERSION` | `1.0.0` | Version shown in the OpenAPI schema. |
| `APP_URL` | `http://localhost:8000` | Public base URL of the app. |
| `APP_REDIRECT_URI` | `http://localhost:8000/callback` | OIDC redirect URI. |
| `DOCS_ENABLED` | `true` | Serve `/docs`, `/redoc`, `/openapi.json`. Set `false` in prod to hide the API surface. |
| `LOG_LEVEL` | `INFO` | Log level. |
| `LOG_FORMAT` | `json` | `json` (structured) or plain. |

## Keycloak

| Variable | Default | Purpose |
|---|---|---|
| `KEYCLOAK_URL` | `http://localhost:8080` | Keycloak base URL (must be reachable from the app). |
| `KEYCLOAK_REALM` | `Premkey` | Application realm. |
| `KEYCLOAK_CLIENT_ID` | `Hello-World-app` | The app's Keycloak client. |
| `KEYCLOAK_CLIENT_SECRET` | _(fetched/empty)_ | Confidential-client secret; usually resolved at startup. |
| `KEYCLOAK_ADMIN_USER` | `admin` | Admin user for provisioning. |
| `KEYCLOAK_ADMIN_PASSWORD` | `admin` | Admin password. |
| `KEYCLOAK_ADMIN_REALM` | `master` | Realm the admin authenticates against. |
| `KEYCLOAK_REQUIRED` | `true` | If `false`, the app starts in a degraded mode when Keycloak is unreachable. |
| `KEYCLOAK_STARTUP_RETRIES` | `10` | Provisioning retry attempts on boot. |
| `KEYCLOAK_STARTUP_BACKOFF` | `2.0` | Backoff (seconds) between retries. |
| `ADMIN_ROLE` | `tenant-admin` | Role required for admin endpoints. |
| `SUPERADMIN_ROLE` | _(empty)_ | Optional role that bypasses tenant scoping. |
| `SERVICE_ACCOUNT_ROLE` | _(empty)_ | Role granted to the app's service account for M2M. |
| `SERVICE_ACCOUNT_AUDIENCE` | _(empty)_ | Audience minted into M2M tokens. |
| `APP_AUDIENCE` | _(empty)_ | Audience required by `/protected/audience` (falls back to the service audience). |

## Auth0 (federation + M2M management)

| Variable | Default | Purpose |
|---|---|---|
| `AUTH0_DOMAIN` | _(required)_ | Auth0 tenant domain. |
| `AUTH0_CLIENT_ID` | _(required)_ | M2M application client id. |
| `AUTH0_CLIENT_SECRET` | _(required)_ | M2M application secret (one line — see `check-env.sh`). |
| `AUTH0_AUDIENCE` | _(empty)_ | API audience for M2M tokens. |
| `AUTH0_MANAGEMENT_MODE` | `auto` | `auto`/`off` — disables Management API endpoints when off/unreachable. |

## OpenBao — secrets, AppRole, PKI

| Variable | Default | Purpose |
|---|---|---|
| `OPENBAO_ADDR` | `http://127.0.0.1:8200` | OpenBao API address (needs the `http(s)://` scheme). |
| `OPENBAO_TOKEN` | _(empty)_ | Static token; if empty, AppRole login is used. |
| `OPENBAO_ROLE_ID` / `OPENBAO_SECRET_ID` | _(empty)_ | AppRole credentials (least-privilege). |
| `OPENBAO_SECRETS` | _(empty)_ | Comma-separated names to read from OpenBao first (else Key Vault). `*` = all. |
| `OPENBAO_KV_MOUNT` | `secret` | KV v2 mount. |
| `OPENBAO_APPROLE_MOUNT` | `approle` | AppRole auth mount. |
| `OPENBAO_PKI_MOUNT` | `pki` | PKI mount (internal CA). |
| `OPENBAO_SECRET_ID_TTL` | `0` | AppRole secret_id TTL (`0` = never; set finite in prod). |
| `OPENBAO_SECRET_ID_NUM_USES` | `0` | AppRole secret_id use count (`0` = unlimited). |
| `OPENBAO_KEYCLOAK_MOUNT` | `oidc` | Mount for OpenBao's own Keycloak-OIDC login. |
| `OPENBAO_KC_CLIENT_ID` | `openbao` | Keycloak client OpenBao logs in as (for OIDC login). |
| `OPENBAO_KC_CLIENT_SECRET` | _(empty)_ | That client's secret. |
| `KEY_VAULT_URL` | _(empty)_ | Azure Key Vault URL (secrets fallback). |

### OpenBao auto-unseal (entrypoint)

| Variable | Default | Purpose |
|---|---|---|
| `BAO_AUTO_UNSEAL` | `0` | `1` = seal-backed auto-unseal (KMS/transit); init with recovery keys, no persisted unseal key. |
| `BAO_UNSEAL_KEY` | _(empty)_ | Unseal from this key (e.g. a Docker secret) instead of the volume file. |

## Rate limiting

| Variable | Default | Purpose |
|---|---|---|
| `RATE_LIMIT_BACKEND` | `memory` | `memory` or `redis` (shared across replicas). |
| `RATE_LIMIT_LOGIN_MAX` / `_WINDOW` | `10` / `60.0` | `/token` password-grant limit per IP. |
| `RATE_LIMIT_REGISTER_MAX` / `_WINDOW` | `5` / `60.0` | `/register` limit per IP. |
| `RATE_LIMIT_TOKENOPS_MAX` / `_WINDOW` | `120` / `60.0` | introspect/userinfo/revoke limit (separate from login). |
| `RATE_LIMIT_TRUST_PROXY` | _(false)_ | Trust `X-Forwarded-For` for the client key (only behind a trusted proxy). |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis for the shared backends. |

## Account lockout (per-user brute-force)

| Variable | Default | Purpose |
|---|---|---|
| `LOCKOUT_ENABLED` | `true` | Enable per-user failed-login lockout. |
| `LOCKOUT_MAX_FAILURES` | `5` | Failures within the window before lockout. |
| `LOCKOUT_WINDOW_SECONDS` | `900.0` | Sliding window (15 min). |
| `LOCKOUT_BACKEND` | `memory` | `memory` or `redis` (shared across replicas). |

## API keys

| Variable | Default | Purpose |
|---|---|---|
| `API_KEY_BACKEND` | `memory` | `memory` or `openbao` (persist keys in KV v2, shared across replicas). |

Keys are created via `POST /admin/api-keys` with optional `ttl_seconds` (expiry)
and `scopes` (comma-separated). Enforced by `require_api_key` /
`require_api_key_scope`, and usable through the Traefik ForwardAuth gateway via
the `X-API-Key` header.

## CORS

| Variable | Default | Purpose |
|---|---|---|
| `CORS_ALLOW_ORIGINS` | _(empty)_ | Comma-separated origins; empty = CORS off (server-side default). |
| `CORS_ALLOW_CREDENTIALS` | `false` | Allow credentials (never combined with a wildcard origin). |

## Security / TLS

| Variable | Default | Purpose |
|---|---|---|
| `SECURITY_HSTS` | _(empty)_ | Set to enable the HSTS response header (only when served over real HTTPS). |

## Passwords (dev/provisioning)

`DEFAULT_USER_PASSWORD`, `ADMIN_USER_PASSWORD`, `ADMIN_USERNAME`,
`NEW_USER_EMAIL` seed dev users during provisioning. Change or remove for
production — do not ship the defaults.

## Test / integration only

`DOTENV_PATH`, `LOGIN_FLOW_CATCH`, `INTEGRATION_*`, `SMOKE_*`, `KC_USER`,
`KC_PASS`, `GITHUB_TOKEN` are used only by test/diagnostic scripts, not the app
at runtime.
