# Keycloak + Auth0 + Azure Key Vault Integration

A FastAPI application that brokers user authentication through Keycloak, with
Auth0 wired in as an upstream OIDC identity provider (so users can log in via
Auth0 and its social connections), and Azure Key Vault holding the Auth0
credentials. Includes user-management tooling, secret rotation, and a full
mocked test suite.

## How the pieces fit together

```
                         ┌─────────────────────────────┐
   Browser / API  ─────► │        FastAPI (main.py)     │
                         │  /token /protected /register │
                         │  /users/lookup /oidc-token   │
                         └──────────────┬──────────────┘
                                        │
              ┌─────────────────────────┼──────────────────────────┐
              ▼                         ▼                           ▼
       ┌────────────┐          ┌────────────────┐          ┌────────────────┐
       │  Keycloak  │ ◄──IdP── │     Auth0      │          │ Azure Key Vault │
       │  (realm)   │  broker  │ (social, M2M)  │ ◄─secrets─│ (Auth0 creds)  │
       └────────────┘          └────────────────┘          └────────────────┘
```

- **Keycloak** authenticates users and manages the realm. It is configured with
  Auth0 as a brokered OIDC identity provider.
- **Auth0** provides social/enterprise login (Google, Facebook, …) and a
  machine-to-machine API used for user management.
- **Azure Key Vault** stores the Auth0 client credentials so they never live in
  application config.

## Files

| File | Role |
|------|------|
| `main.py` | The FastAPI app. Endpoints for login, protected resources, registration, and user lookup. Run this to serve the API. |
| `authorize.py` | Auth helpers + the `/secure-data` router. Local token verification, Key Vault access, Auth0 M2M token caching, and Auth0 RS256 (JWKS) verification. |
| `auth0_connect.py` | One-time **setup tooling**. Registers Auth0 social connections, creates an OIDC client, generates a dev TLS cert, and registers Auth0 as an IdP in Keycloak. Also defines `Auth0Connect`, `get_keycloak_admin_token`, and `rotate_client_secret`. |
| `auth0_talk.py` | API clients for user management: `KeycloakAdminAPI` and `Auth0UsersAPI`. |
| `auth0_type.py` | `UserManager`: detect which system a user belongs to and create users in both Keycloak and Auth0. |
| `rotate_secret.py` | Rotate the Auth0 client secret and sync it into the Keycloak IdP (and `.env`). |
| `login_flow.py` | Build the Keycloak→Auth0 brokered login URL; prints a manual browser-test checklist. |
| `auth0_test.py`, `test_main.py`, `test_rotate.py` | Test suites (all HTTP mocked). |

## Setup

1. **Create a virtual environment and install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate          # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Create a `.env` file** in the directory you run scripts from:
   ```
   AUTH0_DOMAIN=your-tenant.us.auth0.com
   AUTH0_CLIENT_ID=your-m2m-client-id
   AUTH0_CLIENT_SECRET=your-m2m-client-secret
   AUTH0_AUDIENCE=https://your-tenant.us.auth0.com/api/v2/
   KEYCLOAK_URL=http://localhost:8080
   KEYCLOAK_ADMIN_USER=admin
   KEYCLOAK_ADMIN_PASSWORD=admin
   KEYCLOAK_REALM=Premkey
   KEY_VAULT_URL=https://your-keyvault.vault.azure.net/
   ```
   Keep `.env` out of version control (add it to `.gitignore`).

3. **Grant the Auth0 M2M application these Management API scopes**
   (Auth0 Dashboard → Applications → APIs → Auth0 Management API →
   Machine to Machine Applications → your app):
   ```
   read:connections   create:connections
   read:clients       create:clients
   read:users         create:users   update:users   delete:users
   read:roles         (for membership/role lookup)
   create:user_tickets  delete:sessions  delete:grants   (account lifecycle)
   update:client_keys   (for secret rotation)
   ```

   For Auth0 **group** membership, the tenant must have the Authorization
   Extension installed; set its API URL via `AUTH0_AUTHZ_EXTENSION_URL`
   (e.g. `https://<tenant>.<region>.webtask.io/<id>/api`). Without it, group
   lookup is skipped and only Auth0 roles are reported.

4. **Start Keycloak** (from your Keycloak distribution directory):
   ```bash
   ./bin/kc.sh start-dev
   ```
   Make sure the realm named in `KEYCLOAK_REALM` exists.

## Usage

Always run with the venv active (or use `./venv/bin/python <script>`).

**One-time integration setup** — registers Auth0 connections, the OIDC client,
and the Keycloak IdP:
```bash
python auth0_connect.py
```

**Run the API server:**
```bash
python main.py        # serves on http://0.0.0.0:8000
```

**Register a user in both Keycloak and Auth0:**
```bash
curl -X POST http://localhost:8000/register \
  -d "email=jane@example.com" -d "password=ChangeMe123!"
```

**Look up where a user exists** (requires a valid Keycloak bearer token):
```bash
curl "http://localhost:8000/users/lookup?username=jane-ab12cd&email=jane@example.com" \
  -H "Authorization: Bearer <keycloak-token>"
```

**Test the real browser login flow** (manual — prints a URL and checklist):
```bash
python login_flow.py
```

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | none | Health/hello |
| GET | `/hello` | none | Echoes email + username |
| POST | `/token` | none | Log in via Keycloak; returns an access token |
| GET | `/protected` | Bearer | Example protected resource |
| POST | `/oidc-token` | Bearer | Validate a token via Keycloak introspection |
| POST | `/register` | none | Create a user in Keycloak + Auth0 |
| GET | `/users/lookup` | Bearer | Which system(s) a user belongs to |
| GET | `/users/membership` | Bearer | A user's groups + roles in both systems, correlated |
| POST | `/groups` | Bearer | Create a group/subgroup in Keycloak (+ Auth0 if configured) |
| POST | `/users/groups` | Bearer | Add or revoke a user's group membership (`action=add\|revoke`) |
| POST | `/users/roles` | Bearer | Assign or revoke a user's role in both systems (`action=assign\|revoke`) |
| PATCH | `/groups` | Bearer | Rename a group across systems |
| DELETE | `/groups` | Bearer | Delete a group across systems |
| POST | `/organizations` | Bearer | Create (or reuse) an Auth0 organization |
| GET | `/organizations` | Bearer | List Auth0 organizations |
| PATCH | `/organizations/{org_id}` | Bearer | Update an organization's display name |
| DELETE | `/organizations/{org_id}` | Bearer | Delete an organization |
| POST | `/organizations/members` | Bearer | Add/remove a user from an org (`action=add\|remove`) |
| PATCH | `/users/metadata` | Bearer | Merge metadata into Keycloak attributes + Auth0 app_metadata |
| POST | `/users/active` | Bearer | Enable/disable (Keycloak) and unblock/block (Auth0) an account |
| POST | `/users/verify-email` | Bearer | Mark email verified or send verification emails (`action=set\|send`) |
| POST | `/users/password-reset` | Bearer | Trigger reset in both systems; returns an Auth0 ticket URL |
| POST | `/users/logout` | Bearer | Kill sessions in both systems (Auth0 also revokes grants) |
| GET | `/secure-data` | depends | Uses a server-side Auth0 M2M token |
| GET | `/keys` | none | Public RSA key |
| WS | `/ws/github` | Token on connect | Authenticated WebSocket GitHub relay (send `{resource, params}`) |


## Brokered browser login: how it works and how to debug it

The full chain is: your app -> Keycloak -> Auth0 -> Keycloak -> your app.
Verify it end-to-end with a real token round trip:

```bash
LOGIN_FLOW_CATCH=1 python login_flow.py
```

Open the printed URL, log in via Auth0, and it reports
`Round trip OK - user=..., idp=auth0`. If the client secret isn't in the
environment it is fetched from Keycloak automatically (needs admin creds).

### Two Auth0 applications (by design)

| App | Purpose | Where its ID/secret lives |
|---|---|---|
| M2M app (`non_interactive`) | Management API calls | `.env` `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET` |
| `keycloak-oidc-client` (`regular_web`) | The browser login Keycloak brokers through | Stored inside Keycloak's IdP config |

They are different apps with different secrets. `rotate_secret.py` refuses to
push the M2M secret into the IdP (it would break every brokered login), and
`diagnose_idp.py --fix-secret` refuses for the same reason. Use
`--set-idp-secret '<secret>'` with the browser-login app's own secret.

### Diagnosing a failed login

`diagnose_idp.py` inspects both sides and can repair most problems:

```bash
python diagnose_idp.py                       # full report
python diagnose_idp.py --events              # Keycloak's recorded login errors
python diagnose_idp.py --dump                # full IdP config JSON
python diagnose_idp.py --verify-idp-secret 'S'   # is this secret valid at Auth0?
python diagnose_idp.py --set-idp-secret 'S'      # verify, then store it
python diagnose_idp.py --fix-alg             # force RS256 ID-token signing
python diagnose_idp.py --fix-mappers         # add first-broker-login mappers
python diagnose_idp.py --fix-mappers-clean   # also remove conflicting duplicates
```

**Auth0's own logs are the authoritative source.** Auth0 Dashboard ->
Monitoring -> Logs, find the attempt:

- `type=feacft` ("Failed Exchange: Authorization Code") / `Unauthorized`
  -> Auth0 rejected Keycloak's credentials. The IdP's client secret is wrong.
- `type=seacft` ("Success Exchange") -> the exchange worked; any remaining
  failure is in Keycloak's first-broker-login (user creation/linking).

Keycloak's own `IDENTITY_PROVIDER_LOGIN_ERROR` event is often generic and
records no provider detail. **Its lack of detail does not mean the token
exchange succeeded** - check Auth0's logs before concluding anything.

### Failure modes hit in practice

| Symptom | Cause | Fix |
|---|---|---|
| `Invalid parameter: redirect_uri` | Client's Valid Redirect URIs missing the callback | App startup provisions it (`ensure_keycloak_client`); or `fix_redirect_uri.py` |
| Generic broker error, Auth0 log `feacft` | Wrong client secret in the IdP | `--verify-idp-secret` then `--set-idp-secret` |
| Generic broker error, ID token alg not RS256 | Auth0 signs ID tokens HS256; Keycloak validates via RS256 JWKS | `--fix-alg` |
| Generic broker error, no `clientAuthMethod` | Keycloak doesn't know how to authenticate at the token endpoint | `--fix-secret` / re-register the IdP |
| Login reaches Keycloak then fails creating the user | Missing/duplicate IdP mappers, or `disableUserInfo=true` | `--fix-mappers-clean` |
| `Invalid client or Invalid client credentials` from **Keycloak** | The app<->Keycloak leg: the app client's secret wasn't sent | set `KEYCLOAK_CLIENT_SECRET` (Clients -> your client -> Credentials) |

Note: the client **ID** is not the client **secret**. Pasting the ID where a
secret belongs produces `access_denied`; `--verify-idp-secret` detects this.


## OpenBao (the "Z-axis"): Keycloak + Auth0 <-> OpenBao

OpenBao is wired in three ways, all in `openbao_connect.py`, ADDED alongside the
existing Azure Key Vault (Key Vault stays; nothing is removed). Runtime target
is a local dev server:

```bash
bao server -dev -dev-root-token-id=root      # or: docker compose up openbao
export OPENBAO_ADDR=http://127.0.0.1:8200
export OPENBAO_TOKEN=root
```

**1. Keycloak -> OpenBao** (`configure_keycloak_oidc`) — OpenBao's OIDC auth
method trusts your Keycloak realm, so a Keycloak user can log into OpenBao and
receive a Vault token scoped by policy. The OpenBao role maps the
`preferred_username` claim and registers OpenBao's own callback URIs; the
Keycloak client must list those as valid redirect URIs and allow the
authorization-code flow.

**2. Auth0 -> OpenBao** (`configure_auth0_jwt`, `login_auth0_jwt`) — OpenBao's
JWT auth method trusts Auth0's issuer/JWKS, so an Auth0-issued token
authenticates to OpenBao directly (machine-to-machine, no browser).
`login_auth0_jwt(jwt)` exchanges an Auth0 JWT for an OpenBao token.

**3. OpenBao as a secret store** (`OpenBaoSecrets`, `resolve_secret`) — read and
write secrets in OpenBao's KV v2 engine. `resolve_secret(name)` tries OpenBao
first and FALLS BACK to Key Vault, so you can migrate secrets incrementally.
OpenBao is only attempted when `OPENBAO_TOKEN` is set, so environments without
it transparently keep using Key Vault.

Configure all three at once:

```bash
OPENBAO_TOKEN=root AUTH0_DOMAIN=... OPENBAO_KC_CLIENT_SECRET=...   python openbao_connect.py
```

Each step is idempotent (safe to re-run). The `compose.yaml` stack now includes
an `openbao` dev service on `:8200`; the app talks to it at
`http://openbao:8200`. Dev mode is in-memory and insecure — LOCAL USE ONLY.

### Running OpenBao with your live Keycloak & Auth0

`openbao_setup.py` is the executable mechanism that wires OpenBao to your REAL
IdPs. It reads config from `.env` and checks every precondition before writing.

```bash
# 0. Fill in .env (OPENBAO_TOKEN, KEYCLOAK_*, AUTH0_*), start OpenBao:
bao server -dev -dev-root-token-id=root

# 1. Verify preconditions WITHOUT changing anything:
python openbao_setup.py check

# 2. Configure Keycloak -> OpenBao (prints the redirect URIs to register + login cmd):
python openbao_setup.py keycloak

# 3. Configure Auth0 -> OpenBao (verifies with a REAL Auth0 token if M2M creds set):
python openbao_setup.py auth0

# Or do check + both at once:
python openbao_setup.py all

# Print the manual checklist any time:
python openbao_setup.py checklist
```

`check` confirms OpenBao is up and your token works, and that each IdP's
discovery URL is not just reachable but a VALID OIDC discovery document (a bare
200 that isn't real discovery is reported as a failure — OpenBao would reject
it too). The `keycloak` step configures OIDC auth then tells you the exact
Keycloak Valid Redirect URIs to add and the `bao login -method=oidc` command;
the browser step needs a human. The `auth0` step configures JWT auth and, if
`AUTH0_CLIENT_ID/SECRET/AUDIENCE` are set, fetches a real client-credentials
token and exchanges it for an OpenBao token — proving that leg end to end.

### Login round-trip verification

The JWT login *mechanics* are proven live by `openbao_login_smoke.py` — it mints
a real RS256 token, configures OpenBao's JWT auth against a local JWKS, and
asserts `login_auth0_jwt` returns a usable token (and that expired / wrong-
audience tokens are rejected):

```bash
bao server -dev -dev-root-token-id=root
OPENBAO_ADDR=http://127.0.0.1:8200 OPENBAO_TOKEN=root python openbao_login_smoke.py
```

The two flows that need a live IdP (a browser login through Keycloak, and a real
Auth0-issued JWT) are covered by a step-by-step checklist:

```python
python -c "import openbao_connect as o; print(o.login_checklist())"
```

### Live smoke test

`test_openbao.py` mocks the API; to verify against a REAL server, run
`openbao_smoke.py` (validated against OpenBao v2.6.1):

```bash
bao server -dev -dev-root-token-id=root      # terminal 1
OPENBAO_ADDR=http://127.0.0.1:8200 OPENBAO_TOKEN=root python openbao_smoke.py
```

It uses throwaway `smoke-*` mounts/secrets and cleans them up. It also stands up
a tiny local OIDC discovery stub, because of one important gotcha:

**OpenBao validates the OIDC discovery URL by FETCHING it at config-write time.**
`configure_keycloak_oidc` / `configure_auth0_jwt` will fail if the IdP's
`<issuer>/.well-known/openid-configuration` is not reachable *from the OpenBao
server*. The error is made explicit ("OpenBao could not reach the OIDC discovery
URL ... the IdP must be reachable FROM the OpenBao server"). In the compose
stack this works because all services share a network; for a local dev server
talking to a container, ensure the URLs resolve from OpenBao's point of view.

## Secret rotation

Rotate the Auth0 client secret and sync it into Keycloak:
```bash
python rotate_secret.py
```

**About zero-downtime:** Auth0's `client_secret` model allows only one active
secret per application — rotating invalidates the old one immediately. So there
is an unavoidable brief window between the Auth0 rotation and the Keycloak
update during which brokered logins would fail. `rotate_secret.py` minimises
this by rotating and pushing to Keycloak back-to-back, then verifying. For true
zero-downtime you would need either a standby second Auth0 application (swap the
IdP to it, then rotate the idle one) or Auth0's private-key-JWT client
authentication with multiple keys — larger changes not implemented here.

## Running in a container (Docker or Podman)

The image is defined in a `Containerfile` (with an identical `Dockerfile` copy),
using only standard OCI instructions so it builds and runs the same under both
engines.

Build:
```bash
docker build -t auth-broker .      # Docker
podman build --format docker -t auth-broker .   # Podman (see note below)
```

Run (supplying config via an env file):
```bash
docker run --env-file .env -p 8000:8000 auth-broker
podman run --env-file .env -p 8000:8000 auth-broker
```

Or bring up the API together with a Keycloak instance via compose:
```bash
docker compose up --build          # Docker
podman compose up --build          # Podman v4.1+
podman-compose up --build          # standalone podman-compose
```

Notes:
- The container runs as a non-root user and writes generated RSA keys to
  `KEY_DIR` (`/data/keys`), which `compose.yaml` persists in a named volume.
- On startup the app waits for Keycloak, retrying with exponential backoff
  (`KEYCLOAK_STARTUP_RETRIES`, default 10; `KEYCLOAK_STARTUP_BACKOFF`, default
  2.0s). This tolerates Keycloak still coming up, complementing compose's
  `depends_on: service_healthy`.
- A `HEALTHCHECK` hits `GET /`. Docker stores and runs it natively. Podman's
  default OCI image format drops HEALTHCHECK, so build with `--format docker`
  (shown above) or pass `--health-cmd` at run time.
- The bundled Keycloak service sets `KC_HEALTH_ENABLED=true`; on Keycloak 25+
  the health endpoints live on the management port (9000), which the compose
  healthcheck targets.

## Testing

```bash
pip install pytest responses
pytest
```

All HTTP is mocked, so no live Keycloak or Auth0 is needed.

For a one-command end-to-end check that the REAL app boots and serves (full
lifespan, token grant, introspection, protected endpoints) against a built-in
mock IdP, run:
```bash
python e2e_smoke.py     # exit 0 = all checks passed
``` The suite covers
every module and all HTTP endpoints. CI (`.github/workflows/ci.yml`) runs lint
(`pyflakes`) and the full suite on every push against Python 3.11 and 3.12.

## Production hardening (not yet implemented)

- Rate limiting on `/token` and `/register`
- HTTPS enforcement / TLS termination (the generated cert is self-signed, dev only)
- Persisting registered users to your own database where applicable
- Zero-downtime secret rotation (see above)
