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

**The app bootstraps a fresh Keycloak automatically.** On startup it creates the
target realm if missing, provisions the client (with redirect URIs and flows),
and creates a default `user` account that is fully set up for the password
grant. You do not need to pre-create the realm by hand — pointing
`KEYCLOAK_URL` at a clean Keycloak and providing admin credentials is enough.
This path is verified end to end against a real Keycloak, not just mocks.

### Bringing the stack up (and the port-80 conflict, solved)

The stack binds host ports 80/443 (Traefik). If a Traefik from **another** compose
project is already running, it holds those ports and this stack's Traefik fails
with `Bind for 0.0.0.0:80 failed: port is already allocated`. `docker compose down`
does not fix it — it only touches the current project, not the stray from a
different one. Use `stack-up.sh`, which resolves this deterministically:

```bash
./stack-up.sh --check      # report what's holding your ports; change nothing
./stack-up.sh              # clear this project's leftovers + strays (prompts first)
./stack-up.sh -y --up      # the "just make it work" invocation: clear + start
```

It removes this project's own containers/orphans (always safe), finds containers
from *other* projects holding your ports and removes them (after a prompt, or
immediately with `-y`), flags any non-docker listener it can't safely kill, and
with `--up` starts the stack and prints status.

**Freeing a single port** (e.g. `bind: address already in use` on 8200 from a
leftover `bao server -dev`, or any one port): `free-port.sh` targets one or more
ports and clears **both** kinds of holder — a Docker container publishing the
port *and* a plain host process listening on it:

```bash
./free-port.sh --check 8200   # report what's on 8200; change nothing
./free-port.sh -y 8200        # remove the container / kill the process on 8200
./free-port.sh -y 8200 8201   # several ports at once
```

It ignores your stack's internal-only ports and Docker's own proxy, so it only
acts on real conflicts.

### The PremAlytics Command Center hostnames (`*.test.local`)

The stack routes both `*.localhost` and `*.test.local`. To use the `.test.local`
Command Center URLs over HTTPS:

1. Add hosts entries (`.test.local` does not auto-resolve like `.localhost`):
   ```bash
   echo "127.0.0.1  app.test.local  keycloak.test.local  openbao.test.local  traefik.test.local" | sudo tee -a /etc/hosts
   ```
2. Issue the cert covering those names (see the OpenBao PKI section), then trust the CA.
3. Bring the stack up: `./stack-up.sh -y --up`
4. Open `https://app.test.local`, `https://keycloak.test.local`,
   `https://traefik.test.local/dashboard/`.

(Keycloak's issuer stays `keycloak.localhost` unless you change `KC_HOSTNAME` —
doing so also means updating your Auth0 callback URLs.)


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
| POST | `/token/client` | none | Machine-to-machine token (OAuth2 client_credentials): an app authenticates with its Keycloak client_id + secret. Accepts an optional `scope` to constrain the token. The client's service account can hold realm roles (set `SERVICE_ACCOUNT_ROLE`) so the token carries real permissions; endpoints enforce scopes via `require_scope`. M2M requests use a separate, higher rate limit (`RATE_LIMIT_M2M_MAX`). |
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

### Migrating secrets to OpenBao (incremental, reversible)

`authorize.get_secret()` can read from OpenBao first, per secret, opt-in via
`OPENBAO_SECRETS`. Key Vault remains the fallback, so nothing breaks if OpenBao
is down or the secret isn't there yet.

```bash
# Default: empty -> Key Vault only, byte-for-byte the original behaviour.
OPENBAO_SECRETS=

# Pilot ONE secret:
OPENBAO_SECRETS=AUTH0_AUDIENCE

# Expand as you gain confidence:
OPENBAO_SECRETS=AUTH0_AUDIENCE,AUTH0_CLIENT_ID

# Everything:
OPENBAO_SECRETS=*
```

Write the secret into OpenBao first, then add its name:

```bash
python -c "import openbao_connect as o; \
  o.OpenBaoSecrets().put_secret('AUTH0_AUDIENCE','https://your-api')"
```

Rollback is removing the name from `OPENBAO_SECRETS` — no code change. If
OpenBao is unreachable or the secret is missing, the lookup logs a warning and
falls through to Key Vault rather than failing the request.

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

## Traefik (edge proxy + ForwardAuth)

Traefik fronts the whole stack: it terminates TLS and routes to Keycloak,
OpenBao, and the app by hostname, and it protects the app's non-public routes by
delegating the auth decision to the app itself via **ForwardAuth**.

Bring it up with the rest of the stack:

```bash
docker compose up --build     # or podman compose up --build
```

Add these to `/etc/hosts` (most systems already resolve `*.localhost` to
127.0.0.1, so this may be unnecessary):

```
127.0.0.1  app.localhost  keycloak.localhost  openbao.localhost
```

Then:
- App:        https://app.localhost/
- Keycloak:   https://keycloak.localhost/
- OpenBao:    https://openbao.localhost/
- Dashboard:  http://localhost:8090/dashboard/

### How ForwardAuth works here

On every request to a *protected* app route, Traefik calls the app's
`GET/POST /auth/forward` endpoint, forwarding the original request's headers. The
endpoint validates the bearer token (the same Keycloak introspection path the
app's own endpoints use) and returns:

- **2xx** -> Traefik proceeds to the app, adding `X-Auth-User` / `X-Auth-Subject`
  from the *validated token*.
- **401/503** -> Traefik denies, returning that status to the client.

The public routes (`/token`, `/register`, `/auth/forward`, `/`, `/keys`,
`/status/*`) are deliberately NOT behind ForwardAuth — otherwise you'd need a
token to reach the endpoint that issues tokens. This is enforced by router
priority (public > protected) and validated by `container_check.py`.

### Verifying the whole stack end to end

`container_check.py` validates the config statically, and the ForwardAuth
endpoint is unit-tested — but to confirm real requests route and gate correctly
through the actual proxy, run the end-to-end smoke once you have an engine:

```bash
./traefik_smoke.sh            # brings the stack up and tests it
./traefik_smoke.sh --down     # also tears it down afterwards
COMPOSE="podman compose" ./traefik_smoke.sh   # use podman
```

It asserts the things only a live proxy can prove: public routes answer without
a token, `/protected` is DENIED (401) without one and ALLOWED (200) with a valid
token through Traefik, a forged `X-Auth-User` cannot impersonate, and the other
services are routed. On failure it points you at the Traefik dashboard
(http://localhost:8090/dashboard/) and the relevant logs.

### Trust boundary

`X-Auth-User`/`X-Auth-Subject` are set by the app from the validated token and
copied back onto the upstream request by Traefik (`authResponseHeaders`). The
endpoint never echoes client-supplied `X-Auth-*` headers, and `container_check`
plus the test suite guard that a forged header cannot impersonate a user. The app
also trusts `X-Forwarded-For` for rate limiting only now that Traefik fronts it
(`RATE_LIMIT_TRUST_PROXY=true`) — never enable that when the app is directly
reachable.

## Turning subsystems on and off

`features.py` gives each OPTIONAL subsystem three modes. Check live state at
`GET /status/subsystems` or `python features.py`.

| Env var | Values | Default | Controls |
|---|---|---|---|
| `OPENBAO_MODE` | on / off / auto | auto | OpenBao secret lookups |
| `AUTH0_MANAGEMENT_MODE` | on / off / auto | auto | Auth0 Management API (users, orgs, IdP provisioning) |
| `KEYCLOAK_REQUIRED` | true / false | true | whether an unreachable Keycloak is fatal at startup |

- **on** — always enabled; failures surface as errors.
- **off** — always disabled; calls short-circuit with a clear reason (no network call).
- **auto** — enabled only if configured AND reachable, probed and cached for
  `FEATURE_PROBE_TTL` seconds. This is the "based on circumstances" mode: start
  OpenBao and it switches on; stop it and the app degrades to Key Vault.

**An important limit.** Auth0 has two roles here and only one is switchable:

1. **Brokered-login IdP** (Keycloak → Auth0) — ARCHITECTURAL. There is
   deliberately no flag, because disabling it would not degrade login, it would
   break it. A flag implying otherwise would be misleading.
2. **Management API** — genuinely optional, controlled by
   `AUTH0_MANAGEMENT_MODE`. With it off the app still starts and Keycloak-native
   auth works; user/org endpoints return 503 and say why.

`KEYCLOAK_REQUIRED=false` starts the app in degraded mode when Keycloak is down,
so `/status/subsystems` is reachable for diagnosis. Auth endpoints then fail
with a clear reason instead of the whole process being unreachable.

## Container build

Validate the build statically first — no engine needed, runs in CI:

```bash
python container_check.py
```

It catches silent-failure classes that a passing build would hide:

- **Comments inside a line continuation.** Modern BuildKit strips them; older
  Docker and some buildah versions do NOT, truncating the instruction. Here
  that would drop `HOST=0.0.0.0` and `KEY_DIR` — the app would bind loopback
  inside the container and be unreachable from the host, while the healthcheck
  (which runs INSIDE the container against 127.0.0.1) still reported healthy.
- `HOST` not `0.0.0.0`, in the Dockerfile or compose.
- A module imported from `main.py` that `.dockerignore` excludes from the image.
- A third-party import missing from `requirements.txt`.
- `Dockerfile` and `Containerfile` drifting apart.

Then build for real:

```bash
docker build -t auth-broker .
podman build --format docker -t auth-broker .   # --format docker keeps HEALTHCHECK
```

## Testing real endpoints with a real token

```bash
uvicorn main:app --port 8000                    # terminal 1
LOGIN_FLOW_CATCH=1 python login_flow.py         # get a brokered token
APP_TOKEN='<paste>' python endpoint_smoke.py    # exercise the API
APP_TOKEN='<paste>' python endpoint_smoke.py --write   # also create/delete throwaway objects
```

Read-only by default. It asserts `/protected` REJECTS an anonymous caller (a
security check, not a formality), and treats 503 from a disabled subsystem as a
skip rather than a failure.

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

## Production hardening

### Going to production: the dev-only shortcuts to replace

This stack is a **local dev / demo** setup. Several deliberate shortcuts make it
"just work" locally but are **not** production-safe. Before any real deployment:

- **OpenBao auto-unseal.** The `openbao/entrypoint.sh` stores the unseal key in
  plaintext in the data volume so it can auto-unseal on boot. In production,
  remove that and use a real **auto-unseal** (a cloud KMS seal, or a `transit`
  seal backed by a separate OpenBao) so the master key is never persisted. Also
  drop `user: "0:0"` and the loopback `127.0.0.1:8200` publish on the openbao
  service, and don't keep `bao-init.json` around.
- **AppRole secret_id.** Defaults to never-expire / unlimited-use for dev
  convenience. Set a finite lifetime with `OPENBAO_SECRET_ID_TTL` and
  `OPENBAO_SECRET_ID_NUM_USES` (or the `configure_approle` args), and deliver the
  secret_id to the app via a wrapped/response-wrapped token rather than plain env.
- **The CA and cert.** The internal root CA is self-signed and trusted manually
  per-machine. Use an intermediate signed by your org's real root (or ACME/real
  certs) so clients trust it without manual keychain steps.
- **Storage.** OpenBao's `file` backend is deprecated by v2.7 — migrate to a
  supported backend (raft/integrated storage) before upgrading past it.
- **Secrets.** Put real values in Key Vault / OpenBao KV, not demo data, and
  scope the AppRole policy to only the paths the app needs (it already grants
  read-only on the KV data path).

#### Production auto-unseal (the #1 item) — runbook

The dev entrypoint stores the unseal key in plaintext to auto-unseal. Production
replaces this so the master key is held by a seal (KMS/transit) and never
persisted. The pieces are shipped but **must be verified against your real seal**
— they could not be run in the dev sandbox.

1. **Provide a seal.** A cloud KMS (Azure Key Vault fits this stack's existing
   Azure usage) or a separate "transit" OpenBao whose token has encrypt/decrypt
   on a wrapping key.
2. **Config.** Copy `openbao/config.transit.hcl.example` to
   `openbao/config.transit.hcl`, keep exactly one `seal` stanza and fill it in.
   It also switches storage `file` -> `raft` and enables listener TLS.
3. **Entrypoint mode.** Set `BAO_AUTO_UNSEAL=1` on the openbao service. The
   entrypoint then initializes with RECOVERY keys (not unseal keys) and lets the
   seal auto-unseal the server — no manual unseal, no persisted unseal key.
4. **Compose edits** (a prod overlay): mount `config.transit.hcl` instead of
   `config.hcl`, drop `user: "0:0"` (run non-root against a writable volume),
   drop the `127.0.0.1:8200:8200` publish, set `BAO_AUTO_UNSEAL=1`.
5. **Verify on your infra:** `docker compose logs openbao` shows
   `auto-unsealed via seal — OpenBao is ready`, a restart comes back unsealed
   with no unseal key anywhere, and the data volume holds no unseal key.

Intermediate option (better than dev, simpler than KMS): set `BAO_UNSEAL_KEY`
from a Docker secret — the entrypoint unseals from it and never reads the key
from the volume.

### Rate limiting (implemented)

`/token` (credential brute-force) and `/register` (signup spam) are rate-limited
per client IP with an in-process sliding window (`rate_limit.py`) — no Redis or
extra infrastructure. Defaults: 10 logins and 5 registrations per minute per IP,
tunable via `RATE_LIMIT_*`. A blocked request gets `429` with a `Retry-After`
header. Two deliberate properties: it is **fail-open** (a limiter error allows
the request — a security add-on must not break login), and it does **not trust
`X-Forwarded-For`** unless `RATE_LIMIT_TRUST_PROXY=true`, since a spoofable key
lets an attacker dodge the limit and lock out victims. Limitation: counters are
per-process, so behind N replicas the effective limit is N x the value.

### OpenBao as an internal certificate authority (implemented)

OpenBao's PKI engine can act as an internal CA that issues the TLS cert Traefik
serves — replacing Traefik's throwaway self-signed cert with one from a CA you
control. `openbao_connect.py` provides the primitives (`enable_pki_engine`,
`configure_pki_root_ca`, `create_pki_role`, `issue_certificate`), and
`openbao_traefik_cert.py` wires them together: it issues a leaf cert for your
hostnames and writes `openbao-cert.pem` (full chain), `openbao-key.pem` (0600),
and a `tls-openbao.yml` Traefik dynamic-TLS config into `traefik/dynamic/`.

    OPENBAO_ADDR=... OPENBAO_TOKEN=... ./openbao_traefik_cert.py \
        --hostnames app.localhost,keycloak.localhost,openbao.localhost

Then re-up Traefik so it loads the cert, and verify the issuer is your OpenBao
CA:

    curl -vk https://app.localhost 2>&1 | grep -i 'issuer\|subject'

Defaults to a self-signed root CA (right for internal/dev trust); switch to an
intermediate signed by your existing corporate root when you have one. The
generated cert/key/config are git-ignored — the private key must never be
committed.

#### Persistent CA (issue once, trust once)

By default the compose OpenBao now runs with **file storage on a volume**
(`openbao-data`) and an auto-init/unseal entrypoint (`openbao/entrypoint.sh`),
so the CA survives `docker compose down/up` — a cert you trust stays trusted.
The trade-off vs the old `-dev` mode: a durable OpenBao starts *sealed*, so the
entrypoint auto-unseals it. To do that unattended it stores the unseal key in
the data volume in plaintext — fine for local dev, **not** production (production
uses a KMS auto-unseal).

Because it's no longer dev mode, the fixed `root` token is gone — the real root
token is generated on first init. Read it (and point the cert tool at the
container's persistent OpenBao, published on loopback):

    ROOT=$(docker compose exec -T openbao sh -c 'sed -n "s/.*\"root_token\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" /openbao/data/bao-init.json | tr -d "\n"')
    OPENBAO_ADDR=http://127.0.0.1:8200 OPENBAO_TOKEN="$ROOT" ./openbao_traefik_cert.py
    docker compose restart traefik

Trust the CA once and it stays valid across restarts:

    curl -s http://127.0.0.1:8200/v1/pki/ca/pem -o /tmp/openbao-ca.pem
    openssl x509 -in /tmp/openbao-ca.pem -noout -subject          # sanity check
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/openbao-ca.pem

Note: the app's `OPENBAO_TOKEN` env still defaults to `root`, which no longer
exists. OpenBao secret resolution is opt-in and off by default (`OPENBAO_MODE=auto`
falls back to Key Vault), so this doesn't affect normal operation — but if you
use OpenBao-backed secrets, set `OPENBAO_TOKEN` to the generated root token (or
wire an AppRole).

**Renewal.** Certs are re-issued by running the same tool with `--renew`, which
only re-issues when the current cert is due (below 1/3 of its lifetime, or under
7 days remaining — whichever comes first) and otherwise exits without change.
It's a check-and-exit, meant to run on a cron or systemd timer, not a daemon:

    # daily at 03:00 — re-issue only when due, then reload Traefik if changed
    0 3 * * *  OPENBAO_ADDR=... OPENBAO_TOKEN=... /path/openbao_traefik_cert.py --renew

Renewal is safe by construction: the new cert is issued and validated BEFORE any
file is overwritten, so if OpenBao is unreachable or issuance fails, the existing
working cert is left untouched and Traefik keeps serving it. Re-running the
initial setup never mints a new CA (it detects and reuses the existing one), so
previously-issued certs keep chaining; pass `force=True` to `configure_pki_root_ca`
only when you deliberately want to rotate the CA.

### Security response headers (implemented)

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options:
DENY`, and `Referrer-Policy: no-referrer` (set in the correlation-ID
middleware). HSTS (`Strict-Transport-Security`) is opt-in via `SECURITY_HSTS=true`
— it's off by default so a plain-HTTP local/dev setup isn't locked out. No CSP is
set: the broker serves JSON, and a wrong CSP breaks more than it protects. All
use `setdefault`, so an endpoint that sets its own value is never overridden.

### Secrets out of the environment (implemented)

`GITHUB_TOKEN` resolves through the secret store first (`authorize.get_secret`,
honouring `OPENBAO_SECRETS` and the feature flags), falling back to the env var
only for local dev — so in production it lives in OpenBao/Key Vault, not the
process environment. The same pattern applies to any secret.

### Still deployment-side (not code)

- HTTPS / TLS termination at your ingress or proxy (the generated cert is
  self-signed, dev only).
- Keycloak realm SMTP, so email-verification and password-reset flows send mail.
- Persisting registered users to your own database where applicable.
- Zero-downtime secret rotation (see "Secret rotation" above).
