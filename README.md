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
| GET | `/secure-data` | depends | Uses a server-side Auth0 M2M token |
| GET | `/keys` | none | Public RSA key |

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
podman build -t auth-broker .      # Podman (reads Containerfile by default)
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
- A `HEALTHCHECK` hits `GET /`; Docker runs it natively, Podman honours it when
  run with `--health-cmd` or via `podman play`.

## Testing

```bash
pip install pytest responses
pytest
```

All HTTP is mocked, so no live Keycloak or Auth0 is needed. The suite covers
every module and all HTTP endpoints. CI (`.github/workflows/ci.yml`) runs lint
(`pyflakes`) and the full suite on every push against Python 3.11 and 3.12.

## Production hardening (not yet implemented)

- Rate limiting on `/token` and `/register`
- HTTPS enforcement / TLS termination (the generated cert is self-signed, dev only)
- Persisting registered users to your own database where applicable
- Zero-downtime secret rotation (see above)
