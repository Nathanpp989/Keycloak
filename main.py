#!/usr/bin/env python3
import json
import logging
import time
import os
import stat
import tempfile
from contextlib import asynccontextmanager

import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Depends, HTTPException, Form, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer
from authorize import router as auth0_router, oauth2_scheme
from keycloak import KeycloakOpenID, KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError

# User-flow integration (auth0_connect.py / auth0_talk.py / auth0_type.py)
from auth0_connect import Auth0Connect, get_keycloak_admin_token
from auth0_talk import KeycloakAdminAPI, Auth0UsersAPI, Auth0AuthzExtensionAPI, Auth0OrganizationsAPI
from auth0_type import UserManager

# I3 FIX: configure logging before anything else so all logger.* calls produce output
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration (single source of truth) ────────────────────────────────────
# Fix #3: realm and client id are read once here so setup, the OIDC client, and
# the user manager all operate on the SAME realm/client. Previously the realm was
# hardcoded "Premkey" in some places and read from KEYCLOAK_REALM in others.
KEYCLOAK_URL       = os.environ.get("KEYCLOAK_URL", "http://localhost:8080/")
KEYCLOAK_REALM     = os.environ.get("KEYCLOAK_REALM", "Premkey")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "Hello-World-app")

# ── RSA key management ────────────────────────────────────────────────────────
public_pem: bytes = b""

def _write_atomic(path: str, data: bytes, mode: int = 0o644):
    """Write data to path atomically; set permissions before rename."""
    dir_ = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dir_)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def init_rsa_keys():
    global public_pem
    # B108 fix: default to a USER-PRIVATE directory, not world-writable /tmp
    # (symlink/pre-creation risk on shared hosts). Containers override via
    # KEY_DIR=/data/keys. The directory is forced to 0700 either way.
    KEY_DIR = os.environ.get(
        "KEY_DIR", os.path.join(os.path.expanduser("~"), ".auth-broker", "keys"))
    os.makedirs(KEY_DIR, exist_ok=True)
    os.chmod(KEY_DIR, 0o700)
    private_key_path = os.path.join(KEY_DIR, "private.pem")
    public_key_path  = os.path.join(KEY_DIR, "public.pem")
    try:
        with open(public_key_path, "rb") as f:
            public_pem = f.read()
        with open(private_key_path, "rb"):
            pass
    except FileNotFoundError:
        _priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_bytes = _priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        _pub_pem = _priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        _write_atomic(private_key_path, private_bytes, mode=stat.S_IRUSR | stat.S_IWUSR)
        _write_atomic(public_key_path, _pub_pem)
        public_pem = _pub_pem

# ── Keycloak helpers ──────────────────────────────────────────────────────────
def create_keycloak_user(admin: KeycloakAdmin, username: str, password: str, group: str):
    existing = admin.get_users({"username": username, "exact": "true"})
    if existing:
        return existing[0]["id"]
    groups = admin.get_groups()
    group_id = next((g["id"] for g in groups if g["name"] == group), None)
    if not group_id:
        group_id = admin.create_group({"name": group})
    user_id = admin.create_user({
        "username":    username,
        "enabled":     True,
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    admin.group_user_add(user_id, group_id)
    return user_id

def setup_keycloak() -> str:
    """
    Ensure the realm's auth flow, default user, and client secret exist.
    Returns the client's actual secret so the app can authenticate as a
    confidential client (fixes the secret never being wired into keycloak_oidc).
    """
    admin = KeycloakAdmin(
        server_url=os.environ.get("KEYCLOAK_URL", "http://localhost:8080/"),
        username=os.environ.get("KEYCLOAK_ADMIN_USER", "admin"),
        password=os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
        realm_name=KEYCLOAK_REALM,
        user_realm_name="master",
        verify=True
    )
    flows = admin.get_authentication_flows()
    if not any(flow["alias"] == "Hello-World-flow" for flow in flows):
        admin.create_authentication_flow({
            "alias":       "Hello-World-flow",
            "description": "Authentication flow for Hello World app",
            "providerId":  "basic-flow",
            "topLevel":    True,
            "builtIn":     False
        })
    default_password = os.environ.get("DEFAULT_USER_PASSWORD", "change-me")
    create_keycloak_user(admin, "user", default_password, "users")

    client_uuid     = admin.get_client_id(KEYCLOAK_CLIENT_ID)
    existing_secret = admin.get_client_secrets(client_uuid)
    secret_value    = existing_secret.get("value")
    if secret_value is None:
        # M1 FIX: the python-keycloak method is generate_client_secrets —
        # create_client_secret does not exist (AttributeError on real library;
        # hidden in tests by MagicMock accepting any attribute).
        created = admin.generate_client_secrets(client_uuid)
        secret_value = created.get("value") if isinstance(created, dict) else None
    # Fix #2: return the real secret (env override wins if explicitly set)
    return os.environ.get("KEYCLOAK_CLIENT_SECRET") or secret_value or ""

# ── Lifespan ──────────────────────────────────────────────────────────────────
keycloak_oidc: KeycloakOpenID | None = None
user_manager: UserManager | None = None

def _build_user_manager() -> UserManager | None:
    """
    Wire up the UserManager from auth0_type using a fresh Keycloak admin token
    and an Auth0 M2M client. Returns None (with a warning) if the required
    Auth0 env vars are missing, so the rest of the app can still start.
    """
    keycloak_url = KEYCLOAK_URL
    realm        = KEYCLOAK_REALM
    admin_user   = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
    admin_pass   = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")

    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    auth0_id     = os.environ.get("AUTH0_CLIENT_ID")
    auth0_secret = os.environ.get("AUTH0_CLIENT_SECRET")
    if not (auth0_domain and auth0_id and auth0_secret):
        logger.warning(
            "Auth0 env vars missing — user-management endpoints will be disabled. "
            "Set AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET to enable them."
        )
        return None

    # Provide a token-getter so KeycloakAdminAPI always uses a FRESH admin token.
    # Keycloak admin tokens expire in ~60s, so a one-time token would break the
    # endpoints a minute after startup.
    def kc_token_getter() -> str:
        return get_keycloak_admin_token(keycloak_url, admin_user, admin_pass)

    keycloak_api   = KeycloakAdminAPI(keycloak_url, kc_token_getter, realm)
    auth0_conn     = Auth0Connect(auth0_domain, auth0_id, auth0_secret)
    auth0_users    = Auth0UsersAPI(auth0_conn)
    # Optional Auth0 Authorization Extension (groups) — only if its URL is set.
    authz = None
    authz_url = os.environ.get("AUTH0_AUTHZ_EXTENSION_URL")
    if authz_url:
        authz = Auth0AuthzExtensionAPI(auth0_conn, authz_url)
    # Auth0 Organizations are always available via the Management API.
    auth0_orgs = Auth0OrganizationsAPI(auth0_conn)
    return UserManager(keycloak_api, auth0_users, auth0_authz=authz, auth0_orgs=auth0_orgs)


def _setup_keycloak_with_retry() -> str:
    """
    Call setup_keycloak() with retry + exponential backoff, so the app can start
    in a container before Keycloak is fully ready (a common race even with
    compose 'depends_on'). Tunable via env vars:
      KEYCLOAK_STARTUP_RETRIES (default 10)
      KEYCLOAK_STARTUP_BACKOFF (default 2.0 seconds, doubles each attempt, capped)
    Raises the last error if all attempts fail.
    """

    retries = int(os.environ.get("KEYCLOAK_STARTUP_RETRIES", "10"))
    backoff = float(os.environ.get("KEYCLOAK_STARTUP_BACKOFF", "2.0"))
    max_backoff = 30.0
    last_exc: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            return setup_keycloak()
        except Exception as exc:  # noqa: BLE001 — we deliberately retry on any error
            last_exc = exc
            if attempt == retries:
                break
            wait = min(backoff * (2 ** (attempt - 1)), max_backoff)
            logger.warning(
                "Keycloak not ready (attempt %d/%d): %s — retrying in %.1fs",
                attempt, retries, exc, wait,
            )
            time.sleep(wait)

    raise RuntimeError(
        f"Keycloak setup failed after {retries} attempts"
    ) from last_exc


@asynccontextmanager
async def lifespan(app: FastAPI):
    global keycloak_oidc, user_manager
    try:
        init_rsa_keys()
    except Exception as exc:
        logger.error("RSA key initialisation failed: %s", exc)
        raise
    try:
        client_secret = _setup_keycloak_with_retry()
    except Exception as exc:
        logger.error("Keycloak setup failed after retries — check KEYCLOAK_URL "
                     "and credentials: %s", exc)
        raise
    if not client_secret:
        logger.warning(
            "No Keycloak client secret available for '%s'. Confidential-client "
            "operations (/token, introspection) will fail. Set KEYCLOAK_CLIENT_SECRET "
            "or ensure the client has a secret in Keycloak.", KEYCLOAK_CLIENT_ID
        )
    keycloak_oidc = KeycloakOpenID(
        server_url=KEYCLOAK_URL,
        client_id=KEYCLOAK_CLIENT_ID,
        realm_name=KEYCLOAK_REALM,
        client_secret_key=client_secret,   # Fix #2: real secret, not a placeholder
    )
    # Build the user manager; don't let its failure crash the whole app
    try:
        user_manager = _build_user_manager()
    except Exception as exc:
        logger.error("Could not initialise user manager: %s", exc)
        user_manager = None
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(auth0_router)

http_bearer     = HTTPBearer()

# ── Auth dependency ───────────────────────────────────────────────────────────
def _introspect_token(token: str) -> dict:
    """
    Validate a bearer token via Keycloak introspection and return the token-info
    dict. Raises HTTPException(401/503) on failure. Shared by the HTTP dependency
    and the WebSocket handler so both enforce identical rules.
    """
    if keycloak_oidc is None:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    try:
        token_info = keycloak_oidc.introspect(token)
    except Exception:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    # P2 FIX: introspect can return None / a non-dict on some error responses;
    # guard before calling .get() so this surfaces as 401, not an unhandled 500.
    if not isinstance(token_info, dict) or not token_info.get("active"):
        raise HTTPException(status_code=401, detail="Token is inactive or expired")
    return token_info


def require_keycloak_auth(credentials=Depends(http_bearer)) -> dict:
    """
    FastAPI dependency: validate the bearer token via Keycloak introspection.
    Returns the token info dict on success; raises 401/503 otherwise.
    Used to protect endpoints that must only be reachable by authenticated users.
    """
    return _introspect_token(credentials.credentials)

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
def read_root():
    return {"message": "Hello, World!"}

@app.get("/hello")
def read_hello(email: str, username: str):
    return {"email": email, "username": username}

@app.post("/token")
def login(username: str = Form(...), password: str = Form(...)):
    if keycloak_oidc is None:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    try:
        token_response = keycloak_oidc.token(username, password)
        return {"access_token": token_response["access_token"], "token_type": "bearer"}
    except KeycloakAuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")

@app.get("/protected")
def protected_route(token_info: dict = Depends(require_keycloak_auth)):
    return {"message": f"Hello, {token_info.get('preferred_username', 'user')}!"}

@app.post("/oidc-token")
def oidc_login(token: str = Depends(oauth2_scheme)):
    if keycloak_oidc is None:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    try:
        token_info = keycloak_oidc.introspect(token)
        if not isinstance(token_info, dict) or not token_info.get("active"):
            raise HTTPException(status_code=401, detail="Token is inactive or expired")
        return {"message": f"Hello, {token_info.get('preferred_username', 'user')}!"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")

@app.post("/register")
def register(
    email: str = Form(...),
    password: str = Form(...),
    username: str | None = Form(default=None),
):
    """
    Register a new user in BOTH Keycloak and Auth0 via the UserManager.
    If 'username' is omitted, one is derived from the email address.
    """
    if user_manager is None:
        raise HTTPException(
            status_code=503,
            detail="User management is unavailable (Auth0 not configured).",
        )
    try:
        result = user_manager.add_user(email=email, password=password, username=username)
    except RuntimeError as exc:
        # Surfaced for things like missing Auth0 scopes
        logger.error("Registration failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Unexpected registration error: %s", exc)
        raise HTTPException(status_code=500, detail="Registration failed")

    return {
        "message": f"User '{result['username']}' registered.",
        "username": result["username"],
        "email": result["email"],
        "keycloak_id": result["keycloak_id"],
        "auth0_id": result["auth0_id"],
        "pre_existing": result["pre_existing"],
    }

@app.get("/users/lookup")
def users_lookup(
    username: str,
    email: str,
    token_info: dict = Depends(require_keycloak_auth),
):
    """
    Report which system(s) a user belongs to (keycloak/auth0/both/neither).
    Protected: requires a valid Keycloak bearer token, because this endpoint
    reveals whether an account exists (a user-enumeration vector if left open).
    """
    if user_manager is None:
        raise HTTPException(
            status_code=503,
            detail="User management is unavailable (Auth0 not configured).",
        )
    try:
        system = user_manager.determine_user_system(username, email)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("User lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail="Lookup failed")
    return {"username": username, "email": email, "system": system.value}

@app.get("/users/membership")
def users_membership(
    username: str,
    email: str,
    token_info: dict = Depends(require_keycloak_auth),
):
    """
    Return a user's groups and roles from BOTH Keycloak and Auth0, correlated.
    Protected: requires a valid Keycloak bearer token (same enumeration concern
    as /users/lookup).
    """
    if user_manager is None:
        raise HTTPException(
            status_code=503,
            detail="User management is unavailable (Auth0 not configured).",
        )
    try:
        return user_manager.get_membership(username, email)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Membership lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail="Membership lookup failed")

@app.post("/groups")
def create_group(
    name: str = Form(...),
    parent_path: str | None = Form(default=None),
    token_info: dict = Depends(require_keycloak_auth),
):
    """
    Create a group (or subgroup if parent_path is given) in Keycloak and, if the
    Authorization Extension is configured, in Auth0. Protected.
    """
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    try:
        return user_manager.create_group(name, parent_path=parent_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Group creation failed: %s", exc)
        raise HTTPException(status_code=500, detail="Group creation failed")

@app.post("/users/groups")
def modify_group_membership(
    username: str = Form(...),
    email: str = Form(...),
    group_name: str = Form(...),
    action: str = Form(...),  # "add" or "revoke"
    token_info: dict = Depends(require_keycloak_auth),
):
    """
    Add or revoke a user's membership in a group across systems. Protected.
    `action` must be 'add' or 'revoke'.
    """
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    if action not in ("add", "revoke"):
        raise HTTPException(status_code=422, detail="action must be 'add' or 'revoke'")
    try:
        return user_manager.set_group_membership(
            username, email, group_name, add=(action == "add")
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Group membership change failed: %s", exc)
        raise HTTPException(status_code=500, detail="Group membership change failed")

@app.post("/users/roles")
def modify_user_role(
    username: str = Form(...),
    email: str = Form(...),
    role_name: str = Form(...),
    action: str = Form(...),  # "assign" or "revoke"
    token_info: dict = Depends(require_keycloak_auth),
):
    """
    Assign or revoke a role for a user across systems (Keycloak realm role +
    Auth0 Authorization Core role). Protected. `action` must be 'assign'/'revoke'.
    """
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    if action not in ("assign", "revoke"):
        raise HTTPException(status_code=422, detail="action must be 'assign' or 'revoke'")
    try:
        return user_manager.set_role(
            username, email, role_name, assign=(action == "assign")
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Role change failed: %s", exc)
        raise HTTPException(status_code=500, detail="Role change failed")

@app.patch("/groups")
def update_group_endpoint(
    group: str = Form(...),
    new_name: str = Form(...),
    token_info: dict = Depends(require_keycloak_auth),
):
    """Rename a group (by path or name) across systems. Protected."""
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    try:
        return user_manager.update_group(group, new_name)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Group update failed: %s", exc)
        raise HTTPException(status_code=500, detail="Group update failed")

@app.delete("/groups")
def delete_group_endpoint(
    group: str,
    token_info: dict = Depends(require_keycloak_auth),
):
    """Delete a group (by path or name) across systems. Protected."""
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    try:
        return user_manager.delete_group(group)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Group delete failed: %s", exc)
        raise HTTPException(status_code=500, detail="Group delete failed")

@app.post("/organizations")
def create_organization_endpoint(
    name: str = Form(...),
    display_name: str | None = Form(default=None),
    token_info: dict = Depends(require_keycloak_auth),
):
    """Create (or reuse) an Auth0 organization. Protected."""
    if user_manager is None or user_manager.auth0_orgs is None:
        raise HTTPException(status_code=503, detail="Organizations API unavailable.")
    try:
        return user_manager.auth0_orgs.create_organization(name, display_name=display_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Organization create failed: %s", exc)
        raise HTTPException(status_code=500, detail="Organization create failed")

@app.get("/organizations")
def list_organizations_endpoint(
    token_info: dict = Depends(require_keycloak_auth),
):
    """List Auth0 organizations. Protected."""
    if user_manager is None or user_manager.auth0_orgs is None:
        raise HTTPException(status_code=503, detail="Organizations API unavailable.")
    try:
        return {"organizations": user_manager.auth0_orgs.list_organizations()}
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Organization list failed: %s", exc)
        raise HTTPException(status_code=500, detail="Organization list failed")

@app.patch("/organizations/{org_id}")
def update_organization_endpoint(
    org_id: str,
    display_name: str = Form(...),
    token_info: dict = Depends(require_keycloak_auth),
):
    """Update an Auth0 organization's display name. Protected."""
    if user_manager is None or user_manager.auth0_orgs is None:
        raise HTTPException(status_code=503, detail="Organizations API unavailable.")
    try:
        return user_manager.auth0_orgs.update_organization(org_id, display_name=display_name)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Organization update failed: %s", exc)
        raise HTTPException(status_code=500, detail="Organization update failed")

@app.delete("/organizations/{org_id}")
def delete_organization_endpoint(
    org_id: str,
    token_info: dict = Depends(require_keycloak_auth),
):
    """Delete an Auth0 organization. Protected."""
    if user_manager is None or user_manager.auth0_orgs is None:
        raise HTTPException(status_code=503, detail="Organizations API unavailable.")
    try:
        user_manager.auth0_orgs.delete_organization(org_id)
        return {"deleted": org_id}
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Organization delete failed: %s", exc)
        raise HTTPException(status_code=500, detail="Organization delete failed")

@app.post("/organizations/members")
def organization_membership_endpoint(
    email: str = Form(...),
    org_name: str = Form(...),
    action: str = Form(...),  # "add" or "remove"
    token_info: dict = Depends(require_keycloak_auth),
):
    """Add or remove a user (by email) from an Auth0 organization. Protected."""
    if user_manager is None or user_manager.auth0_orgs is None:
        raise HTTPException(status_code=503, detail="Organizations API unavailable.")
    if action not in ("add", "remove"):
        raise HTTPException(status_code=422, detail="action must be 'add' or 'remove'")
    try:
        status = user_manager.set_organization_membership(
            email, org_name, add=(action == "add")
        )
        return {"status": status}
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Organization membership change failed: %s", exc)
        raise HTTPException(status_code=500, detail="Organization membership change failed")

@app.patch("/users/metadata")
def set_user_metadata(
    username: str = Form(...),
    email: str = Form(...),
    metadata: str = Form(...),  # JSON object as a string
    token_info: dict = Depends(require_keycloak_auth),
):
    """Merge key/values into Keycloak attributes + Auth0 app_metadata. Protected."""
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    try:
        parsed = json.loads(metadata)
        if not isinstance(parsed, dict):
            raise ValueError("metadata must be a JSON object")
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="metadata must be a JSON object string")
    try:
        return user_manager.set_user_metadata(username, email, parsed)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Metadata update failed: %s", exc)
        raise HTTPException(status_code=500, detail="Metadata update failed")

@app.post("/users/active")
def set_user_active(
    username: str = Form(...),
    email: str = Form(...),
    active: bool = Form(...),
    token_info: dict = Depends(require_keycloak_auth),
):
    """Enable/disable (Keycloak) and unblock/block (Auth0) an account. Protected."""
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    try:
        return user_manager.set_user_active(username, email, active)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Active-state change failed: %s", exc)
        raise HTTPException(status_code=500, detail="Active-state change failed")

@app.post("/users/verify-email")
def verify_email(
    username: str = Form(...),
    email: str = Form(...),
    action: str = Form(...),  # "set" (mark verified) or "send" (send the email)
    token_info: dict = Depends(require_keycloak_auth),
):
    """Mark email verified in both systems, or trigger verification emails. Protected."""
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    if action not in ("set", "send"):
        raise HTTPException(status_code=422, detail="action must be 'set' or 'send'")
    try:
        if action == "set":
            return user_manager.set_email_verified(username, email, True)
        return user_manager.send_verification_email(username, email)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Email verification failed: %s", exc)
        raise HTTPException(status_code=500, detail="Email verification failed")

@app.post("/users/password-reset")
def password_reset(
    username: str = Form(...),
    email: str = Form(...),
    token_info: dict = Depends(require_keycloak_auth),
):
    """Trigger a password reset in both systems (Auth0 returns a ticket URL). Protected."""
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    try:
        return user_manager.trigger_password_reset(username, email)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Password reset failed: %s", exc)
        raise HTTPException(status_code=500, detail="Password reset failed")

@app.post("/users/logout")
def logout_user(
    username: str = Form(...),
    email: str = Form(...),
    token_info: dict = Depends(require_keycloak_auth),
):
    """Kill the user's sessions in both systems (Auth0 also revokes grants). Protected."""
    if user_manager is None:
        raise HTTPException(status_code=503,
                            detail="User management is unavailable (Auth0 not configured).")
    try:
        return user_manager.logout_everywhere(username, email)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("Logout failed: %s", exc)
        raise HTTPException(status_code=500, detail="Logout failed")

@app.get("/keys")
def get_keys():
    if not public_pem:
        raise HTTPException(status_code=503, detail="Keys not yet initialised")
    return {"public_key": public_pem.decode("utf-8")}


# ── GitHub relay over WebSocket ────────────────────────────────────────────────
GITHUB_API = "https://api.github.com"
# Only these resource shapes are allowed, so a client can't drive the server to
# fetch arbitrary URLs (SSRF guard). Each maps to a GitHub REST path builder.
_GITHUB_ROUTES = {
    "repo":      lambda p: f"/repos/{p['owner']}/{p['repo']}",
    "issues":    lambda p: f"/repos/{p['owner']}/{p['repo']}/issues",
    "user":      lambda p: f"/users/{p['username']}",
}


def fetch_github(resource: str, params: dict) -> dict:
    """
    Fetch an allow-listed GitHub resource. Returns a dict with 'status' and
    'data'. Never raises for HTTP errors — the status is returned to the client.
    Kept synchronous and small so it's easy to unit-test with `responses`.
    """
    builder = _GITHUB_ROUTES.get(resource)
    if builder is None:
        return {"status": 400, "error": f"unknown resource '{resource}'"}
    try:
        path = builder(params)
    except (KeyError, TypeError):
        return {"status": 400, "error": f"missing parameters for resource '{resource}'"}
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "keycloak-auth0-broker"}
    # Optional token lifts rate limits / allows private repos; never required.
    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"
    try:
        resp = requests.get(f"{GITHUB_API}{path}", headers=headers, timeout=10)
    except requests.RequestException as exc:
        return {"status": 502, "error": f"GitHub request failed: {exc}"}
    try:
        data = resp.json()
    except ValueError:
        data = None
    return {"status": resp.status_code, "data": data}


@app.websocket("/ws/github")
async def github_ws(websocket: WebSocket):
    """
    Authenticated WebSocket GitHub relay.

    Handshake: the client's FIRST message must be JSON {"token": "<keycloak
    access token>"}. The token is validated via Keycloak introspection (same
    rules as the HTTP endpoints). On success the server replies
    {"type": "auth_ok"}; on failure it sends {"type": "auth_error"} and closes.

    Thereafter each client message is {"resource": "...", "params": {...}} and
    the server responds with {"type": "result", ...} carrying GitHub's status
    and data. Unknown resources return a 400-style result rather than closing.
    """
    await websocket.accept()
    # 1. Authenticate on the first frame.
    try:
        raw = await websocket.receive_text()
        hello = json.loads(raw)
        token = hello.get("token", "")
    except (WebSocketDisconnect, json.JSONDecodeError, AttributeError):
        await websocket.close(code=1008)
        return
    try:
        _introspect_token(token)
    except HTTPException:
        # Don't leak whether it was 401 vs 503 over the socket; just refuse.
        try:
            await websocket.send_json({"type": "auth_error",
                                       "detail": "authentication failed"})
        finally:
            await websocket.close(code=1008)
        return
    await websocket.send_json({"type": "auth_ok"})

    # 2. Serve requests until the client disconnects.
    try:
        while True:
            msg = await websocket.receive_text()
            try:
                req = json.loads(msg)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "detail": "invalid JSON"})
                continue
            resource = req.get("resource")
            params = req.get("params") or {}
            if not isinstance(params, dict):
                await websocket.send_json({"type": "error",
                                           "detail": "'params' must be an object"})
                continue
            result = fetch_github(resource, params)
            await websocket.send_json({"type": "result", **result})
    except WebSocketDisconnect:
        return


if __name__ == "__main__":
    import uvicorn  # I4 FIX: lazy import — only needed when run directly
    uvicorn.run(
        app,
        # B104 fix: bind loopback by default for local runs; the container
        # opts into all interfaces explicitly via ENV HOST=0.0.0.0.
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000"))
    )
