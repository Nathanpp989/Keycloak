import logging
import os
import stat
import tempfile
from contextlib import asynccontextmanager

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.security import HTTPBearer
from authorize import router as auth0_router, oauth2_scheme
from keycloak import KeycloakOpenID, KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError

# User-flow integration (auth0_connect.py / auth0_talk.py / auth0_type.py)
from auth0_connect import Auth0Connect, get_keycloak_admin_token
from auth0_talk import KeycloakAdminAPI, Auth0UsersAPI
from auth0_type import UserManager

# I3 FIX: configure logging before anything else so all logger.* calls produce output
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

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
    KEY_DIR = os.environ.get("KEY_DIR", "/tmp/keys")
    os.makedirs(KEY_DIR, exist_ok=True)
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

def setup_keycloak():
    admin = KeycloakAdmin(
        server_url=os.environ.get("KEYCLOAK_URL", "http://localhost:8080/"),
        username=os.environ.get("KEYCLOAK_ADMIN_USER", "admin"),
        password=os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
        realm_name="Premkey",
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
    client_uuid     = admin.get_client_id("Hello-World-app")
    existing_secret = admin.get_client_secrets(client_uuid)
    if existing_secret.get("value") is None:
        admin.create_client_secret(client_uuid)

# ── Lifespan ──────────────────────────────────────────────────────────────────
keycloak_oidc: KeycloakOpenID | None = None
user_manager: UserManager | None = None

def _build_user_manager() -> UserManager | None:
    """
    Wire up the UserManager from auth0_type using a fresh Keycloak admin token
    and an Auth0 M2M client. Returns None (with a warning) if the required
    Auth0 env vars are missing, so the rest of the app can still start.
    """
    keycloak_url = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    realm        = os.environ.get("KEYCLOAK_REALM", "Premkey")
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
    return UserManager(keycloak_api, auth0_users)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global keycloak_oidc, user_manager
    try:
        init_rsa_keys()
    except Exception as exc:
        logger.error("RSA key initialisation failed: %s", exc)
        raise
    try:
        setup_keycloak()
    except Exception as exc:
        logger.error("Keycloak setup failed — check KEYCLOAK_URL and credentials: %s", exc)
        raise
    keycloak_oidc = KeycloakOpenID(
        server_url=os.environ.get("KEYCLOAK_URL", "http://localhost:8080/"),
        client_id="Hello-World-app",
        realm_name="Premkey",
        client_secret_key=os.environ.get("KEYCLOAK_CLIENT_SECRET", "your-client-secret")
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
def require_keycloak_auth(credentials=Depends(http_bearer)) -> dict:
    """
    FastAPI dependency: validate the bearer token via Keycloak introspection.
    Returns the token info dict on success; raises 401/503 otherwise.
    Used to protect endpoints that must only be reachable by authenticated users.
    """
    if keycloak_oidc is None:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    try:
        token_info = keycloak_oidc.introspect(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    if not token_info.get("active"):
        raise HTTPException(status_code=401, detail="Token is inactive or expired")
    return token_info

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
        if not token_info.get("active"):
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

@app.get("/keys")
def get_keys():
    if not public_pem:
        raise HTTPException(status_code=503, detail="Keys not yet initialised")
    return {"public_key": public_pem.decode("utf-8")}

if __name__ == "__main__":
    import uvicorn  # I4 FIX: lazy import — only needed when run directly
    uvicorn.run(
        app,
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000"))
    )
