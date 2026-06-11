import logging
import os
import stat
import tempfile
from contextlib import asynccontextmanager

from argon2 import PasswordHasher
from argon2.exceptions import HashingError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.security import HTTPBearer
from authorize import router as auth0_router, oauth2_scheme
from keycloak import KeycloakOpenID, KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    global keycloak_oidc
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
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(auth0_router)

http_bearer     = HTTPBearer()
password_hasher = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8,
                                  hash_len=32, salt_len=16)

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
def protected_route(credentials=Depends(http_bearer)):
    if keycloak_oidc is None:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    try:
        token_info = keycloak_oidc.introspect(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    if not token_info.get("active"):
        raise HTTPException(status_code=401, detail="Token is inactive or expired")
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
def register(username: str = Form(...), password: str = Form(...)):
    try:
        hashed_password = password_hasher.hash(password)
    except HashingError:
        raise HTTPException(status_code=500, detail="Registration failed")
    # Persist username + hashed_password to your database here
    return {"message": f"User {username} registered successfully!"}

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
