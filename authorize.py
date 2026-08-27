# authorize.py — Auth0 + Azure Key Vault helpers
# Integrates with main.py (Keycloak).

import logging
import os
import threading
from datetime import datetime, timezone, timedelta

import requests
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwk, jwt
from jose.exceptions import ExpiredSignatureError
from pydantic import BaseModel

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class TokenData(BaseModel):
    username: str | None = None

ALGORITHM = "HS256"

def verify_token(token: str) -> TokenData:
    """Verify a locally-issued HS256 token."""
    secret_key = os.getenv("SECRET_KEY", "change-me-in-production")
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username: str | None = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenData(username=username)

def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenData:
    return verify_token(token)

# ── Azure Key Vault — thread-safe singleton ───────────────────────────────────
_kv_client: SecretClient | None = None
_kv_lock = threading.Lock()

def _get_kv_client() -> SecretClient:
    global _kv_client
    with _kv_lock:
        if _kv_client is None:
            vault_url = os.getenv("KEY_VAULT_URL", "https://your-keyvault-name.vault.azure.net/")
            _kv_client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    return _kv_client

def _openbao_first_names() -> set[str]:
    """
    Names of secrets that should be read from OpenBao FIRST (Key Vault remains
    the fallback). Opt-in via env, comma-separated:

        OPENBAO_SECRETS=AUTH0_AUDIENCE            # pilot one secret
        OPENBAO_SECRETS=AUTH0_AUDIENCE,AUTH0_CLIENT_ID
        OPENBAO_SECRETS=*                         # all secrets

    Default is EMPTY, so behaviour is byte-for-byte what it was before OpenBao
    existed. This makes the migration incremental and instantly reversible:
    remove the name from the env var and you are back on Key Vault.
    """
    raw = os.environ.get("OPENBAO_SECRETS", "").strip()
    if not raw:
        return set()
    return {p.strip() for p in raw.split(",") if p.strip()}


def _try_openbao(secret_name: str) -> str | None:
    """
    Attempt to read `secret_name` from OpenBao. Returns None (never raises) if
    OpenBao is disabled/unreachable or the read fails, so Key Vault can take
    over — a secret store being down must not become a new single point of
    failure.
    """
    try:
        # features is consulted first so OPENBAO_MODE=off short-circuits without
        # any network call, and OPENBAO_MODE=auto self-disables when OpenBao
        # isn't running instead of paying a timeout on every lookup.
        from features import openbao_state
        state = openbao_state()
        if not state.enabled:
            logger.debug("OpenBao lookup for '%s' skipped: %s",
                         secret_name, state.reason)
            return None
        # Imported lazily: keeps the OpenBao dependency off the hot path and
        # avoids a circular import (openbao_connect.resolve_secret imports this
        # module for its own Key Vault fallback).
        from openbao_connect import OpenBaoSecrets
        value = OpenBaoSecrets().get_secret(secret_name)
        if value:
            logger.info("Secret '%s' resolved from OpenBao", secret_name)
            return value
        return None
    except Exception as exc:  # noqa: BLE001 — fall back to Key Vault
        logger.warning("OpenBao lookup for '%s' failed (%s); "
                       "falling back to Key Vault", secret_name, exc)
        return None


def get_secret(secret_name: str) -> str:
    # OpenBao-first, opt-in per secret name (see _openbao_first_names). When the
    # name isn't opted in, or OpenBao isn't configured/available, this falls
    # straight through to the original Key Vault path below.
    wanted = _openbao_first_names()
    if secret_name in wanted or "*" in wanted:
        value = _try_openbao(secret_name)
        if value is not None:
            return value

    # R3 FIX: Azure Key Vault secret names allow only [0-9a-zA-Z-]. Callers use
    # env-style names (AUTH0_CLIENT_SECRET); map underscores to hyphens so the
    # KV object name is valid (stored as AUTH0-CLIENT-SECRET by convention).
    kv_name = secret_name.replace("_", "-")
    try:
        value = _get_kv_client().get_secret(kv_name).value
    except AzureError as exc:
        logger.error("Key Vault secret '%s' could not be retrieved: %s", secret_name, exc)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Secret store unavailable")
    if value is None:
        logger.error("Key Vault secret '%s' exists but has no value", secret_name)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Secret store unavailable")
    return value

# ── Auth0 M2M token — cached to avoid 4 external calls per request (I2 FIX) ──
_auth0_token_cache: str | None = None
_auth0_token_expiry: datetime = datetime.min.replace(tzinfo=timezone.utc)
_auth0_token_lock = threading.Lock()

def authenticate_with_auth0(client_id: str, client_secret: str, audience: str) -> tuple[str, int]:
    """
    Exchange client credentials for an Auth0 M2M access token.
    Returns (access_token, expires_in_seconds).
    """
    domain    = os.getenv("AUTH0_DOMAIN", "your-auth0-domain")
    token_url = f"https://{domain}/oauth/token"
    payload   = {
        "client_id":     client_id,
        "client_secret": client_secret,
        "audience":      audience,
        "grant_type":    "client_credentials",
    }
    try:
        response = requests.post(token_url, json=payload, timeout=10)
    except requests.RequestException as exc:
        logger.error("Auth0 token request failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Auth0 service unavailable")
    if response.status_code != 200:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authentication with Auth0 failed",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        body  = response.json()
        token = body.get("access_token")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY,
                            detail="Auth0 returned an unexpected response")
    if not token:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY,
                            detail="Auth0 returned no access token")
    return token, int(body.get("expires_in", 86400))

def get_auth0_token() -> str:
    """
    I2 FIX: Return a cached Auth0 M2M token, refreshing only when near expiry.
    Previously fetched 3 Key Vault secrets + 1 Auth0 token on every request.
    Now fetches once and reuses until 60 s before expiry.
    """
    global _auth0_token_cache, _auth0_token_expiry
    with _auth0_token_lock:
        if _auth0_token_cache is None or datetime.now(timezone.utc) >= _auth0_token_expiry:
            client_id     = get_secret("AUTH0_CLIENT_ID")
            client_secret = get_secret("AUTH0_CLIENT_SECRET")
            audience      = get_secret("AUTH0_AUDIENCE")
            token, expires_in = authenticate_with_auth0(client_id, client_secret, audience)
            _auth0_token_cache  = token
            _auth0_token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)
        return _auth0_token_cache

# ── Auth0 token verification — cached JWKS with rotation support ──────────────
_jwks_cache: dict | None = None
_jwks_lock  = threading.RLock()

def _fetch_jwks(domain: str) -> dict:
    try:
        resp = requests.get(f"https://{domain}/.well-known/jwks.json", timeout=10)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("Failed to fetch Auth0 JWKS: %s", exc)
        raise RuntimeError(f"Could not fetch Auth0 JWKS: {exc}") from exc
    try:
        return resp.json()
    except ValueError as exc:
        raise RuntimeError("Auth0 JWKS endpoint returned a non-JSON response") from exc

def _get_jwks(domain: str) -> dict:
    global _jwks_cache
    with _jwks_lock:
        if _jwks_cache is None:
            _jwks_cache = _fetch_jwks(domain)
        return _jwks_cache

def _get_signing_key(domain: str, token: str):
    global _jwks_cache
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid token header",
                            headers={"WWW-Authenticate": "Bearer"})
    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token is missing a kid header",
                            headers={"WWW-Authenticate": "Bearer"})
    for attempt in range(2):
        try:
            jwks = _get_jwks(domain)
        except RuntimeError:
            raise HTTPException(status_code=503, detail="Auth0 service unavailable")
        for key_data in jwks.get("keys", []):
            if key_data.get("kid") == kid:
                try:
                    return jwk.construct(key_data)
                except JWTError as exc:
                    raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY,
                                        detail=f"Invalid signing key from Auth0: {exc}")
        if attempt == 0:
            with _jwks_lock:
                _jwks_cache = None
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Unable to find signing key",
                        headers={"WWW-Authenticate": "Bearer"})

def verify_auth0_token(token: str) -> dict:
    """Validate an Auth0 JWT (RS256) using cached JWKS."""
    domain      = os.getenv("AUTH0_DOMAIN", "your-auth0-domain")
    audience    = get_secret("AUTH0_AUDIENCE")
    signing_key = _get_signing_key(domain, token)
    try:
        return jwt.decode(token, signing_key, algorithms=["RS256"],
                          audience=audience, issuer=f"https://{domain}/")
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Auth0 token has expired",
                            headers={"WWW-Authenticate": "Bearer"})
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Invalid Auth0 token: {exc}",
                            headers={"WWW-Authenticate": "Bearer"})

# Make sure it authorizes the user and also that we can get an Auth0 M2M token (used for downstream calls).
def get_current_user_with_auth0(token: str = Depends(oauth2_scheme)) -> dict:
    """Verify the Auth0 token and ensure we can obtain an Auth0 M2M token."""
    payload = verify_auth0_token(token)
    try:
        get_auth0_token()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error obtaining Auth0 token: %s", exc)
        raise HTTPException(status_code=503, detail="Could not reach Auth0")
    return payload

# ── Router ────────────────────────────────────────────────────────────────────
router = APIRouter()

@router.get("/secure-data")
def read_secure_data(current_user: TokenData = Depends(get_current_user)):
    """Keycloak-protected endpoint; verifies an Auth0 M2M token is obtainable."""
    try:
        # Confirm we can obtain an Auth0 M2M token (used for downstream Auth0
        # calls). Assign to a clearly-named var to signal it's intentionally
        # fetched here; wire real downstream calls in below.
        get_auth0_token()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error obtaining Auth0 token: %s", exc)
        raise HTTPException(status_code=503, detail="Could not reach Auth0")
    return {"message": "This is secure data", "user": current_user.username}


@router.get("/auth0/whoami")
def auth0_whoami(payload: dict = Depends(get_current_user_with_auth0)):
    """Auth0-token-protected endpoint: accepts an Auth0-issued RS256 token
    (validated via JWKS) and confirms the broker can also obtain its own Auth0
    M2M token for downstream calls. Returns the verified subject. This is the
    real use of get_current_user_with_auth0 — the Auth0 counterpart to the
    Keycloak-guarded routes."""
    return {"sub": payload.get("sub"), "aud": payload.get("aud")}
