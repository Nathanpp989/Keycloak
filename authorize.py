# Pusedocode for an authorization module integrating Auth0 and Azure Key Vault, designed to work with a FastAPI application that uses Keycloak for authentication. The module includes functions for verifying locally-issued tokens, fetching secrets from Azure Key Vault, obtaining Auth0 M2M tokens, and verifying Auth0 JWTs using cached JWKS. It also defines a secure endpoint that requires a valid local token and demonstrates how to obtain an Auth0 token server-side without exposing it to the client.
# authorize.py — Auth0 + Azure Key Vault helpers
# Integrates with main.py (Keycloak).

import logging
import os
import threading
# C1 FIX: removed unused `from functools import lru_cache`

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

# ──────────────────────────────────────────────
# Shared OAuth2 scheme — defined ONCE here, imported by main.py
# ──────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ──────────────────────────────────────────────
# Token model
# ──────────────────────────────────────────────
class TokenData(BaseModel):
    username: str | None = None

# ──────────────────────────────────────────────
# Local HS256 token verification
# Only for locally-issued tokens — NOT Auth0 (those are RS256 via JWKS)
# ──────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM  = "HS256"

def verify_token(token: str) -> TokenData:
    """Verify a locally-issued HS256 token."""
    # C7 FIX: decode first, check claims outside the try/except so HTTPException
    # is never accidentally swallowed by the JWTError handler
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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

    # Claim checks live outside the try block
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

# ──────────────────────────────────────────────
# Azure Key Vault — thread-safe singleton
# ──────────────────────────────────────────────
_kv_client: SecretClient | None = None
_kv_lock = threading.Lock()

def _get_kv_client() -> SecretClient:
    global _kv_client
    with _kv_lock:
        if _kv_client is None:
            vault_url = os.getenv("KEY_VAULT_URL", "https://your-keyvault-name.vault.azure.net/")
            _kv_client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    return _kv_client

def get_secret(secret_name: str) -> str:
    try:
        value = _get_kv_client().get_secret(secret_name).value
    except AzureError as exc:
        logger.error("Key Vault secret '%s' could not be retrieved: %s", secret_name, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secret store unavailable",
        )
    if value is None:
        logger.error("Key Vault secret '%s' exists but has no value", secret_name)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secret store unavailable",
        )
    return value

# ──────────────────────────────────────────────
# Auth0 — M2M token acquisition
# C5 FIX: response.json() guarded against non-JSON bodies
# C4 FIX: audience sourced from Key Vault only (consistent with token minting)
# ──────────────────────────────────────────────
def authenticate_with_auth0(client_id: str, client_secret: str, audience: str) -> str:
    """Exchange client credentials for an Auth0 M2M access token."""
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
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth0 service unavailable",
        )
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication with Auth0 failed",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # C5 FIX: guard against non-JSON proxy/WAF error pages
    try:
        token = response.json().get("access_token")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Auth0 returned an unexpected response",
        )
    if not token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Auth0 returned no access token",
        )
    return token

def get_auth0_token() -> str:
    """Fetch Auth0 M2M token using credentials stored in Key Vault."""
    return authenticate_with_auth0(
        get_secret("AUTH0_CLIENT_ID"),
        get_secret("AUTH0_CLIENT_SECRET"),
        get_secret("AUTH0_AUDIENCE"),   # C4: single source of truth for audience
    )

# ──────────────────────────────────────────────
# Auth0 token verification — cached JWKS with rotation support
# C3 FIX: use RLock (reentrant) to prevent deadlock when the refresh path
#         re-enters the same lock via _get_jwks on attempt 1
# C6 FIX: _fetch_jwks raises RuntimeError (not HTTPException) — it's a utility,
#         not an endpoint; callers convert to HTTPException at the HTTP boundary
# C4 FIX: audience for verification also sourced from Key Vault
# ──────────────────────────────────────────────
_jwks_cache: dict | None = None
_jwks_lock  = threading.RLock()   # C3 FIX: RLock allows re-entry on same thread

def _fetch_jwks(domain: str) -> dict:
    """Fetch fresh JWKS from Auth0. Raises RuntimeError on failure (C6 FIX)."""
    try:
        resp = requests.get(f"https://{domain}/.well-known/jwks.json", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        logger.error("Failed to fetch Auth0 JWKS: %s", exc)
        raise RuntimeError(f"Could not fetch Auth0 JWKS: {exc}") from exc  # C6 FIX

def _get_jwks(domain: str) -> dict:
    """Return cached JWKS; fetch and cache if not yet loaded."""
    global _jwks_cache
    with _jwks_lock:
        if _jwks_cache is None:
            _jwks_cache = _fetch_jwks(domain)
        return _jwks_cache

def _get_signing_key(domain: str, token: str):
    """
    Extract the RSA public key matching the token's kid from JWKS.
    Refreshes the cache once on a kid miss to handle Auth0 key rotation.
    Uses RLock so the refresh path can re-enter _get_jwks safely (C3 FIX).
    """
    global _jwks_cache

    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    kid = unverified_header.get("kid")

    for attempt in range(2):
        try:
            jwks = _get_jwks(domain)   # safe on attempt 1 — RLock allows re-entry (C3)
        except RuntimeError:
            raise HTTPException(status_code=503, detail="Auth0 service unavailable")

        for key_data in jwks.get("keys", []):
            if key_data.get("kid") == kid:
                return jwk.construct(key_data)

        # kid not in cache — force a refresh once, then retry
        if attempt == 0:
            with _jwks_lock:
                _jwks_cache = None      # invalidate; _get_jwks will re-fetch on attempt 1

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unable to find signing key",
        headers={"WWW-Authenticate": "Bearer"},
    )

def verify_auth0_token(token: str) -> dict:
    """
    Validate an Auth0 JWT (RS256) using cached JWKS.
    Audience sourced from Key Vault for consistency with token minting (C4 FIX).
    """
    domain   = os.getenv("AUTH0_DOMAIN", "your-auth0-domain")
    # C4 FIX: use Key Vault as the single source of truth for audience
    try:
        audience = get_secret("AUTH0_AUDIENCE")
    except HTTPException:
        raise

    signing_key = _get_signing_key(domain, token)

    try:
        return jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=f"https://{domain}/",
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Auth0 token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Auth0 token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ──────────────────────────────────────────────
# Router
# ──────────────────────────────────────────────
router = APIRouter()

@router.get("/secure-data")
def read_secure_data(current_user: TokenData = Depends(get_current_user)):
    """
    Requires a valid local/Keycloak token. Obtains an Auth0 M2M token
    server-side only — never returned to the client.
    """
    try:
        _auth0_token = get_auth0_token()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error obtaining Auth0 token: %s", exc)
        raise HTTPException(status_code=503, detail="Could not reach Auth0")

    # Use _auth0_token here to call downstream Auth0-protected APIs
    return {"message": "This is secure data", "user": current_user.username}
