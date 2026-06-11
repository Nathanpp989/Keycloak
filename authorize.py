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

def get_secret(secret_name: str) -> str:
    try:
        value = _get_kv_client().get_secret(secret_name).value
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

# ── Router ────────────────────────────────────────────────────────────────────
router = APIRouter()

@router.get("/secure-data")
def read_secure_data(current_user: TokenData = Depends(get_current_user)):
    """Keycloak-protected endpoint; uses a cached Auth0 M2M token server-side."""
    try:
        _auth0_token = get_auth0_token()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error obtaining Auth0 token: %s", exc)
        raise HTTPException(status_code=503, detail="Could not reach Auth0")
    # Use _auth0_token here to call downstream Auth0-protected APIs
    return {"message": "This is secure data", "user": current_user.username}
