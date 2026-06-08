# auth0_connect.py
# Makes Auth0 talk to Keycloak by registering Auth0 as an OIDC Identity Provider
# inside Keycloak, and sets up social connections (Google, Facebook, etc.) in Auth0.
# Integrates with main.py and authorize.py.

import logging
import os
import ipaddress
from datetime import datetime, timezone, timedelta

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class Auth0Connect:
    def __init__(self, domain: str, client_id: str, client_secret: str):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        # F1 FIX: token is fetched lazily on first use, not in __init__.
        # Fetching in __init__ means any construction failure (network down,
        # bad credentials) raises during import rather than at call time, and
        # the token is never refreshed for the lifetime of the object.
        self._token: str | None = None
        self._token_expiry: datetime = datetime.min.replace(tzinfo=timezone.utc)

    @property
    def token(self) -> str:
        """Return a valid M2M token, refreshing if expired or absent."""
        # F2 FIX: tokens expire (Auth0 default: 86400 s). Refresh when within
        # 60 s of expiry instead of reusing a stale token forever.
        if self._token is None or datetime.now(timezone.utc) >= self._token_expiry:
            self._token, self._token_expiry = self._fetch_token()
        return self._token

    def _fetch_token(self) -> tuple[str, datetime]:
        """Fetch a fresh M2M token from Auth0 and return (token, expiry)."""
        url = f"https://{self.domain}/oauth/token"
        data = {
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "audience":      f"https://{self.domain}/api/v2/",
            "grant_type":    "client_credentials",
        }
        # F3 FIX: added timeout; original had none (could hang forever)
        try:
            response = requests.post(url, json=data, timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Auth0 token request failed: {exc}") from exc

        # F4 FIX: raise on non-200 instead of silently returning None token
        if response.status_code != 200:
            raise RuntimeError(
                f"Auth0 token endpoint returned {response.status_code}: {response.text}"
            )

        # F5 FIX: guard against non-JSON response (proxy/WAF HTML error pages)
        try:
            body = response.json()
        except ValueError as exc:
            raise RuntimeError("Auth0 token endpoint returned non-JSON response") from exc

        token = body.get("access_token")
        if not token:
            raise RuntimeError("Auth0 token response missing access_token")

        # F2 FIX: parse expires_in to know when to refresh
        expires_in = int(body.get("expires_in", 86400))
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)  # 60s buffer
        return token, expiry

    def _api(self, method: str, path: str, **kwargs) -> dict:
        """
        F6 FIX: centralised API helper.
        Original code duplicated headers and response handling in every method,
        and never checked response status codes — a failed API call silently
        returned an error dict that callers treated as a success.
        """
        url = f"https://{self.domain}/api/v2/{path.lstrip('/')}"
        headers = {
            "content-type":  "application/json",
            "authorization": f"Bearer {self.token}",
        }
        try:
            response = requests.request(method, url, headers=headers, timeout=10, **kwargs)
        except requests.RequestException as exc:
            raise RuntimeError(f"Auth0 API request to {path} failed: {exc}") from exc

        # F6 FIX: raise on error status codes
        if not response.ok:
            raise RuntimeError(
                f"Auth0 API {method} {path} returned {response.status_code}: {response.text}"
            )
        # F5 FIX: guard against non-JSON
        try:
            return response.json()
        except ValueError:
            return {}

    def create_connection(self, name: str, strategy: str) -> dict:
        """
        Create a social or enterprise connection in Auth0.
        Strategy examples: 'google-oauth2', 'facebook', 'github'.
        F7 FIX: 'auth0' is NOT a valid strategy for create_connection —
        it is the built-in Auth0 database and cannot be created via API.
        The original code passed "auth0" here, which always returns a 400 error.
        Use 'google-oauth2', 'facebook', etc. for social providers.
        """
        return self._api("POST", "connections", json={"name": name, "strategy": strategy})

    def create_client(self, name: str, callbacks: list[str] | None = None) -> dict:
        """
        Register a new application client in Auth0.
        F8 FIX: callbacks defaulted to hardcoded localhost — now a parameter.
        Localhost callbacks must NEVER be used in production.
        """
        if callbacks is None:
            callbacks = [os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:8080/callback")]
        return self._api("POST", "clients", json={
            "name":         name,
            "app_type":     "regular_web",
            "grant_types":  ["authorization_code", "refresh_token"],
            "callbacks":    callbacks,
        })

    def get_client_by_name(self, name: str) -> dict | None:
        """
        F9 FIX (new): integrate_with_keycloak needs the Auth0 client's
        client_id to configure the Keycloak IdP. The original code created a
        client but never retrieved or stored its ID, so the Keycloak IdP was
        always configured with the M2M client_id instead of the correct one.
        """
        clients = self._api("GET", "clients")
        if isinstance(clients, list):
            return next((c for c in clients if c.get("name") == name), None)
        return None


def test_token_access(auth0: Auth0Connect) -> None:
    """
    Verify the M2M token works against the Auth0 Management API.
    F3 FIX: timeout added to GET request.
    F6 FIX: response status checked.
    """
    token = auth0.token
    logger.info("Access token obtained (first 20 chars): %s...", token[:20])
    try:
        response = requests.get(
            f"https://{auth0.domain}/api/v2/clients",
            headers={"authorization": f"Bearer {token}"},
            timeout=10,
        )
        response.raise_for_status()
        logger.info("API response: %d clients returned", len(response.json()))
    except requests.RequestException as exc:
        raise RuntimeError(f"test_token_access failed: {exc}") from exc


def create_server_certificate(
    hostname: str,
    cert_path: str = "server.crt",
    key_path:  str = "server.key",
    days_valid: int = 365,
) -> tuple[str, str]:
    """
    Generate a self-signed TLS certificate for development/testing.
    F10 FIX: the original was a 'pass' stub with no implementation.
    Uses the cryptography library (already a dependency of the project).
    WARNING: self-signed certificates must NOT be used in production;
    use a CA-signed certificate (e.g. Let's Encrypt) instead.
    Returns (cert_path, key_path).
    """
    # Generate RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,         hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,   "Dev"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,        "US"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                # Also cover localhost and loopback for dev use
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # F11 FIX: private key file written with 600 permissions (owner-only)
    import stat
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(key_bytes)
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

    logger.info("Self-signed certificate written to %s / %s", cert_path, key_path)
    return cert_path, key_path


def integrate_with_keycloak(
    auth0: Auth0Connect,
    keycloak_url: str,
    realm_name: str,
    keycloak_admin_token: str,
    oidc_client_id: str,
    oidc_client_secret: str,
) -> None:
    """
    Register Auth0 as an OIDC Identity Provider inside Keycloak.

    F12 FIX: original used auth0.token (an Auth0 M2M token) in the Keycloak
    Authorization header. Keycloak's admin REST API requires a *Keycloak*
    admin bearer token, not an Auth0 token. These are tokens from completely
    different issuers and Keycloak will reject the Auth0 token with 401.
    The caller must obtain a Keycloak admin token first (e.g. via
    python-keycloak's KeycloakAdmin) and pass it as keycloak_admin_token.

    F13 FIX: original hardcoded auth0.client_id (the M2M app) as the OIDC
    client registered in Keycloak. That client is for server-to-server calls
    and was not created with authorization_code grant. The IdP must be
    configured with a dedicated OIDC client (oidc_client_id / oidc_client_secret)
    that has the authorization_code grant and the Keycloak redirect URI in its
    callbacks list.

    F14 FIX: Keycloak's admin API path changed in Keycloak 17+. The old
    '/auth/admin/realms/...' prefix was removed; the correct path is now
    '/admin/realms/...'. The original code used the legacy path unconditionally.
    """
    # Try the modern path first; fall back to legacy if needed
    base = keycloak_url.rstrip("/")
    for path_prefix in ("/admin/realms", "/auth/admin/realms"):
        url = f"{base}{path_prefix}/{realm_name}/identity-provider/instances"
        headers = {
            "content-type":  "application/json",
            "authorization": f"Bearer {keycloak_admin_token}",  # F12 FIX: Keycloak token
        }
        data = {
            "alias":      "auth0",
            "providerId": "oidc",
            "enabled":    True,
            "config": {
                "clientId":          oidc_client_id,      # F13 FIX: dedicated OIDC client
                "clientSecret":      oidc_client_secret,
                "authorizationUrl":  f"https://{auth0.domain}/authorize",
                "tokenUrl":          f"https://{auth0.domain}/oauth/token",
                "userInfoUrl":       f"https://{auth0.domain}/userinfo",
                "jwksUrl":           f"https://{auth0.domain}/.well-known/jwks.json",
                "issuer":            f"https://{auth0.domain}/",
                "defaultScope":      "openid profile email",
                "validateSignature": "true",
                "useJwksUrl":        "true",
            },
        }
        try:
            response = requests.post(url, headers=headers, json=data, timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Keycloak IdP registration failed: {exc}") from exc

        if response.status_code == 201:
            logger.info("Auth0 IdP registered in Keycloak at %s", url)
            return
        if response.status_code == 404 and path_prefix == "/admin/realms":
            # Modern path not found — retry with legacy prefix
            continue
        # F6 FIX: raise on unexpected status
        raise RuntimeError(
            f"Keycloak IdP registration returned {response.status_code}: {response.text}"
        )


def test_login_flow(auth0: Auth0Connect) -> str:
    """
    Return the Auth0 authorization URL to initiate an Authorization Code flow.
    The redirect, code exchange, and token validation happen in the web app
    (or can be simulated with Postman/curl).
    F15 FIX: original printed to stdout and took unused keycloak_url/realm_name
    parameters that played no role. Cleaned up to return the URL for callers
    to use.
    F8 note: redirect_uri must match a callback registered in the Auth0 client.
    """
    redirect_uri = os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:8080/callback")
    auth_url = (
        f"https://{auth0.domain}/authorize"
        f"?response_type=code"
        f"&client_id={auth0.client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=openid profile email"
    )
    logger.info("Authorization URL: %s", auth_url)
    return auth_url


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# F16 FIX: original ran create_connection("keycloak-connection", "auth0") which
# always fails — "auth0" is not a valid connection strategy (see F7).
# Replaced with a realistic sequence: create social connections, a dedicated
# OIDC client, generate a dev certificate, and register the Keycloak IdP.
# Credentials read from environment variables, never hardcoded (F17 FIX).
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s — %(message)s")

    # F17 FIX: all secrets from environment — never hardcoded in source
    domain        = os.environ["AUTH0_DOMAIN"]
    client_id     = os.environ["AUTH0_CLIENT_ID"]
    client_secret = os.environ["AUTH0_CLIENT_SECRET"]

    auth0 = Auth0Connect(domain, client_id, client_secret)

    # Verify M2M token works
    test_token_access(auth0)

    # Create social connections in Auth0
    for strategy in ("google-oauth2", "facebook"):
        conn = auth0.create_connection(f"keycloak-{strategy}", strategy)
        logger.info("Connection created: %s", conn.get("name"))

    # Create a dedicated OIDC client for Keycloak to use
    keycloak_callback = os.environ.get(
        "KEYCLOAK_REDIRECT_URI",
        "http://localhost:8080/realms/Premkey/broker/auth0/endpoint"
    )
    client = auth0.create_client("keycloak-oidc-client", callbacks=[keycloak_callback])
    logger.info("Client created: %s (client_id: %s)", client.get("name"), client.get("client_id"))

    # Generate a dev TLS certificate
    create_server_certificate(hostname=domain, cert_path="server.crt", key_path="server.key")

    # Register Auth0 as an IdP in Keycloak
    # The Keycloak admin token must be obtained separately (e.g. from KeycloakAdmin in main.py)
    keycloak_admin_token  = os.environ["KEYCLOAK_ADMIN_TOKEN"]
    oidc_client_id        = client.get("client_id", "")
    oidc_client_secret    = client.get("client_secret", "")
    integrate_with_keycloak(
        auth0,
        keycloak_url=os.environ.get("KEYCLOAK_URL", "http://localhost:8080"),
        realm_name="Premkey",
        keycloak_admin_token=keycloak_admin_token,
        oidc_client_id=oidc_client_id,
        oidc_client_secret=oidc_client_secret,
    )

    # Print the login URL to begin the Authorization Code flow
    login_url = test_login_flow(auth0)
    logger.info("To test login, open: %s", login_url)
