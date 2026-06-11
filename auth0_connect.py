# auth0_connect.py
# Registers Auth0 as an OIDC Identity Provider inside Keycloak and sets up
# social connections (Google, Facebook, etc.) in Auth0.
# Integrates with main.py and authorize.py.

from __future__ import annotations

import ipaddress
import logging
import os
import stat
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Optional: load a .env file from the current working directory if python-dotenv
# is installed. If not installed, environment variables must be set manually.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)


class Auth0Connect:
    def __init__(self, domain: str, client_id: str, client_secret: str):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: str | None = None
        self._token_expiry = datetime.min.replace(tzinfo=timezone.utc)

    @property
    def token(self) -> str:
        """Return a valid M2M token, refreshing automatically when near expiry."""
        if self._token is None or datetime.now(timezone.utc) >= self._token_expiry:
            self._token, self._token_expiry = self._fetch_token()
        return self._token

    def _fetch_token(self) -> tuple[str, datetime]:
        url = f"https://{self.domain}/oauth/token"
        payload = {
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "audience":      f"https://{self.domain}/api/v2/",
            "grant_type":    "client_credentials",
        }
        try:
            response = requests.post(url, json=payload, timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Auth0 token request failed: {exc}") from exc

        if not response.ok:
            raise RuntimeError(
                f"Auth0 token endpoint returned {response.status_code}: {response.text}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise RuntimeError("Auth0 token endpoint returned non-JSON response") from exc

        token = body.get("access_token")
        if not token:
            raise RuntimeError("Auth0 token response missing access_token")

        expires_in = int(body.get("expires_in", 86400))
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)
        return token, expiry

    def _api(self, method: str, path: str, **kwargs) -> dict | list:
        """Centralised Auth0 Management API helper."""
        url = f"https://{self.domain}/api/v2/{path.lstrip('/')}"
        headers = {
            "content-type":  "application/json",
            "authorization": f"Bearer {self.token}",
        }
        try:
            response = requests.request(method, url, headers=headers, timeout=10, **kwargs)
        except requests.RequestException as exc:
            raise RuntimeError(f"Auth0 API {method} {path} failed: {exc}") from exc

        if not response.ok:
            raise RuntimeError(
                f"Auth0 API {method} {path} returned {response.status_code}: {response.text}"
            )
        try:
            return response.json()
        except ValueError:
            return {}

    def get_connection_by_name(self, name: str) -> dict | None:
        """Retrieve an existing Auth0 connection by name (requires read:connections)."""
        result = self._api("GET", "connections")
        connections = result if isinstance(result, list) else []
        return next((c for c in connections if c.get("name") == name), None)

    def create_connection(self, name: str, strategy: str) -> dict:
        """
        Get-or-create a social connection in Auth0.
        Returns the existing connection if one with this name already exists,
        avoiding a 409 Conflict on repeated runs.
        Valid strategies: 'google-oauth2', 'facebook', 'github', etc.
        'auth0' is NOT valid here — it is the built-in database.
        """
        existing = self.get_connection_by_name(name)
        if existing:
            logger.info("Connection '%s' already exists; reusing it", name)
            return existing
        return self._api("POST", "connections", json={"name": name, "strategy": strategy})

    def get_client_by_name(self, name: str) -> dict | None:
        """Retrieve an existing Auth0 client by display name."""
        result = self._api("GET", "clients")
        clients = result if isinstance(result, list) else []
        return next((c for c in clients if c.get("name") == name), None)

    def create_client(self, name: str, callbacks: list[str]) -> dict:
        """
        Get-or-create an Auth0 application client.
        Returns the existing client if one with this name already exists,
        avoiding a 409 Conflict on repeated runs.
        """
        existing = self.get_client_by_name(name)
        if existing:
            logger.info("Client '%s' already exists; reusing it", name)
            return existing
        return self._api("POST", "clients", json={
            "name":        name,
            "app_type":    "regular_web",
            "grant_types": ["authorization_code", "refresh_token"],
            "callbacks":   callbacks,
        })


def test_token_access(auth0: Auth0Connect) -> None:
    """Verify the M2M token works against the Auth0 Management API."""
    result = auth0._api("GET", "clients")
    count = len(result) if isinstance(result, list) else 1
    logger.info("Token validated: %d client(s) visible", count)


def create_server_certificate(
    hostname: str,
    cert_path: str = "server.crt",
    key_path: str = "server.key",
    days_valid: int = 365,
) -> tuple[str, str]:
    """
    Generate a self-signed TLS certificate for development/testing.
    WARNING: self-signed certificates must NOT be used in production.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dev"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "US"),
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
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(key_bytes)
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 600 — owner only

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
    Tries the Keycloak 17+ path first, then the pre-17 legacy path.
    """
    base = keycloak_url.rstrip("/")
    last_error = ""
    for path_prefix in ("/admin/realms", "/auth/admin/realms"):
        url = f"{base}{path_prefix}/{realm_name}/identity-provider/instances"
        headers = {
            "content-type":  "application/json",
            "authorization": f"Bearer {keycloak_admin_token}",
        }
        data = {
            "alias":      "auth0",
            "providerId": "oidc",
            "enabled":    True,
            "config": {
                "clientId":          oidc_client_id,
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
        if response.status_code == 409:
            # IdP alias already exists — treat as success so re-runs don't fail
            logger.info("Auth0 IdP already exists in Keycloak; skipping creation")
            return
        if response.status_code == 404 and path_prefix == "/admin/realms":
            last_error = response.text
            continue
        raise RuntimeError(
            f"Keycloak IdP registration returned {response.status_code}: {response.text}"
        )

    raise RuntimeError(
        f"Keycloak realm '{realm_name}' not found at {base}. "
        f"Check KEYCLOAK_URL and realm name. Last error: {last_error}"
    )


def test_login_flow(auth0: Auth0Connect, redirect_uri: str) -> str:
    """Return the Auth0 authorization URL to initiate an Authorization Code flow."""
    auth_url = (
        f"https://{auth0.domain}/authorize"
        f"?response_type=code"
        f"&client_id={quote(auth0.client_id, safe='')}"
        f"&redirect_uri={quote(redirect_uri, safe='')}"
        f"&scope=openid%20profile%20email"
    )
    logger.info("Authorization URL: %s", auth_url)
    return auth_url


def _require_env(*names: str) -> dict[str, str]:
    """
    Read required environment variables, collecting ALL missing ones so the user
    sees a single clear message instead of crashing on the first KeyError.
    """
    values = {name: os.environ.get(name) for name in names}
    missing = [name for name, val in values.items() if not val]
    if missing:
        raise SystemExit(
            "Missing required environment variable(s): " + ", ".join(missing) + "\n"
            "Set them in your shell or in a .env file in the directory you run this from.\n"
            "Example:\n"
            "  export AUTH0_DOMAIN=your-tenant.us.auth0.com\n"
            "  export AUTH0_CLIENT_ID=...\n"
            "  export AUTH0_CLIENT_SECRET=...\n"
            "  export KEYCLOAK_ADMIN_TOKEN=...\n"
        )
    return values  # type: ignore[return-value]


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    # Collect all missing required vars at once with a clear, actionable message
    env = _require_env(
        "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "KEYCLOAK_ADMIN_TOKEN"
    )

    keycloak_url      = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    auth0_callback    = os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:8080/callback")
    realm_name        = os.environ.get("KEYCLOAK_REALM", "Premkey")
    keycloak_callback = os.environ.get(
        "KEYCLOAK_REDIRECT_URI",
        f"http://localhost:8080/realms/{realm_name}/broker/auth0/endpoint",
    )

    auth0 = Auth0Connect(env["AUTH0_DOMAIN"], env["AUTH0_CLIENT_ID"], env["AUTH0_CLIENT_SECRET"])
    logger.info("Auth0 instance created for domain: %s", env["AUTH0_DOMAIN"])
    test_token_access(auth0)

    for strategy in ("google-oauth2", "facebook"):
        conn = auth0.create_connection(f"keycloak-{strategy}", strategy)
        logger.info("Connection created: %s", conn.get("name"))

    client = auth0.create_client("keycloak-oidc-client", callbacks=[keycloak_callback])
    logger.info("Client created: %s (client_id: %s)", client.get("name"), client.get("client_id"))

    create_server_certificate(hostname=env["AUTH0_DOMAIN"])

    integrate_with_keycloak(
        auth0,
        keycloak_url=keycloak_url,
        realm_name=realm_name,
        keycloak_admin_token=env["KEYCLOAK_ADMIN_TOKEN"],
        oidc_client_id=client.get("client_id", "Hello-World-app"),
        oidc_client_secret=client.get("client_secret", "WzUyAZTUHOVadVszbi1AaS1idiU46P7y"),
    )

    found = auth0.get_client_by_name("keycloak-oidc-client")
    if found:
        logger.info("Client verified: %s", found.get("client_id"))
    else:
        logger.warning("Client 'keycloak-oidc-client' not found after creation")

    logger.info("Integration complete!")
    logger.info("Test login URL: %s", test_login_flow(auth0, auth0_callback))
