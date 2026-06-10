# auth0_connect.py
# Makes Auth0 talk to Keycloak by registering Auth0 as an OIDC Identity Provider
# inside Keycloak, and sets up social connections (Google, Facebook, etc.) in Auth0.
# Integrates with main.py and authorize.py.

# G5 FIX: from __future__ must be the very first statement after the docstring
from __future__ import annotations

import logging
import os
import ipaddress
import stat
from datetime import datetime, timezone, timedelta

# Load .env file before reading any os.environ values
from dotenv import load_dotenv  # from python-dotenv package
load_dotenv()

# ──────────────────────────────────────────────
# requests — use the real library; fall back to urllib only when unavailable.
# G1 FIX: _RequestsFallback now defines RequestException so that
#         `except requests.RequestException` works identically in both paths.
# G2 FIX: _RequestsFallback now implements request() so _api() works.
# G3 FIX: _Response now implements raise_for_status().
# G4 FIX: _Response now implements the ok property.
# ──────────────────────────────────────────────
try:
    import requests
    from requests import RequestException  # noqa: F401 — re-exported for callers
except ImportError:  # pragma: no cover
    import json as _json
    from urllib import request as _urlreq, error as _error

    class _Response:
        def __init__(self, status: int, body: str, headers: dict | None = None):
            self.status_code = status
            self.text = body
            self.headers = headers or {}

        @property
        def ok(self) -> bool:                          # G4 FIX
            return 200 <= self.status_code < 300

        def raise_for_status(self) -> None:            # G3 FIX
            if not self.ok:
                raise _RequestsFallback.RequestException(
                    f"HTTP {self.status_code}: {self.text}"
                )

        def json(self) -> dict:
            try:
                return _json.loads(self.text) if self.text else {}
            except ValueError as exc:
                raise ValueError("Response body is not valid JSON") from exc

    class _RequestsFallback:
        class RequestException(Exception):            # G1 FIX: exception class on the object
            pass

        @staticmethod
        def _send(method: str, url: str, **kwargs) -> _Response:
            import json as _j
            headers: dict = kwargs.get("headers", {})
            json_body = kwargs.get("json")
            data = kwargs.get("data")

            if json_body is not None:
                body = _j.dumps(json_body).encode()
                headers.setdefault("Content-Type", "application/json")
            elif data is not None:
                from urllib import parse as _p
                body = _p.urlencode(data).encode() if isinstance(data, dict) else str(data).encode()
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                body = None

            req = _urlreq.Request(url, data=body, headers=headers, method=method.upper())
            try:
                with _urlreq.urlopen(req, timeout=kwargs.get("timeout")) as resp:
                    return _Response(resp.getcode(), resp.read().decode(), dict(resp.getheaders()))
            except _error.HTTPError as exc:
                body_text = exc.read().decode() if hasattr(exc, "read") else ""
                return _Response(getattr(exc, "code", 500), body_text)
            except _error.URLError as exc:
                raise _RequestsFallback.RequestException(str(exc)) from exc

        @classmethod
        def get(cls, url: str, **kwargs) -> _Response:
            return cls._send("GET", url, **kwargs)

        @classmethod
        def post(cls, url: str, **kwargs) -> _Response:
            return cls._send("POST", url, **kwargs)

        @classmethod
        def request(cls, method: str, url: str, **kwargs) -> _Response:  # G2 FIX
            return cls._send(method, url, **kwargs)

    requests = _RequestsFallback()

# ──────────────────────────────────────────────
# cryptography — G6 FIX: fail loudly with a clear ImportError message
# instead of silently passing and crashing later with NameError.
# ──────────────────────────────────────────────
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)


class Auth0Connect:
    def __init__(self, domain: str, client_id: str, client_secret: str):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: str | None = None
        self._token_expiry: datetime = datetime.min.replace(tzinfo=timezone.utc)

    @property
    def token(self) -> str:
        """Return a valid M2M token, refreshing if expired or absent."""
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
        try:
            response = requests.post(url, json=data, timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Auth0 token request failed: {exc}") from exc

        if response.status_code != 200:
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

    def _api(self, method: str, path: str, **kwargs) -> dict:
        """Centralised Auth0 Management API helper with auth header and error checking."""
        url = f"https://{self.domain}/api/v2/{path.lstrip('/')}"
        headers = {
            "content-type":  "application/json",
            "authorization": f"Bearer {self.token}",
        }
        try:
            response = requests.request(method, url, headers=headers, timeout=10, **kwargs)
        except requests.RequestException as exc:
            raise RuntimeError(f"Auth0 API request to {path} failed: {exc}") from exc

        if not response.ok:
            raise RuntimeError(
                f"Auth0 API {method} {path} returned {response.status_code}: {response.text}"
            )
        try:
            return response.json()
        except ValueError:
            return {}

    def create_connection(self, name: str, strategy: str) -> dict:
        """
        Create a social or enterprise connection in Auth0.
        Valid strategies: 'google-oauth2', 'facebook', 'github', etc.
        Note: 'auth0' is NOT valid here — it is the built-in database.
        """
        return self._api("POST", "connections", json={"name": name, "strategy": strategy})

    def create_client(self, name: str, callbacks: list[str] | None = None) -> dict:
        """Register a new application client in Auth0."""
        if callbacks is None:
            callbacks = [os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:8080/callback")]
        return self._api("POST", "clients", json={
            "name":        name,
            "app_type":    "regular_web",
            "grant_types": ["authorization_code", "refresh_token"],
            "callbacks":   callbacks,
        })

    def get_client_by_name(self, name: str) -> dict | None:
        """Retrieve an existing Auth0 client by its display name."""
        clients = self._api("GET", "clients")
        if isinstance(clients, list):
            return next((c for c in clients if c.get("name") == name), None)
        return None


def test_token_access(auth0: Auth0Connect) -> None:
    """Verify the M2M token works against the Auth0 Management API."""
    token = auth0.token
    logger.info("Access token obtained (first 20 chars): %s...", token[:20])
    try:
        response = requests.get(
            f"https://{auth0.domain}/api/v2/clients",
            headers={"authorization": f"Bearer {token}"},
            timeout=10,
        )
        response.raise_for_status()
        clients = response.json()
        client_count = len(clients) if isinstance(clients, list) else 1
        logger.info("API response: %d clients returned", client_count)
    except requests.RequestException as exc:
        raise RuntimeError(f"test_token_access failed: {exc}") from exc


def create_server_certificate(
    hostname: str,
    cert_path: str = "server.crt",
    key_path: str = "server.key",
    days_valid: int = 365,
) -> tuple[str, str]:
    """
    Generate a self-signed TLS certificate for development/testing.
    WARNING: self-signed certificates must NOT be used in production.
    Returns (cert_path, key_path).
    """
    # G6 FIX: raise clearly instead of crashing later with NameError
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "The 'cryptography' package is required for certificate generation. "
            "Install it with: pip install cryptography"
        )

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
    Tries the Keycloak 17+ path first, falls back to the legacy path.
    """
    base = keycloak_url.rstrip("/")
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
        if response.status_code == 404 and path_prefix == "/admin/realms":
            continue  # retry with legacy path
        raise RuntimeError(
            f"Keycloak IdP registration returned {response.status_code}: {response.text}"
        )


def test_login_flow(auth0: Auth0Connect) -> str:
    """Return the Auth0 authorization URL to initiate an Authorization Code flow."""
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


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_CLIENT_ID")
    client_secret = os.environ.get("AUTH0_CLIENT_SECRET")
    if not all([domain, client_id, client_secret]):
        raise RuntimeError(
            "Missing required environment variables. Please set: "
            "AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET"
        )

    auth0 = Auth0Connect(domain, client_id, client_secret)
    test_token_access(auth0)

    for strategy in ("google-oauth2", "facebook"):
        conn = auth0.create_connection(f"keycloak-{strategy}", strategy)
        logger.info("Connection created: %s", conn.get("name"))

    keycloak_callback = os.environ.get(
        "KEYCLOAK_REDIRECT_URI",
        "http://localhost:8080/realms/Premkey/broker/auth0/endpoint",
    )
    client = auth0.create_client("keycloak-oidc-client", callbacks=[keycloak_callback])
    logger.info("Client created: %s (client_id: %s)", client.get("name"), client.get("client_id"))

    create_server_certificate(hostname=domain, cert_path="server.crt", key_path="server.key")

    keycloak_admin_token = os.environ["KEYCLOAK_ADMIN_TOKEN"]
    integrate_with_keycloak(
        auth0,
        keycloak_url=os.environ.get("KEYCLOAK_URL", "http://localhost:8080"),
        realm_name="Premkey",
        keycloak_admin_token=keycloak_admin_token,
        oidc_client_id=client.get("client_id", ""),
        oidc_client_secret=client.get("client_secret", ""),
    )

    found = auth0.get_client_by_name("keycloak-oidc-client")
    if found:
        logger.info("Keycloak OIDC client confirmed: %s", found.get("client_id"))
    else:
        logger.warning("Keycloak OIDC client 'keycloak-oidc-client' not found after creation")

    logger.info("To test login, open: %s", test_login_flow(auth0))
