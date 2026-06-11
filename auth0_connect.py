# auth0_connect.py
# Makes Auth0 talk to Keycloak by registering Auth0 as an OIDC Identity Provider
# inside Keycloak, and sets up social connections (Google, Facebook, etc.) in Auth0.
# Integrates with main.py and authorize.py.

from __future__ import annotations

import logging
import os
import ipaddress
import stat
from datetime import datetime, timezone, timedelta
from urllib.parse import quote  # I5 FIX: for percent-encoding redirect_uri in URLs

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional; set env vars manually if not installed

try:
    import requests
except ImportError:
    import json as _json
    from urllib import request as _urlreq, error as _error

    class _RequestsException(Exception):
        """Stand-in for requests.RequestException in the urllib fallback."""
        pass

    class _Response:
        def __init__(self, status: int, body: str, headers: dict | None = None):
            self.status_code = status
            self.text = body
            self.headers = headers or {}

        @property
        def ok(self) -> bool:
            return 200 <= self.status_code < 300

        def raise_for_status(self) -> None:
            if not self.ok:
                raise _RequestsException(f"HTTP {self.status_code}: {self.text}")

        def json(self) -> dict:
            try:
                return _json.loads(self.text) if self.text else {}
            except ValueError as exc:
                raise ValueError("Response body is not valid JSON") from exc

    class _RequestsFallback:
        RequestException = _RequestsException

        @staticmethod
        def _send(method: str, url: str, **kwargs) -> _Response:
            import json as _j
            # I1 FIX: copy headers explicitly so the caller's dict is never mutated
            headers: dict = {**(kwargs.get("headers") or {})}
            json_body = kwargs.get("json")
            data = kwargs.get("data")

            if json_body is not None:
                body = _j.dumps(json_body).encode()
                headers.setdefault("Content-Type", "application/json")
            elif data is not None:
                from urllib import parse as _p
                body = (
                    _p.urlencode(data).encode()
                    if isinstance(data, dict)
                    else str(data).encode()
                )
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                body = None

            req = _urlreq.Request(url, data=body, headers=headers, method=method.upper())
            try:
                with _urlreq.urlopen(req, timeout=kwargs.get("timeout")) as resp:
                    return _Response(
                        resp.getcode(),
                        resp.read().decode(),
                        dict(resp.getheaders()),
                    )
            except _error.HTTPError as exc:
                body_text = exc.read().decode() if hasattr(exc, "read") else ""
                return _Response(getattr(exc, "code", 500), body_text)
            except _error.URLError as exc:
                raise _RequestsException(str(exc)) from exc

        @classmethod
        def get(cls, url: str, **kwargs) -> _Response:
            return cls._send("GET", url, **kwargs)

        @classmethod
        def post(cls, url: str, **kwargs) -> _Response:
            return cls._send("POST", url, **kwargs)

        @classmethod
        def request(cls, method: str, url: str, **kwargs) -> _Response:
            return cls._send(method, url, **kwargs)

    requests = _RequestsFallback()

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
        """Return a valid M2M token, refreshing automatically when near expiry."""
        if self._token is None or datetime.now(timezone.utc) >= self._token_expiry:
            self._token, self._token_expiry = self._fetch_token()
        return self._token

    def _fetch_token(self) -> tuple[str, datetime]:
        """Fetch a fresh M2M token from Auth0."""
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

    def create_connection(self, name: str, strategy: str) -> dict:
        """
        Create a social or enterprise connection in Auth0.
        Valid strategies: 'google-oauth2', 'facebook', 'github', etc.
        'auth0' is NOT valid — it is the built-in database and cannot be created via API.
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
        """Retrieve an existing Auth0 client by display name."""
        result = self._api("GET", "clients")
        clients = result if isinstance(result, list) else []
        return next((c for c in clients if c.get("name") == name), None)


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
    Returns (cert_path, key_path).
    """
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
    Tries the Keycloak 17+ path first, falls back to the pre-17 legacy path.
    """
    base = keycloak_url.rstrip("/")
    last_error: str = ""
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
            last_error = response.text
            continue
        raise RuntimeError(
            f"Keycloak IdP registration returned {response.status_code}: {response.text}"
        )

    raise RuntimeError(
        f"Keycloak realm '{realm_name}' not found at {base}. "
        f"Check KEYCLOAK_URL and realm name. Last error: {last_error}"
    )


def test_login_flow(auth0: Auth0Connect, redirect_uri: str | None = None) -> str:
    """Return the Auth0 authorization URL to initiate an Authorization Code flow."""
    if redirect_uri is None:
        redirect_uri = os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:8080/callback")
    auth_url = (
        f"https://{auth0.domain}/authorize"
        f"?response_type=code"
        f"&client_id={auth0.client_id}"
        f"&redirect_uri={quote(redirect_uri, safe='')}"  # I5 FIX: percent-encode the URI
        f"&scope=openid%20profile%20email"               # I5 FIX: encode spaces in scope too
    )
    logger.info("Authorization URL: %s", auth_url)
    return auth_url


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    domain               = os.environ["AUTH0_DOMAIN"]
    client_id            = os.environ["AUTH0_CLIENT_ID"]
    client_secret        = os.environ["AUTH0_CLIENT_SECRET"]
    keycloak_admin_token = os.environ["KEYCLOAK_ADMIN_TOKEN"]

    keycloak_url      = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    auth0_callback    = os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:8080/callback")
    realm_name        = os.environ.get("KEYCLOAK_REALM", "Premkey")
    keycloak_callback = os.environ.get(
        "KEYCLOAK_REDIRECT_URI",
        f"http://localhost:8080/realms/{realm_name}/broker/auth0/endpoint",
    )

    auth0 = Auth0Connect(domain, client_id, client_secret)
    logger.info("Auth0 instance created for domain: %s", domain)
    test_token_access(auth0)

    for strategy in ("google-oauth2", "facebook"):
        conn = auth0.create_connection(f"keycloak-{strategy}", strategy)
        logger.info("Connection created: %s", conn.get("name"))

    client = auth0.create_client("keycloak-oidc-client", callbacks=[keycloak_callback])
    logger.info("Client created: %s (client_id: %s)", client.get("name"), client.get("client_id"))

    create_server_certificate(hostname=domain, cert_path="server.crt", key_path="server.key")

    integrate_with_keycloak(
        auth0,
        keycloak_url=keycloak_url,
        realm_name=realm_name,
        keycloak_admin_token=keycloak_admin_token,
        oidc_client_id=client.get("client_id", ""),
        oidc_client_secret=client.get("client_secret", ""),
    )

    found = auth0.get_client_by_name("keycloak-oidc-client")
    if found:
        logger.info("Client verified: %s", found.get("client_id"))
    else:
        logger.warning("Client 'keycloak-oidc-client' not found after creation")

    logger.info("Integration complete!")
    logger.info("Test login URL: %s", test_login_flow(auth0, auth0_callback))
    