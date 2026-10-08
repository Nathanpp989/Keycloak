#!/usr/bin/env python3
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
            # A 401 access_denied here almost always means the M2M app isn't
            # authorized for the Management API audience — the single most common
            # Auth0 setup gap. Give an actionable message instead of a raw 401.
            hint = ""
            if response.status_code == 401 and "access_denied" in response.text:
                hint = (
                    "\n  -> The M2M application is not authorized for the Auth0 "
                    "Management API audience "
                    f"(https://{self.domain}/api/v2/).\n"
                    "     Fix: in the Auth0 Dashboard, open Applications -> your "
                    "M2M app -> APIs, authorize 'Auth0 Management API', and grant "
                    "the scopes you need (e.g. read:users, read:clients, "
                    "read:organizations).\n"
                    "     Or, if you don't intend to use Auth0 management here, "
                    "set AUTH0_MANAGEMENT_MODE=off so the app disables those "
                    "endpoints cleanly instead of failing.")
            raise RuntimeError(
                f"Auth0 token endpoint returned {response.status_code}: "
                f"{response.text}{hint}"
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

    def _find_by_name(self, collection: str, name: str,
                      per_page: int = 100) -> dict | None:
        """
        Find an item by its 'name' across ALL pages of an Auth0 Management API
        collection (e.g. 'clients', 'connections').

        BUG FIX: the previous implementation did a single unpaginated GET, which
        returns only the first page (Auth0 defaults to 50 for clients, 100 for
        connections, and hard-caps per_page). On a tenant with more items than
        one page, an existing item past page 1 was invisible — so a get-or-create
        would create a DUPLICATE. This walks pages until it finds the name or
        the collection is exhausted.
        """
        page = 0
        while True:
            result = self._api("GET", collection, params={
                "page": page, "per_page": per_page, "include_totals": "true",
            })
            # With include_totals=true Auth0 wraps the list in an object keyed by
            # the collection name, plus paging metadata.
            if isinstance(result, dict):
                items = result.get(collection, [])
                total = result.get("total", len(items))
                start = result.get("start", page * per_page)
                limit = result.get("limit", per_page)
            else:
                # Defensive: some tenants/tokens may still return a bare list.
                items = result if isinstance(result, list) else []
                total, start, limit = len(items), 0, per_page
            hit = next((i for i in items if i.get("name") == name), None)
            if hit is not None:
                return hit
            # Stop when we've seen everything.
            if not items or (start + limit) >= total or len(items) < limit:
                return None
            page += 1

    def get_connection_by_name(self, name: str) -> dict | None:
        """Retrieve an existing Auth0 connection by name (requires read:connections)."""
        return self._find_by_name("connections", name)

    def create_connection(self, name: str, strategy: str) -> dict:
        """
        Get-or-create a social connection in Auth0.
        Valid strategies: 'google-oauth2', 'facebook', 'github', etc.
        'auth0' is NOT valid here — it is the built-in database.
        """
        existing = self.get_connection_by_name(name)
        if existing:
            logger.info("Connection '%s' already exists; reusing it", name)
            return existing
        return self._api("POST", "connections", json={"name": name, "strategy": strategy})

    def get_client_by_name(self, name: str) -> dict | None:
        """Retrieve an existing Auth0 client by display name (walks all pages)."""
        return self._find_by_name("clients", name)

    def create_client(self, name: str, callbacks: list[str]) -> dict:
        """
        Get-or-create an Auth0 application client.

        IMPORTANT (BUG FIX): GET /clients does NOT return client_secret, only
        POST /clients does. So if the client already exists, we must fetch its
        secret explicitly via GET /clients/{id}?fields=client_secret, otherwise
        the secret would be missing and a junk value sent to Keycloak.
        """
        existing = self.get_client_by_name(name)
        if existing:
            logger.info("Client '%s' already exists; reusing it", name)
            client_id = existing.get("client_id")
            # Re-fetch the single client to obtain its client_secret. Request the
            # field explicitly: without include_fields the secret can be omitted
            # depending on tenant/token config, which would send an empty secret
            # to Keycloak and break brokered login.
            full = self._api("GET", f"clients/{client_id}", params={
                "fields": "client_id,client_secret,name,app_type,callbacks",
                "include_fields": "true",
            })
            return full if isinstance(full, dict) else existing
        return self._api("POST", "clients", json={
            "name":        name,
            "app_type":    "regular_web",
            "grant_types": ["authorization_code", "refresh_token"],
            "callbacks":   callbacks,
            # Keycloak's IdP validates the ID token against Auth0's RS256 JWKS
            # (validateSignature + useJwksUrl). Force RS256 signing here so the
            # broker callback can validate the token; leaving Auth0's default
            # (which may be HS256) causes "Unexpected error when authenticating
            # with identity provider" at the callback.
            "jwt_configuration": {"alg": "RS256"},
            "token_endpoint_auth_method": "client_secret_post",
        })

    def rotate_client_secret(self, client_id: str) -> str:
        """
        Rotate (regenerate) the secret for an Auth0 client.
        Calls POST /api/v2/clients/{id}/rotate-secret and returns the NEW secret.
        Requires the 'update:client_keys' scope on the M2M application.

        NOTE: rotating invalidates the old secret immediately. Any service still
        configured with the old secret (e.g. the Keycloak IdP) must be updated
        with the returned value, or authentication through it will break.
        """
        result = self._api("POST", f"clients/{client_id}/rotate-secret")
        if not isinstance(result, dict) or not result.get("client_secret"):
            raise RuntimeError(
                f"Secret rotation for client {client_id} returned no client_secret"
            )
        new_secret = result["client_secret"]
        # Freshness guard: when rotating OUR OWN client we know the old secret,
        # so a "new" secret identical to it means rotation did NOT actually
        # happen (broken proxy/mock or API anomaly). Failing loudly beats
        # reporting a rotation that never occurred.
        if client_id == self.client_id:
            if new_secret == self.client_secret:
                raise RuntimeError(
                    f"Auth0 returned the SAME secret for client {client_id} — "
                    "rotation did not occur. Check the tenant/endpoint."
                )
            # P1 FIX: update the stored secret so a future token refresh (after
            # the cached token expires) uses the new secret, not the dead one.
            self.client_secret = new_secret
        logger.info("Rotated client secret for %s", client_id)
        return new_secret


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
        # Mark this as an end-entity (leaf) certificate, not a CA. Modern TLS
        # stacks reject a leaf that doesn't say CA:FALSE, and without pathlen
        # discipline a self-signed cert can otherwise look like a usable CA.
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Constrain what the key may do: digital signatures + key encipherment,
        # which is what an RSA server key needs for TLS. Locking this down is
        # basic certificate hygiene and some clients enforce it.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Explicitly scope the cert to TLS server authentication.
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        # Subject Key Identifier — standard hygiene that helps chain building
        # and matches what real CAs emit.
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
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


def get_keycloak_admin_token(
    keycloak_url: str,
    username: str,
    password: str,
    admin_realm: str = "master",
    client_id: str = "admin-cli",
) -> str:
    """
    Fetch a FRESH Keycloak admin token via the password grant.
    Keycloak admin tokens expire in ~60 s, so they must be fetched at runtime.
    This token is issued by Keycloak — it is NOT an Auth0 token. Passing an
    Auth0 token to Keycloak's admin API produces a 401.
    """
    base = keycloak_url.rstrip("/")
    for prefix in ("/realms", "/auth/realms"):
        url = f"{base}{prefix}/{admin_realm}/protocol/openid-connect/token"
        try:
            response = requests.post(
                url,
                data={
                    "client_id":  client_id,
                    "username":   username,
                    "password":   password,
                    "grant_type": "password",
                },
                timeout=10,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"Keycloak token request failed: {exc}") from exc

        if response.status_code == 404 and prefix == "/realms":
            continue
        if not response.ok:
            raise RuntimeError(
                f"Keycloak admin token request returned {response.status_code}: {response.text}. "
                "Check KEYCLOAK_ADMIN_USER / KEYCLOAK_ADMIN_PASSWORD."
            )
        try:
            token = response.json().get("access_token")
        except ValueError as exc:
            raise RuntimeError("Keycloak token endpoint returned non-JSON response") from exc
        if not token:
            raise RuntimeError("Keycloak token response missing access_token")
        return token

    raise RuntimeError(f"Keycloak token endpoint not found at {base}")


def _ensure_idp_mappers(base: str, path_prefix: str, realm_name: str,
                        admin_token: str, alias: str = "auth0",
                        timeout: int = 10) -> None:
    """
    Create the identity-provider mappers Keycloak needs to build a local user
    from the Auth0 token. Without these, first-broker-login fails with the
    opaque "Unexpected error when authenticating with identity provider" even
    though the token exchange succeeded. Idempotent — existing mappers by name
    are left alone. Best-effort: a failure here is logged, not fatal, so IdP
    registration still counts as done.
    """
    url = (f"{base}{path_prefix}/{realm_name}/identity-provider/instances/"
           f"{alias}/mappers")
    headers = {"content-type": "application/json",
               "authorization": f"Bearer {admin_token}"}
    wanted = [
        {"name": "email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "email", "user.attribute": "email",
                    "syncMode": "INHERIT"}},
        {"name": "username",
         "identityProviderMapper": "oidc-username-idp-mapper",
         "config": {"template": "${CLAIM.email}", "syncMode": "INHERIT"}},
        {"name": "firstName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "given_name", "user.attribute": "firstName",
                    "syncMode": "INHERIT"}},
        {"name": "lastName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "family_name", "user.attribute": "lastName",
                    "syncMode": "INHERIT"}},
    ]
    try:
        existing = requests.get(url, headers=headers, timeout=timeout)
        existing.raise_for_status()
        have = {m.get("name") for m in existing.json()}
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Could not list IdP mappers (%s); skipping mapper setup", exc)
        return
    for mapper in wanted:
        if mapper["name"] in have:
            continue
        try:
            resp = requests.post(url, headers=headers, timeout=timeout,
                                 json={**mapper, "identityProviderAlias": alias})
            resp.raise_for_status()
            logger.info("Created IdP mapper '%s'", mapper["name"])
        except requests.RequestException as exc:
            logger.warning("Could not create IdP mapper '%s': %s",
                           mapper["name"], exc)


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
        # BUG FIX: use the realm_name parameter instead of a hardcoded 'Premkey'
        url = f"{base}{path_prefix}/{realm_name}/identity-provider/instances"
        headers = {
            "content-type":  "application/json",
            "authorization": f"Bearer {keycloak_admin_token}",
        }
        data = {
            "alias":      "auth0",
            "providerId": "oidc",
            "enabled":    True,
            # Trust the email Auth0 asserts, so an unverified address doesn't
            # stall Keycloak's first-broker-login flow.
            "trustEmail": True,
            "config": {
                "clientId":          oidc_client_id,
                "clientSecret":      oidc_client_secret,
                # Keycloak must call Auth0's /userinfo to load the profile:
                # Auth0 often returns 'email' there rather than in the ID token,
                # and without it first-broker-login cannot create the user.
                "disableUserInfo":   "false",
                # How Keycloak presents its credentials at Auth0's token
                # endpoint. Without this, Keycloak has no client-auth method
                # configured and the code->token exchange fails with the generic
                # "Unexpected error when authenticating with identity provider".
                # Auth0's default for regular web apps is client_secret_post.
                "clientAuthMethod":  "client_secret_post",
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
            logger.info("Auth0 IdP registered in Keycloak realm '%s'", realm_name)
            _ensure_idp_mappers(base, path_prefix, realm_name,
                                keycloak_admin_token)
            return
        if response.status_code == 409:
            logger.info("Auth0 IdP already exists in Keycloak; skipping creation")
            _ensure_idp_mappers(base, path_prefix, realm_name,
                                keycloak_admin_token)
            return
        if response.status_code == 404:
            # Modern path 404 -> try legacy path. Legacy path 404 -> realm
            # genuinely missing; record and let the loop fall through to the
            # clear "realm not found" message below.
            last_error = response.text
            if path_prefix == "/admin/realms":
                continue
            break
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
    """Read required env vars, collecting ALL missing ones into one clear message."""
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
        )
    return values  # type: ignore[return-value]


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    # Only Auth0 creds required. Keycloak admin TOKEN is fetched at runtime (it
    # expires in ~60 s and an Auth0 token would be rejected with 401).
    env = _require_env("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET")

    keycloak_url        = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    keycloak_admin_user = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
    keycloak_admin_pass = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
    auth0_callback      = os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:8080/callback")
    realm_name          = os.environ.get("KEYCLOAK_REALM", "Premkey")
    keycloak_callback   = os.environ.get(
        "KEYCLOAK_REDIRECT_URI",
        f"http://localhost:8080/realms/{realm_name}/broker/auth0/endpoint",
    )

    auth0 = Auth0Connect(env["AUTH0_DOMAIN"], env["AUTH0_CLIENT_ID"], env["AUTH0_CLIENT_SECRET"])
    logger.info("Auth0 instance created for domain: %s", env["AUTH0_DOMAIN"])
    test_token_access(auth0)

    for strategy in ("google-oauth2", "facebook"):
        conn = auth0.create_connection(f"keycloak-{strategy}", strategy)
        logger.info("Connection ready: %s", conn.get("name"))

    client = auth0.create_client("keycloak-oidc-client", callbacks=[keycloak_callback])
    logger.info("Client ready: %s (client_id: %s)", client.get("name"), client.get("client_id"))

    create_server_certificate(hostname=env["AUTH0_DOMAIN"])

    # Fetch a fresh Keycloak admin token (from Keycloak, never Auth0)
    keycloak_admin_token = get_keycloak_admin_token(
        keycloak_url, keycloak_admin_user, keycloak_admin_pass
    )
    logger.info("Obtained fresh Keycloak admin token")

    # BUG FIX: no hardcoded fallback secret. Fail clearly if the Auth0 client
    # didn't return usable credentials, rather than sending junk to Keycloak.
    oidc_client_id     = client.get("client_id", "")
    oidc_client_secret = client.get("client_secret", "")
    if not oidc_client_id or not oidc_client_secret:
        raise SystemExit(
            "Auth0 client is missing client_id/client_secret — cannot configure the "
            "Keycloak identity provider. Ensure the M2M app has read:clients scope so "
            "the client secret can be retrieved."
        )

    integrate_with_keycloak(
        auth0,
        keycloak_url=keycloak_url,
        realm_name=realm_name,
        keycloak_admin_token=keycloak_admin_token,
        oidc_client_id=oidc_client_id,
        oidc_client_secret=oidc_client_secret,
    )

    found = auth0.get_client_by_name("keycloak-oidc-client")
    if found:
        logger.info("Client verified: %s", found.get("client_id"))
    else:
        logger.warning("Client 'keycloak-oidc-client' not found after creation")

    logger.info("Integration complete!")
    logger.info("Test login URL: %s", test_login_flow(auth0, auth0_callback))
