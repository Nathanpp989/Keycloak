#!/usr/bin/env python3
# openbao_connect.py
# The "Z-axis": connects OpenBao to both Keycloak and Auth0, in both directions.
#
# Three capabilities, all scaffolded here:
#
#   1. Keycloak -> OpenBao   configure_keycloak_oidc()
#      OpenBao's OIDC auth method trusts your Keycloak realm, so a user who
#      logged in through Keycloak can authenticate to OpenBao and receive a
#      Vault token scoped by policy.
#
#   2. Auth0 -> OpenBao      configure_auth0_jwt()
#      OpenBao's JWT auth method trusts Auth0's issuer/JWKS, so an Auth0-issued
#      token authenticates to OpenBao directly (M2M / service style).
#
#   3. OpenBao as secret store   OpenBaoSecrets (get_secret / put_secret)
#      Reads/writes secrets in OpenBao's KV v2 engine. This ADDS to the existing
#      Azure Key Vault (authorize.get_secret) — it does not replace it. A small
#      unified resolver (resolve_secret) tries OpenBao first, then falls back to
#      Key Vault, so callers can migrate incrementally.
#
# Runtime target: local `bao server -dev` (OpenBao/Vault-compatible HTTP API at
# http://127.0.0.1:8200, token auth via X-Vault-Token). The dev server speaks
# the same /v1/... API as Vault, so these calls also work against Vault.
#
# Design mirrors the rest of this codebase: small, synchronous, read-modify-
# write, honest errors, and fully unit-testable with the `responses` library
# (no live OpenBao needed for the tests).

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

# ── Configuration (env with dev-server-friendly defaults) ───────────────────
OPENBAO_ADDR  = os.environ.get("OPENBAO_ADDR", "http://127.0.0.1:8200").rstrip("/")
OPENBAO_TOKEN = os.environ.get("OPENBAO_TOKEN", "")  # dev root token, e.g. "root"

# Where each auth method is mounted inside OpenBao. Two SEPARATE mounts so the
# Keycloak (OIDC, browser) and Auth0 (JWT, machine) integrations don't collide.
OIDC_MOUNT_KEYCLOAK = os.environ.get("OPENBAO_KEYCLOAK_MOUNT", "oidc")
JWT_MOUNT_AUTH0     = os.environ.get("OPENBAO_AUTH0_MOUNT", "auth0-jwt")

# KV v2 secrets engine mount for capability #3.
KV_MOUNT = os.environ.get("OPENBAO_KV_MOUNT", "secret")

# AppRole: how the APP authenticates to OpenBao to read secrets, instead of a
# static root token. The app logs in with a role_id + secret_id (provisioned by
# configure_approle) and gets a short-lived token. This is the right fit now
# that OpenBao is persistent (the fixed 'root' token is gone).
APPROLE_MOUNT = os.environ.get("OPENBAO_APPROLE_MOUNT", "approle")
OPENBAO_ROLE_ID = os.environ.get("OPENBAO_ROLE_ID", "")
OPENBAO_SECRET_ID = os.environ.get("OPENBAO_SECRET_ID", "")

# PKI secrets engine mount — OpenBao acts as an internal Certificate Authority
# that issues TLS certs (e.g. for Traefik). Separate mount from KV/auth so the
# CA lives on its own path.
PKI_MOUNT = os.environ.get("OPENBAO_PKI_MOUNT", "pki")


class OpenBaoError(RuntimeError):
    """Raised for OpenBao API failures with an actionable message."""


def _headers(token: str | None = None) -> dict:
    return {"X-Vault-Token": token or OPENBAO_TOKEN,
            "content-type": "application/json"}


def _require_token(token: str | None) -> str:
    tok = token or OPENBAO_TOKEN
    if not tok:
        raise OpenBaoError(
            "No OpenBao token. Set OPENBAO_TOKEN (the dev root token printed by "
            "`bao server -dev`, often 'root') or pass token=... explicitly.")
    return tok


def _request(method: str, path: str, token: str | None = None,
             json_body: dict | None = None, addr: str | None = None,
             timeout: int = 10) -> requests.Response:
    """Low-level OpenBao API call. `path` is the part after /v1/."""
    base = (addr or OPENBAO_ADDR).rstrip("/")
    # Catch the common "pasted the placeholder" mistake (OPENBAO_ADDR=... or an
    # address with no scheme) with an actionable message, rather than letting it
    # surface as a confusing requests MissingSchema deep in the stack.
    if not base.startswith(("http://", "https://")):
        raise OpenBaoError(
            f"OpenBao address '{base}' is not a valid URL (no http:// or "
            "https:// scheme). Set OPENBAO_ADDR to your server, e.g. "
            "OPENBAO_ADDR=http://127.0.0.1:8200 — did you paste a '...' "
            "placeholder literally?")
    url = f"{base}/v1/{path.lstrip('/')}"
    try:
        resp = requests.request(method, url, headers=_headers(token),
                                json=json_body, timeout=timeout)
    except requests.RequestException as exc:
        raise OpenBaoError(f"Could not reach OpenBao at {base}: {exc}. "
                           "Is `bao server -dev` running?") from exc
    return resp


def _check(resp: requests.Response, action: str) -> dict:
    """Raise on error, else return parsed JSON (or {} for empty 204 bodies)."""
    if resp.status_code == 403:
        raise OpenBaoError(
            f"{action}: permission denied (403). The token lacks the needed "
            "policy, or is wrong. For dev, use the root token.")
    if resp.status_code == 404:
        raise OpenBaoError(f"{action}: not found (404) at {resp.url}")
    if resp.status_code >= 400:
        detail = resp.text[:300]
        # OpenBao validates the OIDC discovery URL by FETCHING it at config-write
        # time. If the IdP isn't reachable FROM OpenBao (wrong URL, network/egress
        # rules, IdP down), it returns this opaque 400. Name it clearly — this is
        # the OpenBao analogue of the "generic broker error" that cost us hours.
        if "oidc discovery" in detail.lower() or "discovery url" in detail.lower():
            raise OpenBaoError(
                f"{action} failed ({resp.status_code}): OpenBao could not reach "
                "the OIDC discovery URL. OpenBao fetches "
                "<issuer>/.well-known/openid-configuration when you write the "
                "config, so the IdP must be reachable FROM the OpenBao server. "
                "Check: the URL is correct (Keycloak realm base, or Auth0 "
                "https://<domain>/ WITH trailing slash), the IdP is up, and no "
                "network/egress rule blocks OpenBao->IdP. Raw error: " + detail)
        raise OpenBaoError(f"{action} failed ({resp.status_code}): {detail}")
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        return {}


# ════════════════════════════════════════════════════════════════════════════
# Shared: enable an auth method mount (idempotent)
# ════════════════════════════════════════════════════════════════════════════
def enable_auth_method(method_type: str, mount: str,
                       token: str | None = None, addr: str | None = None) -> bool:
    """
    Enable an auth method (e.g. 'oidc' or 'jwt') at `mount`. Idempotent: if the
    mount already exists OpenBao returns 400 'path is already in use', which we
    treat as success. Returns True if the mount is present afterward.
    """
    tok = _require_token(token)
    resp = _request("POST", f"sys/auth/{mount}", token=tok, addr=addr,
                    json_body={"type": method_type})
    if resp.status_code < 400:
        logger.info("Enabled %s auth at mount '%s'", method_type, mount)
        return True
    # Already-enabled is fine (idempotent re-run).
    body = resp.text.lower()
    if resp.status_code == 400 and ("already in use" in body or "existing mount" in body):
        logger.info("Auth mount '%s' already exists; reusing", mount)
        return True
    _check(resp, f"enable {method_type} auth at '{mount}'")
    return True


# ════════════════════════════════════════════════════════════════════════════
# Capability 1: Keycloak -> OpenBao  (OIDC auth method)
# ════════════════════════════════════════════════════════════════════════════
def configure_keycloak_oidc(
    keycloak_url: str,
    realm: str,
    oidc_client_id: str,
    oidc_client_secret: str,
    *,
    mount: str = OIDC_MOUNT_KEYCLOAK,
    role_name: str = "keycloak",
    policies: list[str] | None = None,
    openbao_addr: str | None = None,
    openbao_token: str | None = None,
    default_role: bool = True,
) -> dict:
    """
    Configure OpenBao so users can log in with their Keycloak identity.

    Sets up (all idempotent):
      - the 'oidc' auth mount
      - auth/<mount>/config with Keycloak realm as the OIDC discovery URL
      - a role mapping the token's 'preferred_username' claim to OpenBao policies

    The Keycloak client used here must allow the Authorization Code flow and
    register OpenBao's callback URLs as valid redirect URIs:
        <OPENBAO_ADDR>/ui/vault/auth/<mount>/oidc/callback
        http://localhost:8250/oidc/callback   (for `bao login -method=oidc`)

    Returns the role definition written.
    """
    tok = _require_token(openbao_token)
    addr = (openbao_addr or OPENBAO_ADDR).rstrip("/")
    kc = keycloak_url.rstrip("/")
    discovery = f"{kc}/realms/{realm}"

    enable_auth_method("oidc", mount, token=tok, addr=addr)

    # OIDC discovery config. OpenBao appends /.well-known/openid-configuration.
    cfg = {
        "oidc_discovery_url": discovery,
        "oidc_client_id":     oidc_client_id,
        "oidc_client_secret": oidc_client_secret,
        "default_role":       role_name if default_role else "",
    }
    _check(_request("POST", f"auth/{mount}/config", token=tok, addr=addr,
                    json_body=cfg), "write OIDC config")

    role = {
        "role_type":     "oidc",
        "user_claim":    "preferred_username",
        "policies":      policies or ["default"],
        "oidc_scopes":   ["openid", "profile", "email"],
        "allowed_redirect_uris": [
            f"{addr}/ui/vault/auth/{mount}/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
    }
    _check(_request("POST", f"auth/{mount}/role/{role_name}", token=tok,
                    addr=addr, json_body=role), "write OIDC role")
    logger.info("Keycloak->OpenBao OIDC configured (mount=%s role=%s)",
                mount, role_name)
    return role


# ════════════════════════════════════════════════════════════════════════════
# Capability 2: Auth0 -> OpenBao  (JWT auth method)
# ════════════════════════════════════════════════════════════════════════════
def configure_auth0_jwt(
    auth0_domain: str,
    *,
    mount: str = JWT_MOUNT_AUTH0,
    role_name: str = "auth0",
    bound_audiences: list[str] | None = None,
    user_claim: str = "sub",
    policies: list[str] | None = None,
    openbao_addr: str | None = None,
    openbao_token: str | None = None,
) -> dict:
    """
    Configure OpenBao so an Auth0-issued JWT can authenticate directly (no
    browser) — the M2M / service pattern.

    Sets up (idempotent):
      - the 'jwt' auth mount
      - auth/<mount>/config trusting Auth0's issuer + JWKS via OIDC discovery
      - a role binding the issuer/audience and mapping a claim to policies

    bound_audiences should be the Auth0 API identifier(s) the token is minted
    for. Returns the role written.
    """
    tok = _require_token(openbao_token)
    addr = (openbao_addr or OPENBAO_ADDR).rstrip("/")
    domain = auth0_domain.strip().rstrip("/")
    issuer = f"https://{domain}/"

    enable_auth_method("jwt", mount, token=tok, addr=addr)

    cfg = {
        # Discovery lets OpenBao fetch Auth0's JWKS and verify RS256 signatures.
        "oidc_discovery_url": issuer,
        "bound_issuer":       issuer,
    }
    _check(_request("POST", f"auth/{mount}/config", token=tok, addr=addr,
                    json_body=cfg), "write JWT config")

    role: dict[str, Any] = {
        "role_type":   "jwt",
        "user_claim":  user_claim,
        "bound_issuer": issuer,
        "policies":    policies or ["default"],
        "token_ttl":   "1h",
    }
    if bound_audiences:
        role["bound_audiences"] = bound_audiences
    else:
        # Without an audience bind, restrict by issuer + subject presence.
        role["bound_claims"] = {user_claim: "*"}
    _check(_request("POST", f"auth/{mount}/role/{role_name}", token=tok,
                    addr=addr, json_body=role), "write JWT role")
    logger.info("Auth0->OpenBao JWT configured (mount=%s role=%s)",
                mount, role_name)
    return role


def login_auth0_jwt(jwt: str, *, mount: str = JWT_MOUNT_AUTH0,
                    role_name: str = "auth0", openbao_addr: str | None = None
                    ) -> str:
    """
    Exchange an Auth0 JWT for an OpenBao token via the JWT auth method.
    Returns the client_token. No X-Vault-Token needed (this IS the login).
    """
    addr = (openbao_addr or OPENBAO_ADDR).rstrip("/")
    resp = _request("POST", f"auth/{mount}/login", addr=addr,
                    json_body={"role": role_name, "jwt": jwt})
    data = _check(resp, "JWT login")
    token = (data.get("auth") or {}).get("client_token")
    if not token:
        raise OpenBaoError(f"JWT login returned no client_token: {data}")
    return token


# ════════════════════════════════════════════════════════════════════════════
# AppRole: how the APP authenticates to OpenBao to read secrets (no root token)
# ════════════════════════════════════════════════════════════════════════════
def configure_approle(role_name: str, *, mount: str = APPROLE_MOUNT,
                      policy_name: str | None = None,
                      policy_hcl: str | None = None,
                      kv_mount: str | None = None,
                      token_ttl: str = "1h", token_max_ttl: str = "4h",
                      secret_id_ttl: str | None = None,
                      secret_id_num_uses: int | None = None,
                      token: str | None = None,
                      addr: str | None = None) -> dict:
    """Provision AppRole auth so the APP can read secrets without a root token.

    Enables the approle auth method, writes a policy granting READ access to the
    KV secrets, creates a role bound to that policy, and returns
    {role_id, secret_id, policy} for the app to log in with. Requires an admin
    token (the generated root token). Idempotent — safe to re-run (it rewrites
    the policy/role and mints a fresh secret_id each call).
    """
    tok = _require_token(token)
    policy_name = policy_name or f"{role_name}-policy"
    kv = kv_mount or KV_MOUNT
    # secret_id lifetime: DEFAULT is dev-permissive (never expires, unlimited
    # uses) so local dev "just works". For production set a finite TTL and use
    # count — via args or OPENBAO_SECRET_ID_TTL / OPENBAO_SECRET_ID_NUM_USES.
    if secret_id_ttl is None:
        secret_id_ttl = os.environ.get("OPENBAO_SECRET_ID_TTL", "0")
    if secret_id_num_uses is None:
        secret_id_num_uses = int(os.environ.get("OPENBAO_SECRET_ID_NUM_USES", "0"))
    if policy_hcl is None:
        # Least-privilege: read the app's KV secrets, nothing else.
        policy_hcl = (f'path "{kv}/data/*" {{ capabilities = ["read"] }}\n'
                      f'path "{kv}/metadata/*" {{ capabilities = ["read", "list"] }}\n')

    # Ensure the KV engine the policy points at actually exists — a persistent
    # OpenBao doesn't auto-mount it, and the app would 404 on every read otherwise.
    enable_kv_engine(mount=kv, token=tok, addr=addr)
    enable_auth_method("approle", mount, token=tok, addr=addr)
    _check(_request("PUT", f"sys/policies/acl/{policy_name}", token=tok,
                    addr=addr, json_body={"policy": policy_hcl}),
           f"write policy '{policy_name}'")
    _check(_request("POST", f"auth/{mount}/role/{role_name}", token=tok,
                    addr=addr,
                    json_body={"token_policies": [policy_name],
                               "token_ttl": token_ttl,
                               "token_max_ttl": token_max_ttl,
                               "secret_id_ttl": secret_id_ttl,
                               "secret_id_num_uses": secret_id_num_uses}),
           f"create approle role '{role_name}'")
    rid = _check(_request("GET", f"auth/{mount}/role/{role_name}/role-id",
                          token=tok, addr=addr), "read role-id")
    sid = _check(_request("POST", f"auth/{mount}/role/{role_name}/secret-id",
                          token=tok, addr=addr), "generate secret-id")
    role_id = (rid.get("data") or {}).get("role_id")
    secret_id = (sid.get("data") or {}).get("secret_id")
    if not role_id or not secret_id:
        raise OpenBaoError("AppRole provisioning returned no role_id/secret_id")
    logger.info("Provisioned AppRole role '%s' (policy '%s')",
                role_name, policy_name)
    return {"role_id": role_id, "secret_id": secret_id, "policy": policy_name}


def login_approle(role_id: str, secret_id: str, *, mount: str = APPROLE_MOUNT,
                  addr: str | None = None) -> tuple[str, int]:
    """Exchange a role_id + secret_id for an OpenBao token. Returns
    (client_token, lease_duration_seconds). The login endpoint is itself
    unauthenticated — that's the point, it's how you obtain a token."""
    resp = _request("POST", f"auth/{mount}/login", addr=addr,
                    json_body={"role_id": role_id, "secret_id": secret_id})
    data = _check(resp, "AppRole login")
    auth = data.get("auth") or {}
    token = auth.get("client_token")
    if not token:
        raise OpenBaoError("AppRole login returned no client_token")
    return token, int(auth.get("lease_duration", 0))


# Cache the AppRole-obtained token so we don't log in on every secret read.
_approle_token_cache: str | None = None
_approle_token_expiry: float = 0.0   # time.monotonic() deadline
_approle_lock = threading.Lock()


def _get_auth_token() -> str | None:
    """Return a usable OpenBao token for reading secrets, or None if OpenBao
    isn't configured. Prefers the static OPENBAO_TOKEN (dev / back-compat); else
    logs in via AppRole (OPENBAO_ROLE_ID + OPENBAO_SECRET_ID) and caches the
    token, refreshing shortly before it expires."""
    if OPENBAO_TOKEN:
        return OPENBAO_TOKEN
    if not (OPENBAO_ROLE_ID and OPENBAO_SECRET_ID):
        return None
    global _approle_token_cache, _approle_token_expiry
    with _approle_lock:
        now = time.monotonic()
        if _approle_token_cache and now < _approle_token_expiry:
            return _approle_token_cache
        token, ttl = login_approle(OPENBAO_ROLE_ID, OPENBAO_SECRET_ID)
        _approle_token_cache = token
        # Refresh 30s before expiry; if the token has no TTL, re-login periodically.
        _approle_token_expiry = now + (max(ttl - 30, 30) if ttl else 300)
        return token


def _openbao_configured() -> bool:
    """True if OpenBao secret reads are possible — a static token or AppRole."""
    return bool(OPENBAO_TOKEN or (OPENBAO_ROLE_ID and OPENBAO_SECRET_ID))


# ════════════════════════════════════════════════════════════════════════════
# Capability 3: OpenBao as a secret store (KV v2), alongside Azure Key Vault
# ════════════════════════════════════════════════════════════════════════════
class OpenBaoSecrets:
    """
    Minimal KV v2 client. Mirrors authorize.get_secret's role but backed by
    OpenBao. Names use the same convention as callers already use
    (AUTH0_CLIENT_SECRET); underscores are preserved (KV v2 keys allow them).
    """

    def __init__(self, addr: str | None = None, token: str | None = None,
                 mount: str = KV_MOUNT):
        self.addr = (addr or OPENBAO_ADDR).rstrip("/")
        # A caller may pass an explicit token; otherwise use the auth provider,
        # which returns the static OPENBAO_TOKEN or logs in via AppRole.
        self.token = token or _get_auth_token()
        self.mount = mount

    def put_secret(self, name: str, value: str) -> None:
        """Write a single-value secret at <mount>/data/<name> (KV v2 shape)."""
        _require_token(self.token)
        body = {"data": {"value": value}}
        _check(_request("POST", f"{self.mount}/data/{name}", token=self.token,
                        addr=self.addr, json_body=body),
               f"write secret '{name}'")

    def get_secret(self, name: str) -> str:
        """Read the 'value' field of <mount>/data/<name>. Raises if absent."""
        _require_token(self.token)
        resp = _request("GET", f"{self.mount}/data/{name}", token=self.token,
                        addr=self.addr)
        data = _check(resp, f"read secret '{name}'")
        # KV v2 nests under data.data.
        value = ((data.get("data") or {}).get("data") or {}).get("value")
        if value is None:
            raise OpenBaoError(
                f"Secret '{name}' has no 'value' field at {self.mount}/data/{name}")
        return value


def resolve_secret(name: str, *, prefer: str = "openbao") -> str:
    """
    Unified resolver: fetch a secret from OpenBao OR Azure Key Vault, so callers
    can migrate incrementally without ripping out Key Vault.

    prefer='openbao' (default): try OpenBao first, fall back to Key Vault.
    prefer='keyvault':          try Key Vault first, fall back to OpenBao.

    OpenBao is only attempted when OPENBAO_TOKEN is set, so unconfigured
    environments transparently use Key Vault as before.
    """
    def _from_openbao() -> str:
        if not _openbao_configured():
            raise OpenBaoError("OpenBao not configured (no OPENBAO_TOKEN and no "
                               "OPENBAO_ROLE_ID/OPENBAO_SECRET_ID for AppRole)")
        return OpenBaoSecrets().get_secret(name)

    def _from_keyvault() -> str:
        from authorize import get_secret as kv_get  # lazy: avoid azure import cost
        return kv_get(name)

    order = ([_from_openbao, _from_keyvault] if prefer == "openbao"
             else [_from_keyvault, _from_openbao])
    errors = []
    for fn in order:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - fall through to next source
            errors.append(f"{fn.__name__}: {exc}")
    raise OpenBaoError("secret not resolvable from any source: " + " | ".join(errors))


# ════════════════════════════════════════════════════════════════════════════
# PKI: OpenBao as an internal Certificate Authority (Level 1)
# ════════════════════════════════════════════════════════════════════════════
# These let OpenBao mint TLS certificates that Traefik (or anything) can serve,
# instead of relying on Traefik's throwaway self-signed cert. The flow is:
#   1. enable_pki_engine()            — mount the PKI secrets engine
#   2. configure_pki_root_ca()        — generate the CA (the trust anchor)
#   3. create_pki_role()              — a role that constrains what can be issued
#   4. issue_certificate(...)         — mint a leaf cert for a hostname
# Every step is idempotent-friendly and raises OpenBaoError with an actionable
# message on failure, matching the rest of this module.

def enable_kv_engine(*, mount: str = KV_MOUNT, token: str | None = None,
                     addr: str | None = None) -> bool:
    """Mount the KV v2 secrets engine at `mount`. Idempotent.

    A PERSISTENT (non-dev) OpenBao does NOT auto-mount 'secret/' the way dev mode
    does, so this must run before reading/writing secrets there — otherwise the
    first write/read 404s ("no handler for route"). Safe to re-run.
    """
    tok = _require_token(token)
    resp = _request("POST", f"sys/mounts/{mount}", token=tok, addr=addr,
                    json_body={"type": "kv", "options": {"version": "2"}})
    if resp.status_code < 400:
        logger.info("Enabled KV v2 engine at mount '%s'", mount)
        return True
    body = resp.text.lower()
    if resp.status_code == 400 and ("already in use" in body
                                    or "existing mount" in body):
        logger.info("KV mount '%s' already exists; reusing", mount)
        return True
    _check(resp, f"enable KV engine at '{mount}'")
    return True


def enable_pki_engine(*, mount: str = PKI_MOUNT, max_ttl: str = "87600h",
                      token: str | None = None,
                      addr: str | None = None) -> bool:
    """Mount the PKI secrets engine at `mount`. Idempotent.

    max_ttl bounds the longest cert this engine can ever issue (default 10y,
    suitable for a root CA). Returns True if the mount is present afterward.
    """
    tok = _require_token(token)
    resp = _request("POST", f"sys/mounts/{mount}", token=tok, addr=addr,
                    json_body={"type": "pki",
                               "config": {"max_lease_ttl": max_ttl}})
    if resp.status_code < 400:
        logger.info("Enabled PKI engine at mount '%s'", mount)
        return True
    body = resp.text.lower()
    if resp.status_code == 400 and ("already in use" in body
                                    or "existing mount" in body):
        logger.info("PKI mount '%s' already exists; reusing", mount)
        return True
    _check(resp, f"enable PKI engine at '{mount}'")
    return True


def _pki_has_ca(mount: str, addr: str | None, token: str | None) -> bool:
    """True if the PKI mount already has a CA certificate. Used to make root-CA
    generation genuinely idempotent: OpenBao's /root/generate/internal does NOT
    reliably error on a second call (behavior varies by version — it may return
    the existing CA, or in some versions replace it), so we must check first
    rather than rely on catching an 'already exists' error that may never come.
    """
    # GET <mount>/ca/pem returns the CA cert (200 with a PEM body) when one
    # exists, and a non-200 / empty body when the mount has no CA yet.
    resp = _request("GET", f"{mount}/ca/pem", token=token, addr=addr)
    return resp.status_code == 200 and b"BEGIN CERTIFICATE" in resp.content


def configure_pki_root_ca(common_name: str, *, mount: str = PKI_MOUNT,
                          ttl: str = "87600h", key_bits: int = 2048,
                          force: bool = False,
                          token: str | None = None,
                          addr: str | None = None) -> dict:
    """Generate a self-signed root CA inside the PKI mount (the trust anchor).

    Idempotent: if the mount already has a CA, this returns without regenerating
    (so re-running setup doesn't mint a NEW root and orphan previously-issued
    certs). Pass force=True to regenerate anyway (rotating the CA). Returns the
    issued CA data on generation, or {"existing": True} when reusing.

    For an INTERMEDIATE CA instead of a root, you'd generate a CSR here and have
    your existing root sign it — left as a future option; root is the right
    default for internal/dev trust.
    """
    tok = _require_token(token)
    if not force and _pki_has_ca(mount, addr, tok):
        logger.info("PKI mount '%s' already has a CA; reusing (pass force=True "
                    "to rotate)", mount)
        return {"existing": True}
    resp = _request("POST", f"{mount}/root/generate/internal", token=tok,
                    addr=addr,
                    json_body={"common_name": common_name, "ttl": ttl,
                               "key_bits": key_bits})
    data = _check(resp, f"generate root CA '{common_name}'")
    # Also set the URLs the CA advertises (issuing cert + CRL), which real
    # clients use for chain building and revocation checks.
    base = (addr or OPENBAO_ADDR).rstrip("/")
    _request("POST", f"{mount}/config/urls", token=tok, addr=addr,
             json_body={
                 "issuing_certificates": f"{base}/v1/{mount}/ca",
                 "crl_distribution_points": f"{base}/v1/{mount}/crl",
             })
    logger.info("Configured PKI root CA '%s' at mount '%s'", common_name, mount)
    return data.get("data", data) if isinstance(data, dict) else {}


def create_pki_role(role_name: str, *, mount: str = PKI_MOUNT,
                    allowed_domains: list | None = None,
                    allow_subdomains: bool = True,
                    allow_bare_domains: bool = True,
                    allow_localhost: bool = True,
                    allow_ip_sans: bool = True,
                    max_ttl: str = "720h",
                    token: str | None = None,
                    addr: str | None = None) -> bool:
    """Create/replace a PKI role that constrains what certificates may be issued.

    A role is the policy boundary: it says which domains a cert can be issued for
    and the maximum lifetime. Traefik's cert is then issued against this role.
    Roles are idempotent (writing the same name updates it).
    """
    tok = _require_token(token)
    body = {
        "allow_subdomains": allow_subdomains,
        # Allow issuing for the EXACT names in allowed_domains (not just their
        # subdomains). Without this, a SAN that equals an allowed domain — e.g.
        # 'app.test.local' — is rejected ("not allowed by this role"), while
        # '*.localhost' names still slip through as subdomains of localhost.
        "allow_bare_domains": allow_bare_domains,
        "allow_localhost": allow_localhost,
        "allow_ip_sans": allow_ip_sans,
        "max_ttl": max_ttl,
        "key_type": "rsa",
        "key_bits": 2048,
    }
    if allowed_domains:
        body["allowed_domains"] = allowed_domains
    resp = _request("POST", f"{mount}/roles/{role_name}", token=tok, addr=addr,
                    json_body=body)
    _check(resp, f"create PKI role '{role_name}'")
    logger.info("Created PKI role '%s' at mount '%s'", role_name, mount)
    return True


def issue_certificate(role_name: str, common_name: str, *,
                      mount: str = PKI_MOUNT, ttl: str = "720h",
                      alt_names: list | None = None,
                      ip_sans: list | None = None,
                      token: str | None = None,
                      addr: str | None = None) -> dict:
    """Issue a leaf certificate for `common_name` against `role_name`.

    Returns a dict with 'certificate', 'private_key', 'issuing_ca', and
    'ca_chain' (PEM strings). This is the cert Traefik serves. The TTL is capped
    by the role's max_ttl and the engine's max_lease_ttl.
    """
    tok = _require_token(token)
    body: dict = {"common_name": common_name, "ttl": ttl}
    if alt_names:
        body["alt_names"] = ",".join(alt_names)
    if ip_sans:
        body["ip_sans"] = ",".join(ip_sans)
    resp = _request("POST", f"{mount}/issue/{role_name}", token=tok, addr=addr,
                    json_body=body)
    data = _check(resp, f"issue certificate for '{common_name}'")
    issued = data.get("data", {}) if isinstance(data, dict) else {}
    if not issued.get("certificate"):
        raise OpenBaoError(
            f"issue certificate for '{common_name}': response had no "
            "certificate — check the role allows this common_name/domain.")
    logger.info("Issued certificate for '%s' (serial %s)",
                common_name, issued.get("serial_number", "?"))
    return issued


# ════════════════════════════════════════════════════════════════════════════
# One-shot scaffolding: wire all three at once (for setup scripts / demos)
# ════════════════════════════════════════════════════════════════════════════
def scaffold_all(
    *,
    keycloak_url: str,
    keycloak_realm: str,
    keycloak_oidc_client_id: str,
    keycloak_oidc_client_secret: str,
    auth0_domain: str,
    auth0_audience: str | None = None,
    openbao_addr: str | None = None,
    openbao_token: str | None = None,
) -> dict:
    """
    Configure all three OpenBao connections in one call. Returns a summary dict
    describing what was set up. Each step is idempotent, so this is safe to
    re-run. Raises OpenBaoError on the first hard failure.
    """
    summary: dict[str, Any] = {}
    summary["keycloak_oidc"] = configure_keycloak_oidc(
        keycloak_url, keycloak_realm, keycloak_oidc_client_id,
        keycloak_oidc_client_secret, openbao_addr=openbao_addr,
        openbao_token=openbao_token)
    summary["auth0_jwt"] = configure_auth0_jwt(
        auth0_domain,
        bound_audiences=[auth0_audience] if auth0_audience else None,
        openbao_addr=openbao_addr, openbao_token=openbao_token)
    summary["secret_store"] = {"mount": KV_MOUNT, "ready": bool(
        openbao_token or OPENBAO_TOKEN)}
    return summary


def login_checklist(openbao_addr: str | None = None) -> str:
    """
    Return a step-by-step checklist for the two OpenBao login round trips that
    require a live Keycloak/Auth0 (and, for the browser flow, a human). The JWT
    *mechanics* are already proven by openbao_login_smoke.py; this covers the
    real-IdP wiring those live flows additionally need.
    """
    addr = (openbao_addr or OPENBAO_ADDR).rstrip("/")
    kc_cb = f"{addr}/ui/vault/auth/{OIDC_MOUNT_KEYCLOAK}/oidc/callback"
    return f"""
OpenBao login round trips — live verification checklist
=======================================================

A) Keycloak -> OpenBao (browser OIDC)  [needs live Keycloak + a human]
  1. In Keycloak, create/confirm a confidential client for OpenBao
     (e.g. clientId 'openbao') with the Authorization Code flow enabled.
  2. Add these to that client's Valid Redirect URIs:
        {kc_cb}
        http://localhost:8250/oidc/callback
  3. Configure OpenBao (OpenBao must be able to REACH Keycloak's realm URL):
        OPENBAO_TOKEN=... python -c "import openbao_connect as o; \\
          o.configure_keycloak_oidc('<KEYCLOAK_URL>','<REALM>', \\
          'openbao','<CLIENT_SECRET>')"
  4. Log in from the CLI:
        bao login -method=oidc -path={OIDC_MOUNT_KEYCLOAK}
     A browser opens; complete the Keycloak login. Success prints a token.
  5. If it fails, check (in order):
        - OpenBao logs for 'error checking oidc discovery URL' -> OpenBao can't
          reach Keycloak. Fix networking/URL.
        - Keycloak 'Invalid redirect_uri' -> the URIs in step 2 don't match.
        - login works but no policy -> map claims to policies on the role.

B) Auth0 -> OpenBao (JWT)  [needs live Auth0 for a real token]
  MECHANICS ALREADY PROVEN LIVE by openbao_login_smoke.py. To confirm with a
  REAL Auth0 token:
  1. configure_auth0_jwt('<AUTH0_DOMAIN>', bound_audiences=['<API_IDENTIFIER>'])
     (OpenBao must be able to reach https://<domain>/.well-known/... )
  2. Get a real token via client-credentials:
        curl --request POST 'https://<AUTH0_DOMAIN>/oauth/token' \\
          --data grant_type=client_credentials \\
          --data client_id=<M2M_ID> --data client_secret=<M2M_SECRET> \\
          --data audience=<API_IDENTIFIER>
  3. Exchange it for an OpenBao token:
        python -c "import openbao_connect as o; \\
          print(o.login_auth0_jwt('<THE_JWT>'))"
  4. If it fails: 'no key found' -> discovery/JWKS unreachable or wrong issuer;
     'invalid audience' -> bound_audiences != token's aud; 'token is expired'
     -> mint a fresh one.
""".strip()


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    if not OPENBAO_TOKEN:
        print("Set OPENBAO_TOKEN (dev root token from `bao server -dev`).")
        return 1
    try:
        summary = scaffold_all(
            keycloak_url=os.environ.get("KEYCLOAK_URL", "http://localhost:8080"),
            keycloak_realm=os.environ.get("KEYCLOAK_REALM", "Premkey"),
            keycloak_oidc_client_id=os.environ.get("OPENBAO_KC_CLIENT_ID", "openbao"),
            keycloak_oidc_client_secret=os.environ.get("OPENBAO_KC_CLIENT_SECRET", ""),
            auth0_domain=os.environ.get("AUTH0_DOMAIN", ""),
            auth0_audience=os.environ.get("AUTH0_AUDIENCE"),
        )
    except OpenBaoError as exc:
        print(f"✗ {exc}")
        return 1
    print("✓ OpenBao configured:")
    print(f"    Keycloak->OpenBao : mount '{OIDC_MOUNT_KEYCLOAK}', "
          f"role '{summary['keycloak_oidc'].get('user_claim')}' user-claim")
    print(f"    Auth0->OpenBao    : mount '{JWT_MOUNT_AUTH0}'")
    print(f"    Secret store      : KV v2 at '{KV_MOUNT}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
