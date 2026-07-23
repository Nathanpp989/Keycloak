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
        self.token = token or OPENBAO_TOKEN
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
        if not OPENBAO_TOKEN:
            raise OpenBaoError("OpenBao not configured (no OPENBAO_TOKEN)")
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
