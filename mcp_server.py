#!/usr/bin/env python3
"""MCP server exposing the auth broker's operational tools to an AI assistant.

Bridges an MCP client (e.g. Claude) to a RUNNING broker's HTTP API, exposing a
considered, SAFE set of operational tools: health, token introspection, API-key
management, user sessions, and Auth0 org-sync. It deliberately does NOT expose
password-grant login or anything that takes an end user's password — an AI
operator should never handle those.

This is a SEPARATE optional component with its own dependencies (mcp, httpx — see
requirements-mcp.txt); it is not part of the broker image or its requirements.

Run:
    BROKER_URL=https://app.test.local BROKER_TOKEN=<admin-bearer> \\
        python3 mcp_server.py

Config (env):
    BROKER_URL     broker base URL (default https://app.test.local)
    BROKER_TOKEN   admin bearer token (required for the admin tools)
    BROKER_VERIFY  TLS verify (default true; set false for the internal CA if the
                   OS doesn't trust it — see ./trust-ca.sh to trust it instead)
"""
import os

import httpx
from mcp.server.mcpserver import MCPServer

BROKER_URL = os.environ.get("BROKER_URL", "https://app.test.local").rstrip("/")
BROKER_TOKEN = os.environ.get("BROKER_TOKEN", "")
BROKER_VERIFY = os.environ.get("BROKER_VERIFY", "true").strip().lower() not in (
    "0", "false", "no")

server = MCPServer("auth-broker")


def _client() -> httpx.Client:
    headers = {"Authorization": f"Bearer {BROKER_TOKEN}"} if BROKER_TOKEN else {}
    return httpx.Client(base_url=BROKER_URL, headers=headers,
                        verify=BROKER_VERIFY, timeout=10)


def _result(resp) -> dict:
    """Normalize an httpx response into a dict the AI can read."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001 - non-JSON body
        body = {"text": resp.text}
    return {"status": resp.status_code, "ok": resp.is_success, "body": body}


# ── handlers: pure (client in, dict out) — unit-testable without a server ──────
def _h_health(c):               return _result(c.get("/health/live"))
def _h_introspect(c, token):    return _result(c.post("/token/introspect", data={"token": token}))
def _h_list_keys(c):            return _result(c.get("/admin/api-keys"))
def _h_create_key(c, n, s, t):  return _result(c.post("/admin/api-keys", data={"name": n, "scopes": s, "ttl_seconds": t}))
def _h_revoke_key(c, kid):      return _result(c.delete(f"/admin/api-keys/{kid}"))
def _h_sessions(c, uid):        return _result(c.get(f"/admin/users/{uid}/sessions"))
def _h_sync_orgs(c, dry):       return _result(c.post("/admin/org-sync", data={"dry_run": str(bool(dry)).lower()}))


# ── MCP tools: thin wrappers over the handlers ────────────────────────────────
@server.tool()
def broker_health() -> dict:
    """Check whether the auth broker is up (liveness)."""
    with _client() as c:
        return _h_health(c)


@server.tool()
def introspect_token(token: str) -> dict:
    """Introspect a bearer token: whether it's active and its allow-listed claims."""
    with _client() as c:
        return _h_introspect(c, token)


@server.tool()
def list_api_keys() -> dict:
    """List API-key metadata (admin). Never returns secret key values."""
    with _client() as c:
        return _h_list_keys(c)


@server.tool()
def create_api_key(name: str, scopes: str = "", ttl_seconds: int = 0) -> dict:
    """Create a service API key (admin). scopes is comma-separated; ttl_seconds=0
    never expires. The plaintext key is returned ONCE — store it immediately."""
    with _client() as c:
        return _h_create_key(c, name, scopes, ttl_seconds)


@server.tool()
def revoke_api_key(key_id: str) -> dict:
    """Revoke an API key by its id (admin)."""
    with _client() as c:
        return _h_revoke_key(c, key_id)


@server.tool()
def list_user_sessions(user_id: str) -> dict:
    """List a user's active Keycloak sessions (admin)."""
    with _client() as c:
        return _h_sessions(c, user_id)


@server.tool()
def sync_organizations(dry_run: bool = True) -> dict:
    """Sync Auth0 organizations into Keycloak groups (admin). dry_run=true (the
    default) previews the plan without writing."""
    with _client() as c:
        return _h_sync_orgs(c, dry_run)


if __name__ == "__main__":
    server.run()
