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
import logging
import os
import sys

import httpx
from mcp.server.mcpserver import MCPServer

VERSION = "1.1.0"

logger = logging.getLogger("auth-broker-mcp")

BROKER_URL = os.environ.get("BROKER_URL", "https://app.test.local").rstrip("/")
BROKER_TOKEN = os.environ.get("BROKER_TOKEN", "")
BROKER_VERIFY = os.environ.get("BROKER_VERIFY", "true").strip().lower() not in (
    "0", "false", "no")
# Per-request timeout (seconds). A hung/slow broker then returns a clean error to
# the AI operator instead of blocking the MCP call indefinitely.
BROKER_TIMEOUT = float(os.environ.get("BROKER_TIMEOUT", "10"))

# A BROKER_URL without a scheme (http:// or https://) will make every request
# fail in a confusing way — warn loudly at startup rather than letting each tool
# return a cryptic error. (Config misstep when re-pointing at a different broker.)
if BROKER_URL and "://" not in BROKER_URL:
    logger.warning("BROKER_URL has no scheme (%r) — expected http(s)://host; "
                   "requests will fail until this is fixed.", BROKER_URL)

server = MCPServer("auth-broker")


def _client() -> httpx.Client:
    headers = {"Authorization": f"Bearer {BROKER_TOKEN}"} if BROKER_TOKEN else {}
    return httpx.Client(base_url=BROKER_URL, headers=headers,
                        verify=BROKER_VERIFY, timeout=BROKER_TIMEOUT)


def _result(resp) -> dict:
    """Normalize an httpx response into a dict the AI can read."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001 - non-JSON body
        body = {"text": resp.text}
    out = {"status": resp.status_code, "ok": resp.is_success, "body": body}
    # A 401 with no token configured is a common misstep — say so, so an operator
    # isn't left guessing why an admin tool was rejected.
    if resp.status_code == 401 and not BROKER_TOKEN:
        out["hint"] = ("401 Unauthorized and no BROKER_TOKEN is set — export "
                       "BROKER_TOKEN=<admin bearer> for the admin tools.")
    return out


def _safe_call(fn, *args) -> dict:
    """Run a broker handler with a fresh client, turning ANY transport/HTTP error
    into a clean result dict instead of raising into the MCP client.

    An AI operator calling a tool while the broker is down, slow, or unreachable
    (DNS, refused connection, TLS, timeout) should get a readable error it can act
    on — not a raw stack trace. status=0 marks "never reached the broker" (vs a
    real HTTP status). The per-call client is closed by the context manager on
    every path, so a tool interrupted mid-call leaks no socket.
    """
    try:
        with _client() as c:
            return fn(c, *args)
    except httpx.HTTPError as e:
        logger.warning("broker request failed (%s): %s [%s]",
                       e.__class__.__name__, e, BROKER_URL)
        return {
            "ok": False,
            "status": 0,
            "error": f"broker request failed ({e.__class__.__name__}): {e}",
            "broker_url": BROKER_URL,
            "hint": "Is the broker up and reachable? Check BROKER_URL and that the "
                    "stack is running; for a self-signed CA set BROKER_VERIFY=false "
                    "or trust the CA (./trust-ca.sh).",
        }
    except Exception as e:  # noqa: BLE001 - a tool must never raise into the client
        logger.warning("unexpected error in broker call (%s): %s",
                       e.__class__.__name__, e)
        return {
            "ok": False,
            "status": 0,
            "error": f"unexpected error ({e.__class__.__name__}): {e}",
        }


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
    return _safe_call(_h_health)


@server.tool()
def introspect_token(token: str) -> dict:
    """Introspect a bearer token: whether it's active and its allow-listed claims."""
    return _safe_call(_h_introspect, token)


@server.tool()
def list_api_keys() -> dict:
    """List API-key metadata (admin). Never returns secret key values."""
    return _safe_call(_h_list_keys)


@server.tool()
def create_api_key(name: str, scopes: str = "", ttl_seconds: int = 0) -> dict:
    """Create a service API key (admin). scopes is comma-separated; ttl_seconds=0
    never expires. The plaintext key is returned ONCE — store it immediately."""
    return _safe_call(_h_create_key, name, scopes, ttl_seconds)


@server.tool()
def revoke_api_key(key_id: str) -> dict:
    """Revoke an API key by its id (admin)."""
    return _safe_call(_h_revoke_key, key_id)


@server.tool()
def list_user_sessions(user_id: str) -> dict:
    """List a user's active Keycloak sessions (admin)."""
    return _safe_call(_h_sessions, user_id)


@server.tool()
def sync_organizations(dry_run: bool = True) -> dict:
    """Sync Auth0 organizations into Keycloak groups (admin). dry_run=true (the
    default) previews the plan without writing."""
    return _safe_call(_h_sync_orgs, dry_run)


if __name__ == "__main__":
    # Install a basic stderr logger so the server's own warnings (broker
    # unreachable, bad BROKER_URL) actually appear — StreamHandler flushes each
    # line, so they show up immediately rather than sitting in a buffer.
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    logger.info("auth-broker MCP server v%s -> %s (verify=%s, timeout=%ss)%s",
                VERSION, BROKER_URL, BROKER_VERIFY, BROKER_TIMEOUT,
                "" if BROKER_TOKEN else "  [no BROKER_TOKEN — admin tools will 401]")
    server.run()
