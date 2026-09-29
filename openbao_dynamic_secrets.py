"""OpenBao dynamic database secrets — short-lived DB credentials on demand.

Instead of a static DB password stored somewhere, the app asks OpenBao for a
FRESH credential with a lease; OpenBao creates a real database user, hands back
username/password, and auto-revokes them when the lease expires. This is the thin,
tested API layer over OpenBao's `database` secrets engine, built on the same
_request/_check helpers as openbao_connect.

VERIFICATION BOUNDARY: enabling and configuring the engine (enable_database_engine,
configure_connection, create_role) and lease renew/revoke are unit-tested against
a mocked OpenBao. Actually GENERATING a credential (generate_credentials) runs
against a REAL database wired into OpenBao — that step is verified on real
infrastructure, not in unit tests, because there is no database here to issue one.
"""
from __future__ import annotations

from openbao_connect import _request, _check, _require_token  # noqa: F401

DB_MOUNT = "database"


def enable_database_engine(*, mount: str = DB_MOUNT, token: str | None = None,
                           addr: str | None = None) -> bool:
    """Mount the `database` secrets engine at `mount`. Idempotent."""
    tok = _require_token(token)
    resp = _request("POST", f"sys/mounts/{mount}", token=tok, addr=addr,
                    json_body={"type": "database"})
    if resp.status_code < 400:
        return True
    body = resp.text.lower()
    if resp.status_code == 400 and ("already in use" in body
                                    or "existing mount" in body):
        return True
    _check(resp, f"enable database engine at '{mount}'")
    return True


def configure_connection(name: str, *, plugin_name: str, connection_url: str,
                         allowed_roles, username: str, password: str,
                         mount: str = DB_MOUNT, token: str | None = None,
                         addr: str | None = None) -> bool:
    """Register a database connection OpenBao can create users in.

    plugin_name e.g. 'postgresql-database-plugin'; connection_url is a templated
    DSN using {{username}}/{{password}}; allowed_roles limits which roles may use
    this connection (str or list). username/password are OpenBao's own admin
    credentials for the DB (used to create/drop the short-lived users).
    """
    tok = _require_token(token)
    body = {
        "plugin_name": plugin_name,
        "connection_url": connection_url,
        "allowed_roles": (allowed_roles if isinstance(allowed_roles, str)
                          else ",".join(allowed_roles)),
        "username": username,
        "password": password,
    }
    _check(_request("POST", f"{mount}/config/{name}", token=tok, addr=addr,
                    json_body=body), f"configure db connection '{name}'")
    return True


def create_role(role: str, *, db_name: str, creation_statements,
                default_ttl: str = "1h", max_ttl: str = "24h",
                mount: str = DB_MOUNT, token: str | None = None,
                addr: str | None = None) -> bool:
    """Create a role mapping to the SQL that provisions a short-lived user.

    creation_statements is a SQL string or list using {{name}}/{{password}}/
    {{expiration}} — e.g. "CREATE ROLE \\"{{name}}\\" WITH LOGIN PASSWORD
    '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN
    SCHEMA public TO \\"{{name}}\\";".
    """
    tok = _require_token(token)
    body = {
        "db_name": db_name,
        "creation_statements": (creation_statements
                                if isinstance(creation_statements, list)
                                else [creation_statements]),
        "default_ttl": default_ttl,
        "max_ttl": max_ttl,
    }
    _check(_request("POST", f"{mount}/roles/{role}", token=tok, addr=addr,
                    json_body=body), f"create db role '{role}'")
    return True


def generate_credentials(role: str, *, mount: str = DB_MOUNT,
                         token: str | None = None,
                         addr: str | None = None) -> dict:
    """Request a fresh short-lived DB credential for `role`. Returns
    {username, password, lease_id, lease_duration}. Runs against the REAL
    database — verified on real infrastructure, not in unit tests."""
    tok = _require_token(token)
    data = _check(_request("GET", f"{mount}/creds/{role}", token=tok, addr=addr),
                  f"generate credentials for role '{role}'")
    creds = data.get("data") or {}
    return {
        "username": creds.get("username"),
        "password": creds.get("password"),
        "lease_id": data.get("lease_id"),
        "lease_duration": data.get("lease_duration"),
    }


def renew_lease(lease_id: str, *, increment: int = 3600,
                token: str | None = None, addr: str | None = None) -> dict:
    """Extend a credential's lease by `increment` seconds (up to the role max_ttl)."""
    tok = _require_token(token)
    data = _check(_request("PUT", "sys/leases/renew", token=tok, addr=addr,
                           json_body={"lease_id": lease_id,
                                      "increment": increment}),
                  f"renew lease '{lease_id}'")
    return {"lease_id": data.get("lease_id"),
            "lease_duration": data.get("lease_duration")}


def revoke_lease(lease_id: str, *, token: str | None = None,
                 addr: str | None = None) -> bool:
    """Revoke a credential immediately — OpenBao drops the DB user now."""
    tok = _require_token(token)
    _check(_request("PUT", "sys/leases/revoke", token=tok, addr=addr,
                    json_body={"lease_id": lease_id}), f"revoke lease '{lease_id}'")
    return True
