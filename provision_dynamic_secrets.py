#!/usr/bin/env python3
"""Provision OpenBao's database secrets engine against the Postgres from
compose.postgres.yaml, so the app can request short-lived DB credentials.

Idempotent. Run after the stack (incl. postgres + a provisioned OpenBao) is up:

    OPENBAO_ADDR=... OPENBAO_TOKEN=... \\
    POSTGRES_ADMIN_PASSWORD=... python3 provision_dynamic_secrets.py

Verifies here (mocked) that it calls the engine/connection/role setup correctly;
the real credential issuance is proven by test-dynamic-secrets.sh on the stack.
"""
from __future__ import annotations

import os
import sys

from openbao_dynamic_secrets import (enable_database_engine, configure_connection,
                                     create_role)

# Role that maps to a read-only ephemeral user (least privilege by default).
ROLE = os.environ.get("DB_DYNAMIC_ROLE", "app-readonly")
CONNECTION = os.environ.get("DB_CONNECTION_NAME", "appdb")
DB_HOST = os.environ.get("POSTGRES_HOST", "postgres")
DB_PORT = os.environ.get("POSTGRES_PORT", "5432")
DB_NAME = os.environ.get("POSTGRES_DB", "appdb")
DB_ADMIN_USER = os.environ.get("POSTGRES_USER", "vaultadmin")

CREATION_SQL = [
    'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' '
    "VALID UNTIL '{{expiration}}';",
    'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";',
]


def provision() -> None:
    addr = os.environ.get("OPENBAO_ADDR")
    token = os.environ.get("OPENBAO_TOKEN")
    db_pw = os.environ.get("POSTGRES_ADMIN_PASSWORD")
    if not (addr and token and db_pw):
        print("SKIP: set OPENBAO_ADDR, OPENBAO_TOKEN, POSTGRES_ADMIN_PASSWORD.")
        sys.exit(0)

    enable_database_engine(token=token, addr=addr)
    print("[1/3] database engine enabled")

    configure_connection(
        CONNECTION,
        plugin_name="postgresql-database-plugin",
        connection_url=(
            f"postgresql://{{{{username}}}}:{{{{password}}}}@"
            f"{DB_HOST}:{DB_PORT}/{DB_NAME}?sslmode=disable"),
        allowed_roles=[ROLE],
        username=DB_ADMIN_USER,
        password=db_pw,
        token=token, addr=addr)
    print(f"[2/3] connection '{CONNECTION}' configured -> {DB_HOST}:{DB_PORT}/{DB_NAME}")

    create_role(
        ROLE, db_name=CONNECTION, creation_statements=CREATION_SQL,
        default_ttl=os.environ.get("DB_DEFAULT_TTL", "1h"),
        max_ttl=os.environ.get("DB_MAX_TTL", "24h"),
        token=token, addr=addr)
    print(f"[3/3] role '{ROLE}' created (read-only, default_ttl 1h)")
    print(f"\nDone. Test with:  bao read database/creds/{ROLE}")


if __name__ == "__main__":
    provision()
