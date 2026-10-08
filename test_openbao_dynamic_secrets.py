"""Tests for openbao_dynamic_secrets — the OpenBao database secrets engine API
layer, exercised against a mocked OpenBao (no real database needed for the config
layer; credential generation is mocked at the HTTP boundary)."""
import json

import responses

import openbao_dynamic_secrets as ds

ADDR = "http://127.0.0.1:8200"


@responses.activate
def test_enable_database_engine_new():
    responses.add(responses.POST, f"{ADDR}/v1/sys/mounts/database", status=204)
    assert ds.enable_database_engine(token="root", addr=ADDR) is True


@responses.activate
def test_enable_database_engine_idempotent():
    responses.add(responses.POST, f"{ADDR}/v1/sys/mounts/database",
                  json={"errors": ["path is already in use at database/"]},
                  status=400)
    assert ds.enable_database_engine(token="root", addr=ADDR) is True


@responses.activate
def test_configure_connection():
    responses.add(responses.POST, f"{ADDR}/v1/database/config/mydb", status=204)
    ds.configure_connection(
        "mydb", plugin_name="postgresql-database-plugin",
        connection_url="postgresql://{{username}}:{{password}}@db:5432/app",
        allowed_roles=["app-role"], username="vaultadmin", password="pw",
        token="root", addr=ADDR)
    body = json.loads(responses.calls[0].request.body)
    assert body["plugin_name"] == "postgresql-database-plugin"
    assert body["allowed_roles"] == "app-role"       # list joined to CSV


@responses.activate
def test_create_role():
    responses.add(responses.POST, f"{ADDR}/v1/database/roles/app-role", status=204)
    ds.create_role("app-role", db_name="mydb",
                   creation_statements="CREATE ROLE x;",
                   default_ttl="1h", max_ttl="24h", token="root", addr=ADDR)
    body = json.loads(responses.calls[0].request.body)
    assert body["db_name"] == "mydb"
    assert body["creation_statements"] == ["CREATE ROLE x;"]   # str wrapped to list


@responses.activate
def test_generate_credentials():
    responses.add(responses.GET, f"{ADDR}/v1/database/creds/app-role",
                  json={"lease_id": "database/creds/app-role/abc",
                        "lease_duration": 3600,
                        "data": {"username": "v-app-xyz", "password": "s3cret"}},
                  status=200)
    c = ds.generate_credentials("app-role", token="root", addr=ADDR)
    assert c["username"] == "v-app-xyz" and c["password"] == "s3cret"
    assert c["lease_id"].endswith("/abc") and c["lease_duration"] == 3600


@responses.activate
def test_renew_lease():
    responses.add(responses.PUT, f"{ADDR}/v1/sys/leases/renew",
                  json={"lease_id": "lid", "lease_duration": 7200}, status=200)
    out = ds.renew_lease("lid", increment=7200, token="root", addr=ADDR)
    assert out["lease_duration"] == 7200


@responses.activate
def test_revoke_lease():
    responses.add(responses.PUT, f"{ADDR}/v1/sys/leases/revoke", status=204)
    assert ds.revoke_lease("lid", token="root", addr=ADDR) is True


@responses.activate
def test_enable_database_engine_raises_on_real_error():
    # a non-"already in use" 400 must raise, not be swallowed
    responses.add(responses.POST, f"{ADDR}/v1/sys/mounts/database",
                  json={"errors": ["permission denied"]}, status=403)
    import pytest
    with pytest.raises(ds.OpenBaoError if hasattr(ds, "OpenBaoError") else Exception):
        ds.enable_database_engine(token="root", addr=ADDR)
