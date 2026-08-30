#!/usr/bin/env python3
# test_main.py
# Endpoint tests for main.py using FastAPI's TestClient.
#
# The app's lifespan reaches out to Keycloak/Auth0 on startup, so we DON'T run
# it. Instead we import the app, bypass the lifespan, and monkeypatch the
# module-level globals (keycloak_oidc, user_manager, public_pem) that the
# endpoints read. This isolates each route's logic from any live services.
#
# Run with:   pytest test_main.py -v
# Requires:   pip install pytest fastapi httpx

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import MagicMock, create_autospec

import pytest
import responses
from fastapi.testclient import TestClient

import main


# Replace the real lifespan with a no-op so importing the app for tests does
# not try to contact Keycloak/Auth0. We patch globals per-test instead.
@asynccontextmanager
async def _noop_lifespan(app):
    yield


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main.app.router, "lifespan_context", _noop_lifespan)
    with TestClient(main.app) as c:
        yield c


# ──────────────────────────────────────────────
# Static / always-on endpoints
# ──────────────────────────────────────────────
def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"message": "Hello, World!"}

def test_hello(client):
    r = client.get("/hello", params={"email": "a@x.com", "username": "alice"})
    assert r.status_code == 200
    assert r.json() == {"email": "a@x.com", "username": "alice"}

def test_keys_uninitialised_returns_503(client, monkeypatch):
    monkeypatch.setattr(main, "public_pem", b"")
    r = client.get("/keys")
    assert r.status_code == 503

def test_keys_initialised(client, monkeypatch):
    monkeypatch.setattr(main, "public_pem", b"PEMDATA")
    r = client.get("/keys")
    assert r.status_code == 200
    assert r.json() == {"public_key": "PEMDATA"}


# ──────────────────────────────────────────────
# /token  (Keycloak login)
# ──────────────────────────────────────────────
def test_token_service_unavailable_when_oidc_none(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", None)
    r = client.post("/token", data={"username": "u", "password": "p"})
    assert r.status_code == 503

def test_token_success(client, monkeypatch):
    fake = MagicMock()
    fake.token.return_value = {"access_token": "abc"}
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.post("/token", data={"username": "u", "password": "p"})
    assert r.status_code == 200
    assert r.json() == {"access_token": "abc", "token_type": "bearer"}

def test_token_invalid_credentials(client, monkeypatch):
    from keycloak.exceptions import KeycloakAuthenticationError
    fake = MagicMock()
    fake.token.side_effect = KeycloakAuthenticationError("bad")
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.post("/token", data={"username": "u", "password": "wrong"})
    assert r.status_code == 401


# ──────────────────────────────────────────────
# /protected  (Keycloak introspection)
# ──────────────────────────────────────────────
def test_protected_active_token(client, monkeypatch):
    fake = MagicMock()
    fake.introspect.return_value = {"active": True, "preferred_username": "bob"}
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.get("/protected", headers={"Authorization": "Bearer good"})
    assert r.status_code == 200
    assert "bob" in r.json()["message"]

def test_protected_inactive_token(client, monkeypatch):
    fake = MagicMock()
    fake.introspect.return_value = {"active": False}
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.get("/protected", headers={"Authorization": "Bearer stale"})
    assert r.status_code == 401

def test_protected_requires_credentials(client, monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.get("/protected")  # no Authorization header
    # HTTPBearer returns 401 when the Authorization header is absent
    assert r.status_code == 401

def test_protected_introspect_returns_none(client, monkeypatch):
    # P2 regression: introspect returning None must yield 401, not an unhandled 500
    fake = MagicMock()
    fake.introspect.return_value = None
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.get("/protected", headers={"Authorization": "Bearer x"})
    assert r.status_code == 401


# ──────────────────────────────────────────────
# /oidc-token  (Keycloak introspection via OAuth2 scheme)
# ──────────────────────────────────────────────
def test_oidc_token_unavailable_when_oidc_none(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", None)
    r = client.post("/oidc-token", headers={"Authorization": "Bearer x"})
    assert r.status_code == 503

def test_oidc_token_active(client, monkeypatch):
    fake = MagicMock()
    fake.introspect.return_value = {"active": True, "preferred_username": "carol"}
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.post("/oidc-token", headers={"Authorization": "Bearer good"})
    assert r.status_code == 200
    assert "carol" in r.json()["message"]

def test_oidc_token_inactive(client, monkeypatch):
    fake = MagicMock()
    fake.introspect.return_value = {"active": False}
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.post("/oidc-token", headers={"Authorization": "Bearer stale"})
    assert r.status_code == 401

def test_oidc_token_introspect_returns_none(client, monkeypatch):
    # P2 regression for the /oidc-token path
    fake = MagicMock()
    fake.introspect.return_value = None
    monkeypatch.setattr(main, "keycloak_oidc", fake)
    r = client.post("/oidc-token", headers={"Authorization": "Bearer x"})
    assert r.status_code == 401


# ──────────────────────────────────────────────
# /register  (UserManager.add_user)
# ──────────────────────────────────────────────
def test_register_unavailable_when_manager_none(client, monkeypatch):
    monkeypatch.setattr(main, "user_manager", None)
    r = client.post("/register", data={"email": "a@x.com", "password": "pw"})
    assert r.status_code == 503

def test_register_success(client, monkeypatch):
    mgr = MagicMock()
    mgr.add_user.return_value = {
        "username": "alice-ab12cd",
        "email": "alice@x.com",
        "keycloak_id": "kc-1",
        "auth0_id": "auth0|1",
        "pre_existing": "neither",
    }
    monkeypatch.setattr(main, "user_manager", mgr)
    r = client.post("/register", data={"email": "alice@x.com", "password": "pw"})
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "alice-ab12cd"
    assert body["keycloak_id"] == "kc-1"
    assert body["auth0_id"] == "auth0|1"
    mgr.add_user.assert_called_once_with(email="alice@x.com", password="pw", username=None)

def test_register_runtime_error_becomes_502(client, monkeypatch):
    mgr = MagicMock()
    mgr.add_user.side_effect = RuntimeError("missing read:users scope")
    monkeypatch.setattr(main, "user_manager", mgr)
    r = client.post("/register", data={"email": "a@x.com", "password": "pw"})
    assert r.status_code == 502
    assert "read:users" in r.json()["detail"]

def test_register_unexpected_error_becomes_500(client, monkeypatch):
    mgr = MagicMock()
    mgr.add_user.side_effect = ValueError("boom")
    monkeypatch.setattr(main, "user_manager", mgr)
    r = client.post("/register", data={"email": "a@x.com", "password": "pw"})
    assert r.status_code == 500

def test_register_missing_email_is_422(client, monkeypatch):
    # Migrated from tests.py: posting the OLD username/password shape (no email)
    # is now a FastAPI validation error, documenting the breaking signature change.
    monkeypatch.setattr(main, "user_manager", MagicMock())
    r = client.post("/register", data={"username": "newuser", "password": "secret"})
    assert r.status_code == 422


# ──────────────────────────────────────────────
# /users/lookup  (UserManager.determine_user_system) — now AUTH-PROTECTED
# ──────────────────────────────────────────────
def _auth_override():
    """Dependency override that simulates a valid authenticated Keycloak token.

    Includes the admin role AND a broad org membership so functional tests of
    admin/org endpoints represent an authorized caller acting within their
    tenant. The organizations list covers the org ids/names these tests use, so
    tenant scoping (enforce_org_access) passes. Cross-tenant DENIAL is covered by
    the dedicated tests in test_authz.py, which use a token scoped to one org.
    """
    return {"active": True, "preferred_username": "caller",
            "realm_access": {"roles": ["tenant-admin"]},
            "organizations": ["org_1", "acme", "o"]}

def test_lookup_requires_authentication(client, monkeypatch):
    # No auth override and no keycloak_oidc -> request must be rejected, NOT served.
    monkeypatch.setattr(main, "keycloak_oidc", None)
    mgr = MagicMock()
    monkeypatch.setattr(main, "user_manager", mgr)
    r = client.get("/users/lookup", params={"username": "u", "email": "e@x.com"})
    assert r.status_code in (401, 403, 503)
    # Crucially, the lookup logic must NOT have run for an unauthenticated caller
    mgr.determine_user_system.assert_not_called()

def test_lookup_unavailable_when_manager_none(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        monkeypatch.setattr(main, "user_manager", None)
        r = client.get("/users/lookup", params={"username": "u", "email": "e@x.com"})
        assert r.status_code == 503
    finally:
        main.app.dependency_overrides.clear()

def test_lookup_success(client, monkeypatch):
    from auth0_type import UserSystem
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.determine_user_system.return_value = UserSystem.BOTH
        monkeypatch.setattr(main, "user_manager", mgr)
        mgr.get_user_org_refs.return_value = ["org_1"]  # target shares caller org
        r = client.get("/users/lookup", params={"username": "u", "email": "e@x.com"})
        assert r.status_code == 200
        assert r.json()["system"] == "both"
    finally:
        main.app.dependency_overrides.clear()

def test_lookup_runtime_error_becomes_502(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.determine_user_system.side_effect = RuntimeError("missing read:users scope")
        monkeypatch.setattr(main, "user_manager", mgr)
        mgr.get_user_org_refs.return_value = ["org_1"]  # target shares caller org
        r = client.get("/users/lookup", params={"username": "u", "email": "e@x.com"})
        assert r.status_code == 502
        assert "read:users" in r.json()["detail"]
    finally:
        main.app.dependency_overrides.clear()


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


# ──────────────────────────────────────────────
# setup_keycloak secret wiring (regression for the "secret never wired" bug)
# ──────────────────────────────────────────────
def test_setup_keycloak_returns_existing_secret(monkeypatch):
    import main as m
    fake_admin = MagicMock()
    fake_admin.get_authentication_flows.return_value = [{"alias": "Hello-World-flow"}]
    fake_admin.get_client_id.return_value = "uuid-1"
    fake_admin.get_client_secrets.return_value = {"value": "real-kc-secret"}
    monkeypatch.setattr(m, "KeycloakAdmin", lambda **kw: fake_admin)
    monkeypatch.setattr(m, "_ensure_realm", lambda *a, **k: None)
    monkeypatch.setattr(m, "create_keycloak_user", lambda *a, **k: "uid")
    monkeypatch.delenv("KEYCLOAK_CLIENT_SECRET", raising=False)
    secret = m.setup_keycloak()
    assert secret == "real-kc-secret"   # the REAL secret, not a placeholder

def test_setup_keycloak_creates_secret_when_missing(monkeypatch):
    import main as m
    fake_admin = MagicMock()
    fake_admin.get_authentication_flows.return_value = [{"alias": "Hello-World-flow"}]
    fake_admin.get_client_id.return_value = "uuid-1"
    fake_admin.get_client_secrets.return_value = {"value": None}
    fake_admin.generate_client_secrets.return_value = {"value": "newly-created"}
    monkeypatch.setattr(m, "KeycloakAdmin", lambda **kw: fake_admin)
    monkeypatch.setattr(m, "_ensure_realm", lambda *a, **k: None)
    monkeypatch.setattr(m, "create_keycloak_user", lambda *a, **k: "uid")
    monkeypatch.delenv("KEYCLOAK_CLIENT_SECRET", raising=False)
    secret = m.setup_keycloak()
    assert secret == "newly-created"
    fake_admin.generate_client_secrets.assert_called_once()

def test_setup_keycloak_env_override_wins(monkeypatch):
    import main as m
    fake_admin = MagicMock()
    fake_admin.get_authentication_flows.return_value = [{"alias": "Hello-World-flow"}]
    fake_admin.get_client_id.return_value = "uuid-1"
    fake_admin.get_client_secrets.return_value = {"value": "kc-secret"}
    monkeypatch.setattr(m, "KeycloakAdmin", lambda **kw: fake_admin)
    monkeypatch.setattr(m, "_ensure_realm", lambda *a, **k: None)
    monkeypatch.setattr(m, "create_keycloak_user", lambda *a, **k: "uid")
    monkeypatch.setenv("KEYCLOAK_CLIENT_SECRET", "env-override")
    secret = m.setup_keycloak()
    assert secret == "env-override"   # explicit env var takes precedence


# ──────────────────────────────────────────────
# /users/membership  (UserManager.get_membership) — AUTH-PROTECTED
# ──────────────────────────────────────────────
def test_membership_requires_authentication(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", None)
    mgr = MagicMock()
    monkeypatch.setattr(main, "user_manager", mgr)
    r = client.get("/users/membership", params={"username": "u", "email": "e@x.com"})
    assert r.status_code in (401, 403, 503)
    mgr.get_membership.assert_not_called()

def test_membership_unavailable_when_manager_none(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        monkeypatch.setattr(main, "user_manager", None)
        r = client.get("/users/membership", params={"username": "u", "email": "e@x.com"})
        assert r.status_code == 503
    finally:
        main.app.dependency_overrides.clear()

def test_membership_success(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.get_membership.return_value = {
            "username": "u", "email": "e@x.com",
            "keycloak": {"found": True, "groups": [], "roles": {"realm": [], "client": []}},
            "auth0": {"found": False, "groups": [], "roles": []},
            "correlation": {"groups_in_both": [], "roles_in_both": []},
        }
        monkeypatch.setattr(main, "user_manager", mgr)
        mgr.get_user_org_refs.return_value = ["org_1"]  # target shares caller org
        r = client.get("/users/membership", params={"username": "u", "email": "e@x.com"})
        assert r.status_code == 200
        assert r.json()["keycloak"]["found"] is True
    finally:
        main.app.dependency_overrides.clear()

def test_membership_runtime_error_becomes_502(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.get_membership.side_effect = RuntimeError("missing read:roles scope")
        monkeypatch.setattr(main, "user_manager", mgr)
        mgr.get_user_org_refs.return_value = ["org_1"]  # target shares caller org
        r = client.get("/users/membership", params={"username": "u", "email": "e@x.com"})
        assert r.status_code == 502
        assert "read:roles" in r.json()["detail"]
    finally:
        main.app.dependency_overrides.clear()


# ──────────────────────────────────────────────
# /groups  and  /users/groups  — group management (AUTH-PROTECTED)
# ──────────────────────────────────────────────
def test_create_group_requires_auth(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", None)
    mgr = MagicMock()
    monkeypatch.setattr(main, "user_manager", mgr)
    r = client.post("/groups", data={"name": "admins"})
    assert r.status_code in (401, 403, 503)
    mgr.create_group.assert_not_called()

def test_create_group_success(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.create_group.return_value = {"keycloak_id": "g-1", "auth0_group": None}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/groups", data={"name": "admins"})
        assert r.status_code == 200
        assert r.json()["keycloak_id"] == "g-1"
        mgr.create_group.assert_called_once_with("admins", parent_path=None)
    finally:
        main.app.dependency_overrides.clear()

def test_create_subgroup_passes_parent(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.create_group.return_value = {"keycloak_id": "sub-1", "auth0_group": None}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/groups", data={"name": "billing", "parent_path": "/finance"})
        assert r.status_code == 200
        mgr.create_group.assert_called_once_with("billing", parent_path="/finance")
    finally:
        main.app.dependency_overrides.clear()

def test_create_group_missing_parent_is_400(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.create_group.side_effect = ValueError("Keycloak parent group '/x' not found")
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/groups", data={"name": "billing", "parent_path": "/x"})
        assert r.status_code == 400
    finally:
        main.app.dependency_overrides.clear()

def test_modify_group_membership_add(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.set_group_membership.return_value = {"keycloak": "added", "auth0": "skipped"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/users/groups", data={
            "username": "u", "email": "e@x.com", "group_name": "admins", "action": "add",
        })
        assert r.status_code == 200
        assert r.json()["keycloak"] == "added"
        mgr.set_group_membership.assert_called_once_with("u", "e@x.com", "admins", add=True)
    finally:
        main.app.dependency_overrides.clear()

def test_modify_group_membership_revoke(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.set_group_membership.return_value = {"keycloak": "removed", "auth0": "skipped"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/users/groups", data={
            "username": "u", "email": "e@x.com", "group_name": "admins", "action": "revoke",
        })
        assert r.status_code == 200
        mgr.set_group_membership.assert_called_once_with("u", "e@x.com", "admins", add=False)
    finally:
        main.app.dependency_overrides.clear()

def test_modify_group_membership_bad_action_is_422(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        monkeypatch.setattr(main, "user_manager", MagicMock())
        r = client.post("/users/groups", data={
            "username": "u", "email": "e@x.com", "group_name": "admins", "action": "frobnicate",
        })
        assert r.status_code == 422
    finally:
        main.app.dependency_overrides.clear()


# ──────────────────────────────────────────────
# /users/roles — role assign/revoke (AUTH-PROTECTED)
# ──────────────────────────────────────────────
def test_role_change_requires_auth(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", None)
    mgr = MagicMock()
    monkeypatch.setattr(main, "user_manager", mgr)
    r = client.post("/users/roles", data={
        "username": "u", "email": "e@x.com", "role_name": "admin", "action": "assign",
    })
    assert r.status_code in (401, 403, 503)
    mgr.set_role.assert_not_called()

def test_role_assign_success(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.set_role.return_value = {"keycloak": "assigned", "auth0": "assigned"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/users/roles", data={
            "username": "u", "email": "e@x.com", "role_name": "admin", "action": "assign",
        })
        assert r.status_code == 200
        assert r.json()["keycloak"] == "assigned"
        mgr.set_role.assert_called_once_with("u", "e@x.com", "admin", assign=True)
    finally:
        main.app.dependency_overrides.clear()

def test_role_revoke_success(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.set_role.return_value = {"keycloak": "revoked", "auth0": "revoked"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/users/roles", data={
            "username": "u", "email": "e@x.com", "role_name": "admin", "action": "revoke",
        })
        assert r.status_code == 200
        mgr.set_role.assert_called_once_with("u", "e@x.com", "admin", assign=False)
    finally:
        main.app.dependency_overrides.clear()

def test_role_bad_action_is_422(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        monkeypatch.setattr(main, "user_manager", MagicMock())
        r = client.post("/users/roles", data={
            "username": "u", "email": "e@x.com", "role_name": "admin", "action": "nope",
        })
        assert r.status_code == 422
    finally:
        main.app.dependency_overrides.clear()

def test_role_unavailable_when_manager_none(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        monkeypatch.setattr(main, "user_manager", None)
        r = client.post("/users/roles", data={
            "username": "u", "email": "e@x.com", "role_name": "admin", "action": "assign",
        })
        assert r.status_code == 503
    finally:
        main.app.dependency_overrides.clear()


# ──────────────────────────────────────────────
# Group update/delete + Organizations endpoints (AUTH-PROTECTED)
# ──────────────────────────────────────────────
def test_update_group_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.update_group.return_value = {"keycloak": "updated", "auth0": "skipped"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.patch("/groups", data={"group": "/admins", "new_name": "superadmins"})
        assert r.status_code == 200
        mgr.update_group.assert_called_once_with("/admins", "superadmins")
    finally:
        main.app.dependency_overrides.clear()

def test_delete_group_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.delete_group.return_value = {"keycloak": "deleted", "auth0": "skipped"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.delete("/groups", params={"group": "/admins"})
        assert r.status_code == 200
        mgr.delete_group.assert_called_once_with("/admins")
    finally:
        main.app.dependency_overrides.clear()

def test_group_endpoints_require_auth(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", None)
    monkeypatch.setattr(main, "user_manager", MagicMock())
    assert client.patch("/groups", data={"group": "g", "new_name": "n"}).status_code in (401, 403, 503)
    assert client.request("DELETE", "/groups", params={"group": "g"}).status_code in (401, 403, 503)

def _mgr_with_orgs():
    mgr = MagicMock()
    mgr.auth0_orgs = MagicMock()
    return mgr

def test_create_organization_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = _mgr_with_orgs()
        mgr.auth0_orgs.create_organization.return_value = {"id": "org_1", "name": "acme"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/organizations", data={"name": "acme"})
        assert r.status_code == 200
        assert r.json()["id"] == "org_1"
    finally:
        main.app.dependency_overrides.clear()

def test_organizations_unavailable_without_orgs_api(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.auth0_orgs = None   # orgs API not configured
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.get("/organizations")
        assert r.status_code == 503
    finally:
        main.app.dependency_overrides.clear()

def test_list_organizations_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = _mgr_with_orgs()
        mgr.auth0_orgs.list_organizations.return_value = [{"id": "org_1"}]
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.get("/organizations")
        assert r.status_code == 200
        assert r.json()["organizations"][0]["id"] == "org_1"
    finally:
        main.app.dependency_overrides.clear()

def test_update_organization_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = _mgr_with_orgs()
        mgr.auth0_orgs.update_organization.return_value = {"id": "org_1", "display_name": "Acme"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.patch("/organizations/org_1", data={"display_name": "Acme"})
        assert r.status_code == 200
        mgr.auth0_orgs.update_organization.assert_called_once_with("org_1", display_name="Acme")
    finally:
        main.app.dependency_overrides.clear()

def test_delete_organization_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = _mgr_with_orgs()
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.delete("/organizations/org_1")
        assert r.status_code == 200
        assert r.json()["deleted"] == "org_1"
        mgr.auth0_orgs.delete_organization.assert_called_once_with("org_1")
    finally:
        main.app.dependency_overrides.clear()

def test_org_membership_endpoint_add(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = _mgr_with_orgs()
        mgr.set_organization_membership.return_value = "added"
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/organizations/members", data={
            "email": "u@x.com", "org_name": "acme", "action": "add",
        })
        assert r.status_code == 200
        assert r.json()["status"] == "added"
        mgr.set_organization_membership.assert_called_once_with("u@x.com", "acme", add=True)
    finally:
        main.app.dependency_overrides.clear()

def test_org_membership_endpoint_bad_action(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = _mgr_with_orgs()
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/organizations/members", data={
            "email": "u@x.com", "org_name": "acme", "action": "nope",
        })
        assert r.status_code == 422
    finally:
        main.app.dependency_overrides.clear()


def test_create_organization_invalid_name_is_400(client, monkeypatch):
    # Q3: an unconvertible org name should surface as 400, not 500.
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = _mgr_with_orgs()
        mgr.auth0_orgs.create_organization.side_effect = ValueError(
            "'x' cannot be converted to a valid Auth0 organization name")
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/organizations", data={"name": "x"})
        assert r.status_code == 400
    finally:
        main.app.dependency_overrides.clear()


# ──────────────────────────────────────────────
# _setup_keycloak_with_retry — container startup resilience
# ──────────────────────────────────────────────
def test_setup_keycloak_retry_succeeds_after_transient_failure(monkeypatch):
    import main as m
    monkeypatch.setenv("KEYCLOAK_STARTUP_RETRIES", "5")
    monkeypatch.setenv("KEYCLOAK_STARTUP_BACKOFF", "0")  # no real waiting in tests
    calls = {"n": 0}
    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("Keycloak not up yet")
        return "the-secret"
    monkeypatch.setattr(m, "setup_keycloak", flaky)
    monkeypatch.setattr(m.time if hasattr(m, "time") else __import__("time"),
                        "sleep", lambda *_: None)
    assert m._setup_keycloak_with_retry() == "the-secret"
    assert calls["n"] == 3  # failed twice, succeeded on the third

def test_setup_keycloak_retry_gives_up_after_max(monkeypatch):
    import main as m
    monkeypatch.setenv("KEYCLOAK_STARTUP_RETRIES", "3")
    monkeypatch.setenv("KEYCLOAK_STARTUP_BACKOFF", "0")
    calls = {"n": 0}
    def always_fail():
        calls["n"] += 1
        raise ConnectionError("down")
    monkeypatch.setattr(m, "setup_keycloak", always_fail)
    monkeypatch.setattr(__import__("time"), "sleep", lambda *_: None)
    with pytest.raises(RuntimeError, match="failed after 3 attempts"):
        m._setup_keycloak_with_retry()
    assert calls["n"] == 3  # tried exactly the configured number of times

def test_setup_keycloak_retry_succeeds_first_try(monkeypatch):
    import main as m
    monkeypatch.setenv("KEYCLOAK_STARTUP_RETRIES", "5")
    monkeypatch.setattr(m, "setup_keycloak", lambda: "immediate")
    assert m._setup_keycloak_with_retry() == "immediate"


# ──────────────────────────────────────────────
# Lifecycle endpoints (AUTH-PROTECTED): /users/metadata, /users/active,
# /users/verify-email, /users/password-reset, /users/logout
# ──────────────────────────────────────────────
def test_lifecycle_endpoints_require_auth(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", None)
    mgr = MagicMock()
    monkeypatch.setattr(main, "user_manager", mgr)
    d = {"username": "u", "email": "e@x.com"}
    assert client.patch("/users/metadata", data={**d, "metadata": "{}"}).status_code in (401, 403, 503)
    assert client.post("/users/active", data={**d, "active": "true"}).status_code in (401, 403, 503)
    assert client.post("/users/verify-email", data={**d, "action": "set"}).status_code in (401, 403, 503)
    assert client.post("/users/password-reset", data=d).status_code in (401, 403, 503)
    assert client.post("/users/logout", data=d).status_code in (401, 403, 503)
    mgr.set_user_metadata.assert_not_called()
    mgr.logout_everywhere.assert_not_called()

def test_metadata_endpoint_success_and_bad_json(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.set_user_metadata.return_value = {"keycloak": "updated", "auth0": "updated"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.patch("/users/metadata", data={
            "username": "u", "email": "e@x.com", "metadata": '{"dept": "eng"}'})
        assert r.status_code == 200
        mgr.set_user_metadata.assert_called_once_with("u", "e@x.com", {"dept": "eng"})
        # invalid JSON -> 422
        r = client.patch("/users/metadata", data={
            "username": "u", "email": "e@x.com", "metadata": "not json"})
        assert r.status_code == 422
        # JSON but not an object -> 422
        r = client.patch("/users/metadata", data={
            "username": "u", "email": "e@x.com", "metadata": "[1,2]"})
        assert r.status_code == 422
    finally:
        main.app.dependency_overrides.clear()

def test_active_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.set_user_active.return_value = {"keycloak": "disabled", "auth0": "blocked"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/users/active", data={
            "username": "u", "email": "e@x.com", "active": "false"})
        assert r.status_code == 200
        mgr.set_user_active.assert_called_once_with("u", "e@x.com", False)
    finally:
        main.app.dependency_overrides.clear()

def test_verify_email_endpoint_actions(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.set_email_verified.return_value = {"keycloak": "set", "auth0": "set"}
        mgr.send_verification_email.return_value = {"keycloak": "sent", "auth0": "sent"}
        monkeypatch.setattr(main, "user_manager", mgr)
        d = {"username": "u", "email": "e@x.com"}
        assert client.post("/users/verify-email", data={**d, "action": "set"}).status_code == 200
        mgr.set_email_verified.assert_called_once_with("u", "e@x.com", True)
        assert client.post("/users/verify-email", data={**d, "action": "send"}).status_code == 200
        mgr.send_verification_email.assert_called_once_with("u", "e@x.com")
        assert client.post("/users/verify-email", data={**d, "action": "bogus"}).status_code == 422
    finally:
        main.app.dependency_overrides.clear()

def test_password_reset_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.trigger_password_reset.return_value = {
            "keycloak": "email-sent", "auth0": "ticket-created",
            "auth0_ticket": "https://x/r?t=1"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/users/password-reset", data={"username": "u", "email": "e@x.com"})
        assert r.status_code == 200
        assert r.json()["auth0_ticket"].startswith("https://")
    finally:
        main.app.dependency_overrides.clear()

def test_logout_endpoint(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.logout_everywhere.return_value = {
            "keycloak": "logged-out", "auth0": "sessions-and-grants-revoked"}
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/users/logout", data={"username": "u", "email": "e@x.com"})
        assert r.status_code == 200
        mgr.logout_everywhere.assert_called_once_with("u", "e@x.com")
    finally:
        main.app.dependency_overrides.clear()

def test_lifecycle_scope_errors_become_502(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.logout_everywhere.side_effect = RuntimeError("missing delete:grants scope")
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.post("/users/logout", data={"username": "u", "email": "e@x.com"})
        assert r.status_code == 502
        assert "delete:grants" in r.json()["detail"]
    finally:
        main.app.dependency_overrides.clear()


# ──────────────────────────────────────────────
# WebSocket GitHub relay (/ws/github) — auth handshake + relay
# ──────────────────────────────────────────────
class _FakeOIDC:
    """Stand-in for keycloak_oidc.introspect with controllable result."""
    def __init__(self, active=True):
        self._active = active
    def introspect(self, token):
        return {"active": self._active, "preferred_username": "nathan"}

def test_ws_requires_valid_token_first(client, monkeypatch):
    # A bad token must get auth_error and a closed socket.
    monkeypatch.setattr(main, "keycloak_oidc", _FakeOIDC(active=False))
    with client.websocket_connect("/ws/github") as ws:
        ws.send_json({"token": "bad"})
        reply = ws.receive_json()
        assert reply["type"] == "auth_error"

def test_ws_auth_ok_then_fetch(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", _FakeOIDC(active=True))
    # Patch fetch_github so the WS test doesn't hit the network.
    monkeypatch.setattr(main, "fetch_github",
                        lambda resource, params: {"status": 200,
                                                  "data": {"resource": resource,
                                                           "params": params}})
    with client.websocket_connect("/ws/github") as ws:
        ws.send_json({"token": "good"})
        assert ws.receive_json() == {"type": "auth_ok"}
        ws.send_json({"resource": "repo", "params": {"owner": "o", "repo": "r"}})
        result = ws.receive_json()
        assert result["type"] == "result"
        assert result["status"] == 200
        assert result["data"]["resource"] == "repo"

def test_ws_invalid_json_after_auth_is_reported(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", _FakeOIDC(active=True))
    with client.websocket_connect("/ws/github") as ws:
        ws.send_json({"token": "good"})
        ws.receive_json()  # auth_ok
        ws.send_text("not json{")
        err = ws.receive_json()
        assert err["type"] == "error" and "JSON" in err["detail"]

def test_ws_bad_params_type_reported(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", _FakeOIDC(active=True))
    with client.websocket_connect("/ws/github") as ws:
        ws.send_json({"token": "good"})
        ws.receive_json()
        ws.send_json({"resource": "repo", "params": "not-an-object"})
        err = ws.receive_json()
        assert err["type"] == "error" and "params" in err["detail"]

def test_ws_unavailable_when_oidc_none(client, monkeypatch):
    # If auth service is down, connecting client should get auth_error.
    monkeypatch.setattr(main, "keycloak_oidc", None)
    with client.websocket_connect("/ws/github") as ws:
        ws.send_json({"token": "whatever"})
        reply = ws.receive_json()
        assert reply["type"] == "auth_error"


# ──────────────────────────────────────────────
# W1/W2/W3 regressions: WS relay hardening
# ──────────────────────────────────────────────
def test_ws_non_object_json_reported_not_crash(client, monkeypatch):
    # W1: '42' is valid JSON but not an object — must get an error reply and
    # the connection must SURVIVE for the next message.
    monkeypatch.setattr(main, "keycloak_oidc", _FakeOIDC(active=True))
    monkeypatch.setattr(main, "fetch_github",
                        lambda r, p: {"status": 200, "data": {}})
    with client.websocket_connect("/ws/github") as ws:
        ws.send_json({"token": "good"})
        ws.receive_json()  # auth_ok
        ws.send_text("42")
        err = ws.receive_json()
        assert err["type"] == "error" and "object" in err["detail"]
        # connection still alive — a valid request works afterwards
        ws.send_json({"resource": "repo", "params": {"owner": "o", "repo": "r"}})
        assert ws.receive_json()["type"] == "result"

def test_ws_binary_frame_reported_not_crash(client, monkeypatch):
    # W3: binary frames must be reported, not crash the handler.
    monkeypatch.setattr(main, "keycloak_oidc", _FakeOIDC(active=True))
    with client.websocket_connect("/ws/github") as ws:
        ws.send_json({"token": "good"})
        ws.receive_json()
        ws.send_bytes(b"\x00\x01")
        err = ws.receive_json()
        assert err["type"] == "error" and "text frame" in err["detail"]

def test_fetch_github_rejects_path_injection():
    # W2: params must not escape the resource allow-list via '/', '?', etc.
    import main as m
    for bad in ({"owner": "octocat", "repo": "Hello-World/collaborators"},
                {"owner": "octocat/../../orgs", "repo": "x"},
                {"owner": "octocat", "repo": "x?per_page=100"},
                {"owner": "octocat", "repo": "x%2Fy"},
                {"owner": "", "repo": "x"},
                {"owner": 123, "repo": "x"}):
        out = m.fetch_github("repo", bad)
        assert out["status"] == 400 and "invalid value" in out["error"], bad

def test_fetch_github_accepts_legit_identifiers():
    # W2 must NOT break real GitHub names.
    import main as m
    import responses as rsp
    @rsp.activate
    def run():
        rsp.add(rsp.GET, "https://api.github.com/repos/octo-cat/Hello.World_2",
                json={"ok": True}, status=200)
        out = m.fetch_github("repo", {"owner": "octo-cat", "repo": "Hello.World_2"})
        assert out["status"] == 200
    run()


# ──────────────────────────────────────────────
# /secure-data (authorize router — previously untested endpoint)
# ──────────────────────────────────────────────
def test_secure_data_ok(client, monkeypatch):
    import authorize
    main.app.dependency_overrides[authorize.get_current_user] = \
        lambda: authorize.TokenData(username="nathan")
    try:
        monkeypatch.setattr(authorize, "get_auth0_token", lambda: "m2m-tok")
        r = client.get("/secure-data")
        assert r.status_code == 200
        assert r.json()["user"] == "nathan"
    finally:
        main.app.dependency_overrides.clear()

def test_secure_data_auth0_down_is_503(client, monkeypatch):
    import authorize
    main.app.dependency_overrides[authorize.get_current_user] = \
        lambda: authorize.TokenData(username="nathan")
    try:
        def boom():
            raise RuntimeError("kv exploded")
        monkeypatch.setattr(authorize, "get_auth0_token", boom)
        r = client.get("/secure-data")
        assert r.status_code == 503
    finally:
        main.app.dependency_overrides.clear()


# ──────────────────────────────────────────────
# init_rsa_keys + create_keycloak_user (previously untested startup helpers)
# ──────────────────────────────────────────────
def test_init_rsa_keys_creates_keypair_with_safe_perms(tmp_path, monkeypatch):
    import os, stat
    monkeypatch.setenv("KEY_DIR", str(tmp_path))
    main.init_rsa_keys()
    priv = tmp_path / "private.pem"
    pub = tmp_path / "public.pem"
    assert priv.exists() and pub.exists()
    mode = stat.S_IMODE(os.stat(priv).st_mode)
    assert mode == 0o600                       # private key not world-readable
    assert main.public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")

def test_init_rsa_keys_reuses_existing(tmp_path, monkeypatch):
    monkeypatch.setenv("KEY_DIR", str(tmp_path))
    main.init_rsa_keys()
    first = (tmp_path / "public.pem").read_bytes()
    main.init_rsa_keys()                       # second call must not regenerate
    assert (tmp_path / "public.pem").read_bytes() == first

def test_create_keycloak_user_existing_short_circuits():
    admin = MagicMock()
    admin.get_users.return_value = [{"id": "u-exists"}]
    out = main.create_keycloak_user(admin, "user", "pw", "users")
    assert out == "u-exists"
    admin.create_user.assert_not_called()

def test_create_keycloak_user_creates_group_if_missing():
    admin = MagicMock()
    admin.get_users.return_value = []
    admin.get_groups.return_value = [{"id": "g-other", "name": "other"}]
    admin.create_group.return_value = "g-new"
    admin.create_user.return_value = "u-new"
    out = main.create_keycloak_user(admin, "user", "pw", "users")
    assert out == "u-new"
    admin.create_group.assert_called_once_with({"name": "users"})
    admin.group_user_add.assert_called_once_with("u-new", "g-new")

def test_create_keycloak_user_finalizes_account():
    # Regression: a live Keycloak leaves the account "not fully set up" unless
    # we set email/emailVerified and clear required actions, which makes the
    # password grant fail with a generic 503. Assert the new user is created
    # with those fields AND finalized via update + password reset.
    admin = MagicMock()
    admin.get_users.return_value = []
    admin.get_groups.return_value = [{"id": "g", "name": "users"}]
    admin.create_user.return_value = "u-new"
    main.create_keycloak_user(admin, "user", "pw", "users")
    created = admin.create_user.call_args[0][0]
    assert created["emailVerified"] is True
    assert created["requiredActions"] == []
    assert created["email"]                       # a unique email is set
    admin.update_user.assert_called_once()
    admin.set_user_password.assert_called_once_with("u-new", "pw", temporary=False)

def test_create_keycloak_user_finalize_failure_is_not_fatal():
    # Finalization is best-effort: if update_user fails, the user id is still
    # returned (startup shouldn't crash over a profile tweak).
    admin = MagicMock()
    admin.get_users.return_value = []
    admin.get_groups.return_value = [{"id": "g", "name": "users"}]
    admin.create_user.return_value = "u-new"
    admin.update_user.side_effect = RuntimeError("kc rejected update")
    out = main.create_keycloak_user(admin, "user", "pw", "users")
    assert out == "u-new"     # no exception propagated


# ──────────────────────────────────────────────
# Endpoint error branches (RuntimeError -> 502, Exception -> 500)
# ──────────────────────────────────────────────
def test_group_endpoint_runtime_error_is_502(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.update_group.side_effect = RuntimeError("missing scope xyz")
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.patch("/groups", data={"group": "/g", "new_name": "n"})
        assert r.status_code == 502 and "xyz" in r.json()["detail"]
    finally:
        main.app.dependency_overrides.clear()

def test_metadata_endpoint_unexpected_error_is_500(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        mgr.set_user_metadata.side_effect = ValueError("boom")
        monkeypatch.setattr(main, "user_manager", mgr)
        r = client.patch("/users/metadata", data={
            "username": "u", "email": "e@x.com", "metadata": "{}"})
        assert r.status_code == 500
        assert "boom" not in r.json()["detail"]   # internals not leaked
    finally:
        main.app.dependency_overrides.clear()


# ──────────────────────────────────────────────
# Error-branch sweep: every mutating endpoint maps RuntimeError -> 502 and
# unexpected exceptions -> 500 (without leaking internals). One parametrized
# test covers all the copy-paste handlers.
# ──────────────────────────────────────────────
_ERROR_SWEEP = [
    ("patch",  "/groups", {"group": "/g", "new_name": "n"},
     lambda m: m.update_group),
    ("delete", "/groups", {"group": "/g"},
     lambda m: m.delete_group),
    ("post",   "/users/groups", {"username": "u", "email": "e@x", "group_name": "g", "action": "add"},
     lambda m: m.set_group_membership),
    ("post",   "/users/roles", {"username": "u", "email": "e@x", "role_name": "r", "action": "assign"},
     lambda m: m.set_role),
    ("post",   "/users/active", {"username": "u", "email": "e@x", "active": "true"},
     lambda m: m.set_user_active),
    ("post",   "/users/verify-email", {"username": "u", "email": "e@x", "action": "set"},
     lambda m: m.set_email_verified),
    ("post",   "/users/password-reset", {"username": "u", "email": "e@x"},
     lambda m: m.trigger_password_reset),
    ("post",   "/users/logout", {"username": "u", "email": "e@x"},
     lambda m: m.logout_everywhere),
    ("post",   "/organizations", {"name": "acme"},
     lambda m: m.auth0_orgs.create_organization),
    ("post",   "/organizations/members", {"email": "e@x", "org_name": "o", "action": "add"},
     lambda m: m.set_organization_membership),
]

@pytest.mark.parametrize("method,path,data,pick", _ERROR_SWEEP)
def test_endpoint_runtime_error_maps_to_502(client, monkeypatch, method, path, data, pick):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        pick(mgr).side_effect = RuntimeError("scope missing: xyz")
        monkeypatch.setattr(main, "user_manager", mgr)
        r = getattr(client, method)(path, **({"params": data} if method == "delete" else {"data": data}))
        assert r.status_code == 502, (path, r.status_code, r.text)
        assert "xyz" in r.json()["detail"]      # scope message surfaced to caller
    finally:
        main.app.dependency_overrides.clear()

@pytest.mark.parametrize("method,path,data,pick", _ERROR_SWEEP)
def test_endpoint_unexpected_error_maps_to_500(client, monkeypatch, method, path, data, pick):
    main.app.dependency_overrides[main.require_keycloak_auth] = _auth_override
    try:
        mgr = MagicMock()
        pick(mgr).side_effect = ValueError("internal-detail-abc")
        monkeypatch.setattr(main, "user_manager", mgr)
        r = getattr(client, method)(path, **({"params": data} if method == "delete" else {"data": data}))
        # /organizations create maps ValueError->400 by design (Q3); others 500.
        expected = 400 if path == "/organizations" else 500
        assert r.status_code == expected, (path, r.status_code, r.text)
        if expected == 500:
            assert "internal-detail-abc" not in r.json()["detail"]   # no leak
    finally:
        main.app.dependency_overrides.clear()


# ──────────────────────────────────────────────
# ensure_keycloak_client — ROOT-CAUSE fix for "Invalid parameter: redirect_uri".
# Uses create_autospec against the REAL KeycloakAdmin so a wrong method name
# fails the test (the M1 lesson: bare MagicMock hides AttributeError).
# ──────────────────────────────────────────────
from keycloak import KeycloakAdmin as _RealKCAdmin

def _kc_admin_autospec():
    return create_autospec(_RealKCAdmin, instance=True)

def test_ensure_client_creates_when_missing(monkeypatch):
    monkeypatch.setattr(main, "APP_REDIRECT_URI", "http://localhost:8000/callback")
    monkeypatch.setattr(main, "KEYCLOAK_CLIENT_ID", "Hello-World-app")
    admin = _kc_admin_autospec()
    admin.get_client_id.side_effect = [None, "new-uuid"]   # missing, then created
    uuid = main.ensure_keycloak_client(admin)
    assert uuid == "new-uuid"
    payload = admin.create_client.call_args[0][0]
    assert payload["clientId"] == "Hello-World-app"
    assert "http://localhost:8000/callback" in payload["redirectUris"]
    assert "http://localhost:8000/*" in payload["redirectUris"]
    assert payload["standardFlowEnabled"] is True   # browser login possible
    assert payload["serviceAccountsEnabled"] is True  # M2M client_credentials


def test_ensure_client_heals_service_accounts(monkeypatch):
    # An existing client missing serviceAccountsEnabled must get it healed, so
    # the /token/client (M2M) grant works.
    monkeypatch.setattr(main, "APP_REDIRECT_URI", "http://localhost:8000/callback")
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = {
        "clientId": "Hello-World-app", "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "redirectUris": ["http://localhost:8000/callback",
                         "http://localhost:8000/*"]}  # only SA missing
    main.ensure_keycloak_client(admin)
    sent = admin.update_client.call_args[0][1]
    assert sent["serviceAccountsEnabled"] is True

def test_ensure_client_adds_missing_redirect_uri(monkeypatch):
    monkeypatch.setattr(main, "APP_REDIRECT_URI", "http://localhost:8000/callback")
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = {
        "clientId": "Hello-World-app", "standardFlowEnabled": True,
        "redirectUris": ["http://localhost:8000/other"]}
    main.ensure_keycloak_client(admin)
    sent = admin.update_client.call_args[0][1]
    assert "http://localhost:8000/callback" in sent["redirectUris"]
    assert "http://localhost:8000/other" in sent["redirectUris"]   # preserved

def test_ensure_client_enables_standard_flow(monkeypatch):
    monkeypatch.setattr(main, "APP_REDIRECT_URI", "http://localhost:8000/callback")
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = {
        "clientId": "Hello-World-app", "standardFlowEnabled": False,
        "redirectUris": ["http://localhost:8000/callback",
                         "http://localhost:8000/*"]}
    main.ensure_keycloak_client(admin)
    sent = admin.update_client.call_args[0][1]
    assert sent["standardFlowEnabled"] is True

def test_ensure_client_noop_when_already_correct(monkeypatch):
    monkeypatch.setattr(main, "APP_REDIRECT_URI", "http://localhost:8000/callback")
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = {
        "clientId": "Hello-World-app", "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": True,
        "redirectUris": ["http://localhost:8000/callback",
                         "http://localhost:8000/*"]}
    main.ensure_keycloak_client(admin)
    admin.update_client.assert_not_called()   # no pointless write
    admin.create_client.assert_not_called()

def test_ensure_client_raises_if_creation_fails(monkeypatch):
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = None    # never resolves, even after create
    with pytest.raises(RuntimeError, match="Could not create or find"):
        main.ensure_keycloak_client(admin)

def test_setup_keycloak_provisions_client(monkeypatch):
    # The root-cause regression: setup_keycloak MUST provision the client's
    # redirect URIs, not just look the client up.
    called = {}
    monkeypatch.setattr(main, "ensure_keycloak_client",
                        lambda admin: called.setdefault("uuid", "uuid-1") or "uuid-1")
    fake_admin = _kc_admin_autospec()
    fake_admin.get_authentication_flows.return_value = [{"alias": "Hello-World-flow"}]
    fake_admin.get_client_secrets.return_value = {"value": "sec"}
    monkeypatch.setattr(main, "KeycloakAdmin", lambda **kw: fake_admin)
    monkeypatch.setattr(main, "_ensure_realm", lambda *a, **k: None)
    monkeypatch.setattr(main, "create_keycloak_user", lambda *a, **k: "u-1")
    monkeypatch.delenv("KEYCLOAK_CLIENT_SECRET", raising=False)
    assert main.setup_keycloak() == "sec"
    assert called["uuid"] == "uuid-1"   # provisioning ran

def test_ensure_client_survives_unexpected_representation(monkeypatch):
    # Defensive guard: a non-dict from get_client must not crash startup
    # (same class as the P2 introspect fix).
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = []          # unexpected shape
    assert main.ensure_keycloak_client(admin) == "uuid-1"
    admin.update_client.assert_not_called()


# ── rate limiting on /token and /register ───────────────────────────────────
def test_token_rate_limited_after_threshold(client, monkeypatch):
    import rate_limit
    monkeypatch.setenv("RATE_LIMIT_LOGIN_MAX", "3")
    monkeypatch.setenv("RATE_LIMIT_LOGIN_WINDOW", "60")
    rate_limit.reset_all()
    # keycloak_oidc is None in tests -> endpoint returns 503, but the RATE LIMIT
    # runs first. The 4th call within the window must be 429 regardless.
    monkeypatch.setattr(main, "keycloak_oidc", None)
    statuses = [client.post("/token", data={"username": "u", "password": "p"}).status_code
                for _ in range(4)]
    assert statuses[:3] == [503, 503, 503]   # allowed through to the handler
    assert statuses[3] == 429                 # blocked by the limiter
    rate_limit.reset_all()

def test_token_429_includes_retry_after(client, monkeypatch):
    import rate_limit
    monkeypatch.setenv("RATE_LIMIT_LOGIN_MAX", "1")
    rate_limit.reset_all()
    monkeypatch.setattr(main, "keycloak_oidc", None)
    client.post("/token", data={"username": "u", "password": "p"})
    r = client.post("/token", data={"username": "u", "password": "p"})
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    rate_limit.reset_all()

def test_register_rate_limited(client, monkeypatch):
    import rate_limit
    monkeypatch.setenv("RATE_LIMIT_REGISTER_MAX", "2")
    rate_limit.reset_all()
    monkeypatch.setattr(main, "user_manager", None)   # -> 503 from handler
    statuses = [client.post("/register",
                            data={"email": f"a{i}@b.com", "password": "x"}).status_code
                for i in range(3)]
    assert statuses[2] == 429     # third within window blocked
    rate_limit.reset_all()

def test_rate_limit_fails_open_on_limiter_error(client, monkeypatch):
    # If the limiter itself raises, the request must still be ALLOWED through to
    # the handler (fail-open) — a security add-on must not break login.
    import rate_limit
    rate_limit.reset_all()
    def boom():
        raise RuntimeError("limiter exploded")
    monkeypatch.setattr(rate_limit, "login_limiter", boom)
    monkeypatch.setattr(main, "keycloak_oidc", None)
    r = client.post("/token", data={"username": "u", "password": "p"})
    assert r.status_code == 503    # reached the handler, not blocked
    rate_limit.reset_all()


# ── _ensure_realm: the fresh-Keycloak bootstrap fix ─────────────────────────
@responses.activate
def test_ensure_realm_creates_when_missing():
    import main
    base = "http://kc:8080"
    responses.add(responses.POST,
                  f"{base}/realms/master/protocol/openid-connect/token",
                  json={"access_token": "adm"}, status=200)
    responses.add(responses.GET, f"{base}/admin/realms/Premkey", status=404)
    responses.add(responses.POST, f"{base}/admin/realms", status=201)
    main._ensure_realm(base, "Premkey", "admin", "admin")
    # The realm creation POST must have fired with the right body.
    create = [c for c in responses.calls if c.request.method == "POST"
              and c.request.url.endswith("/admin/realms")][0]
    import json as _j
    body = _j.loads(create.request.body)
    assert body["realm"] == "Premkey" and body["enabled"] is True

@responses.activate
def test_ensure_realm_skips_when_present():
    import main
    base = "http://kc:8080"
    responses.add(responses.POST,
                  f"{base}/realms/master/protocol/openid-connect/token",
                  json={"access_token": "adm"}, status=200)
    responses.add(responses.GET, f"{base}/admin/realms/Premkey",
                  json={"realm": "Premkey"}, status=200)
    main._ensure_realm(base, "Premkey", "admin", "admin")
    # No creation POST when the realm already exists.
    assert not [c for c in responses.calls if c.request.method == "POST"
                and c.request.url.endswith("/admin/realms")]

@responses.activate
def test_ensure_realm_tolerates_concurrent_creation():
    import main
    base = "http://kc:8080"
    responses.add(responses.POST,
                  f"{base}/realms/master/protocol/openid-connect/token",
                  json={"access_token": "adm"}, status=200)
    responses.add(responses.GET, f"{base}/admin/realms/Premkey", status=404)
    responses.add(responses.POST, f"{base}/admin/realms", status=409)  # race
    # 409 (already created by another worker) must NOT raise.
    main._ensure_realm(base, "Premkey", "admin", "admin")

@responses.activate
def test_ensure_realm_raises_on_bad_admin_credentials():
    import main
    base = "http://kc:8080"
    responses.add(responses.POST,
                  f"{base}/realms/master/protocol/openid-connect/token",
                  json={"error": "invalid_grant"}, status=401)
    with pytest.raises(Exception):
        main._ensure_realm(base, "Premkey", "admin", "wrong")


# ── 503 handlers must LOG the real cause (operability regression guard) ──────
def test_token_503_logs_real_error(client, monkeypatch, caplog):
    import rate_limit
    rate_limit.reset_all()
    class Boom:
        def token(self, u, p):
            raise RuntimeError("kc-token-boom")
    monkeypatch.setattr(main, "keycloak_oidc", Boom())
    with caplog.at_level("ERROR", logger="main"):
        r = client.post("/token", data={"username": "u", "password": "p"})
    assert r.status_code == 503
    # client gets a generic message, server log has the real cause
    assert r.json() == {"detail": "Authentication service unavailable"}
    assert "kc-token-boom" in caplog.text
    rate_limit.reset_all()

def test_oidc_token_503_logs_real_error(client, monkeypatch, caplog):
    class Boom:
        def introspect(self, t):
            raise RuntimeError("kc-introspect-boom")
    monkeypatch.setattr(main, "keycloak_oidc", Boom())
    with caplog.at_level("ERROR", logger="main"):
        r = client.post("/oidc-token", headers={"Authorization": "Bearer x"})
    assert r.status_code == 503
    assert "kc-introspect-boom" in caplog.text

def test_write_atomic_reraises_on_failure(tmp_path, monkeypatch):
    # A failed key write must propagate, not be silently swallowed.
    import main
    target = str(tmp_path / "sub" / "key.pem")   # parent dir doesn't exist
    # mkstemp will fail because the dir is missing -> must raise, not return None
    with pytest.raises(Exception):
        main._write_atomic(target, b"data")


def test_ensure_client_heals_direct_access_grants(monkeypatch):
    # Regression: an EXISTING client created without directAccessGrantsEnabled
    # must be healed, or every /token password grant fails with
    # 'unauthorized_client'. The create path set this; the update path did not.
    admin = MagicMock()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = {
        "clientId": "Hello-World-app",
        "redirectUris": ["http://localhost:8000/callback",
                         "http://localhost:8000/*"],
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,   # the broken state
    }
    main.ensure_keycloak_client(admin)
    # update_client must have been called with the flag flipped on
    assert admin.update_client.called
    sent = admin.update_client.call_args[0][1]
    assert sent["directAccessGrantsEnabled"] is True

def test_ensure_client_no_update_when_already_correct(monkeypatch):
    # If the existing client is already fully configured, no update is issued.
    admin = MagicMock()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = {
        "clientId": "Hello-World-app",
        "redirectUris": ["http://localhost:8000/callback",
                         "http://localhost:8000/*"],
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": True,
    }
    main.ensure_keycloak_client(admin)
    admin.update_client.assert_not_called()


# ── Traefik ForwardAuth endpoint ────────────────────────────────────────────
def test_forward_auth_allows_valid_token(client, monkeypatch):
    # A valid token -> 200 (Traefik reads 2xx as "allow") + identity headers.
    monkeypatch.setattr(main, "_introspect_token",
                        lambda t: {"active": True, "preferred_username": "alice",
                                   "sub": "kc-123"})
    r = client.get("/auth/forward", headers={"Authorization": "Bearer good"})
    assert r.status_code == 200
    assert r.headers.get("X-Auth-User") == "alice"
    assert r.headers.get("X-Auth-Subject") == "kc-123"

def test_forward_auth_denies_missing_token(client):
    # No Authorization header -> 401 (Traefik reads non-2xx as "deny").
    r = client.get("/auth/forward")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == "Bearer"

def test_forward_auth_denies_non_bearer(client):
    r = client.get("/auth/forward", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401

def test_forward_auth_denies_empty_bearer(client):
    r = client.get("/auth/forward", headers={"Authorization": "Bearer "})
    assert r.status_code == 401

def test_forward_auth_propagates_401_for_inactive_token(client, monkeypatch):
    # _introspect_token raises 401 for an inactive token -> deny.
    def raise_401(t):
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Token is inactive or expired")
    monkeypatch.setattr(main, "_introspect_token", raise_401)
    r = client.get("/auth/forward", headers={"Authorization": "Bearer stale"})
    assert r.status_code == 401

def test_forward_auth_propagates_503_when_backend_down(client, monkeypatch):
    # Introspection backend unreachable -> 503 (auth temporarily unavailable),
    # NOT a silent allow. Traefik will deny on 503 too, which is correct.
    def raise_503(t):
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    monkeypatch.setattr(main, "_introspect_token", raise_503)
    r = client.get("/auth/forward", headers={"Authorization": "Bearer x"})
    assert r.status_code == 503

def test_forward_auth_works_for_post_method(client, monkeypatch):
    # Traefik calls ForwardAuth regardless of the original method; POST must work.
    monkeypatch.setattr(main, "_introspect_token",
                        lambda t: {"active": True, "preferred_username": "bob",
                                   "sub": "s"})
    r = client.post("/auth/forward", headers={"Authorization": "Bearer good"})
    assert r.status_code == 200
    assert r.headers.get("X-Auth-User") == "bob"

def test_forward_auth_does_not_trust_inbound_identity_headers(client, monkeypatch):
    # A client forging X-Auth-User must NOT have it echoed back; the endpoint
    # sets identity from the validated token only.
    monkeypatch.setattr(main, "_introspect_token",
                        lambda t: {"active": True, "preferred_username": "real",
                                   "sub": "s"})
    r = client.get("/auth/forward",
                   headers={"Authorization": "Bearer good",
                            "X-Auth-User": "attacker"})
    assert r.headers.get("X-Auth-User") == "real"    # from token, not the forged header


# ── Correlation ID middleware ───────────────────────────────────────────────
def test_correlation_id_generated_when_absent(client):
    # A request with no X-Request-ID gets one generated and returned.
    r = client.get("/")
    rid = r.headers.get("X-Request-ID")
    assert rid and len(rid) >= 16   # a generated hex id

def test_correlation_id_reused_when_provided(client):
    # An inbound X-Request-ID is reused (so the id spans the call chain).
    r = client.get("/", headers={"X-Request-ID": "trace-abc-123"})
    assert r.headers.get("X-Request-ID") == "trace-abc-123"

def test_correlation_id_capped_in_length(client):
    # A huge inbound id is truncated (defensive: don't let a client stuff a
    # giant string into every log line).
    huge = "x" * 5000
    r = client.get("/", headers={"X-Request-ID": huge})
    assert len(r.headers.get("X-Request-ID")) <= 128

def test_correlation_id_unique_per_request(client):
    # Two requests without inbound ids get DIFFERENT generated ids.
    a = client.get("/").headers.get("X-Request-ID")
    b = client.get("/").headers.get("X-Request-ID")
    assert a != b

def test_correlation_id_appears_in_logs(client, caplog):
    # A log line emitted during the request carries the request_id contextvar.
    # We read the contextvar via the logging_config module.
    import logging_config
    seen = {}

    @main.app.get("/_ridcheck")
    def _ridcheck():
        seen["rid"] = logging_config.request_id_var.get()
        return {"ok": True}

    r = client.get("/_ridcheck", headers={"X-Request-ID": "check-me"})
    assert r.headers.get("X-Request-ID") == "check-me"
    assert seen["rid"] == "check-me"   # the contextvar was set during handling


# ── Health / readiness split ────────────────────────────────────────────────
def test_health_live_always_ok(client):
    # Liveness is up as long as the process serves — independent of Keycloak.
    r = client.get("/health/live")
    assert r.status_code == 200
    assert r.json()["status"] == "alive"

def test_health_ready_503_when_keycloak_down(client, monkeypatch):
    # Degraded start (keycloak_oidc is None) -> not ready -> 503.
    monkeypatch.setattr(main, "keycloak_oidc", None)
    r = client.get("/health/ready")
    assert r.status_code == 503
    assert r.json()["status"] == "not_ready"

def test_health_ready_200_when_keycloak_connected(client, monkeypatch):
    # Keycloak wired up -> ready -> 200.
    monkeypatch.setattr(main, "keycloak_oidc", object())
    r = client.get("/health/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


# ── Role provisioning on startup ────────────────────────────────────────────
def test_ensure_realm_role_creates_when_missing():
    from unittest.mock import MagicMock
    admin = MagicMock()
    admin.get_realm_roles.return_value = [{"name": "user"}]  # tenant-admin absent
    main.ensure_realm_role(admin, "tenant-admin")
    admin.create_realm_role.assert_called_once()
    args = admin.create_realm_role.call_args[0][0]
    assert args["name"] == "tenant-admin"

def test_ensure_realm_role_idempotent_when_present():
    from unittest.mock import MagicMock
    admin = MagicMock()
    admin.get_realm_roles.return_value = [{"name": "tenant-admin"}]  # already there
    main.ensure_realm_role(admin, "tenant-admin")
    admin.create_realm_role.assert_not_called()   # no duplicate creation

def test_ensure_realm_role_survives_error():
    from unittest.mock import MagicMock
    admin = MagicMock()
    admin.get_realm_roles.side_effect = RuntimeError("kc down")
    # must not raise — provisioning failures shouldn't crash startup
    main.ensure_realm_role(admin, "tenant-admin")

def test_grant_realm_role_assigns():
    from unittest.mock import MagicMock
    admin = MagicMock()
    admin.get_realm_role.return_value = {"name": "tenant-admin", "id": "r1"}
    main.grant_realm_role(admin, "user-123", "tenant-admin")
    admin.assign_realm_roles.assert_called_once()

def test_grant_realm_role_survives_error():
    from unittest.mock import MagicMock
    admin = MagicMock()
    admin.get_realm_role.side_effect = RuntimeError("no such role")
    main.grant_realm_role(admin, "user-123", "tenant-admin")   # must not raise


# ── /status/subsystems (diagnostic endpoint, previously untested) ────────────
def test_subsystem_status_reports_feature_states(client):
    r = client.get("/status/subsystems")
    assert r.status_code == 200
    body = r.json()
    # Reports the two optional subsystems with enabled/mode/reason each.
    assert "auth0_management" in body
    assert "openbao" in body
    for key in ("auth0_management", "openbao"):
        assert set(body[key]) >= {"enabled", "mode", "reason"}
    # And the clarifying note about brokered login always being on.
    assert "note" in body


def test_subsystem_status_survives_feature_error(client, monkeypatch):
    # If feature-state resolution raises, the endpoint returns a graceful error
    # object rather than 500-ing — it's a diagnostic, it must not itself crash.
    import features
    monkeypatch.setattr(features, "auth0_management_state",
                        lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    r = client.get("/status/subsystems")
    assert r.status_code == 200
    assert "error" in r.json()


# ── Security response headers ───────────────────────────────────────────────
def test_security_headers_present_on_responses(client):
    r = client.get("/health/live")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "no-referrer"


def test_hsts_is_opt_in(client):
    # Without SECURITY_HSTS, no HSTS header (so plain-HTTP dev isn't locked out).
    r = client.get("/health/live")
    assert r.headers.get("Strict-Transport-Security") is None


def test_hsts_present_when_enabled(client, monkeypatch):
    monkeypatch.setenv("SECURITY_HSTS", "true")
    r = client.get("/health/live")
    assert "max-age=31536000" in r.headers.get("Strict-Transport-Security", "")


# ── Defense-in-depth: header sanitization + edge input validation ───────────
def test_sanitize_header_value_strips_control_chars():
    assert main._sanitize_header_value("evil\r\nX-Injected: 1") == "evilX-Injected: 1"
    assert main._sanitize_header_value("alice") == "alice"
    assert main._sanitize_header_value("a\x00b\x7fc") == "abc"
    assert len(main._sanitize_header_value("x" * 500)) == 256


def test_validate_registration_accepts_good_input():
    assert main._validate_registration("a@b.com", "goodpass123", "alice") is None
    assert main._validate_registration("a@b.com", "goodpass123", None) is None


def test_validate_registration_rejects_bad_email():
    assert main._validate_registration("notanemail", "p", None) is not None
    assert main._validate_registration("x" * 300 + "@e.com", "p", None) is not None


def test_validate_registration_rejects_oversized_password():
    assert main._validate_registration("a@b.com", "x" * 2000, None) is not None


def test_validate_registration_rejects_control_chars():
    assert main._validate_registration("a@b.com", "pass\x00word", None) is not None
    assert main._validate_registration("a@b.com", "goodpass", "ev\r\nil") is not None


def test_register_endpoint_422_on_bad_email(client, monkeypatch):
    # The endpoint should reject bad input with 422 BEFORE touching the manager.
    from unittest.mock import MagicMock
    mgr = MagicMock()
    monkeypatch.setattr(main, "user_manager", mgr)
    r = client.post("/register", data={"email": "notanemail", "password": "p"})
    assert r.status_code == 422
    mgr.register_user.assert_not_called()  # never reached the upstream


# ── /token/client — machine-to-machine (client_credentials) ─────────────────
def test_client_token_success(client, monkeypatch):
    # keycloak_oidc must be non-None (availability guard); the endpoint builds
    # its OWN KeycloakOpenID with the caller's creds, so patch that constructor.
    monkeypatch.setattr(main, "keycloak_oidc", MagicMock())
    caller = MagicMock()
    caller.token.return_value = {"access_token": "m2m-abc", "expires_in": 300}
    monkeypatch.setattr(main, "KeycloakOpenID", lambda **kw: caller)
    r = client.post("/token/client",
                    data={"client_id": "svc-app", "client_secret": "sek"})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"] == "m2m-abc"
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 300
    # must have used the client_credentials grant
    assert caller.token.call_args.kwargs.get("grant_type") == "client_credentials"


def test_client_token_invalid_credentials_is_401(client, monkeypatch):
    from keycloak.exceptions import KeycloakAuthenticationError
    monkeypatch.setattr(main, "keycloak_oidc", MagicMock())
    caller = MagicMock()
    caller.token.side_effect = KeycloakAuthenticationError("bad client")
    monkeypatch.setattr(main, "KeycloakOpenID", lambda **kw: caller)
    r = client.post("/token/client",
                    data={"client_id": "svc-app", "client_secret": "wrong"})
    assert r.status_code == 401


def test_client_token_service_unavailable_when_oidc_none(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", None)
    r = client.post("/token/client",
                    data={"client_id": "svc-app", "client_secret": "sek"})
    assert r.status_code == 503


def test_client_token_upstream_error_is_503(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", MagicMock())
    caller = MagicMock()
    caller.token.side_effect = RuntimeError("keycloak down")
    monkeypatch.setattr(main, "KeycloakOpenID", lambda **kw: caller)
    r = client.post("/token/client",
                    data={"client_id": "svc-app", "client_secret": "sek"})
    assert r.status_code == 503


def test_client_token_requires_both_fields(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", MagicMock())
    # missing client_secret -> FastAPI 422 (Form(...) required)
    r = client.post("/token/client", data={"client_id": "svc-app"})
    assert r.status_code == 422


# ── M2M rate limiter (step 1) ───────────────────────────────────────────────
def test_client_credentials_limiter_is_distinct_and_tunable(monkeypatch):
    import rate_limit
    rate_limit.reset_all()
    monkeypatch.setenv("RATE_LIMIT_M2M_MAX", "3")
    monkeypatch.setenv("RATE_LIMIT_M2M_WINDOW", "60")
    rate_limit.reset_all()
    lim = rate_limit.client_credentials_limiter()
    # distinct object from the login limiter
    assert lim is not rate_limit.login_limiter()
    # honors its own env: 3 allowed, 4th denied
    ok = [lim.check_and_consume("k")[0] for _ in range(4)]
    assert ok == [True, True, True, False]
    rate_limit.reset_all()


# ── /token/client scope passthrough (step 3) ────────────────────────────────
def test_client_token_passes_scope_to_grant(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", MagicMock())
    caller = MagicMock()
    caller.token.return_value = {"access_token": "t", "expires_in": 300}
    monkeypatch.setattr(main, "KeycloakOpenID", lambda **kw: caller)
    r = client.post("/token/client", data={
        "client_id": "svc", "client_secret": "sek", "scope": "openid orders:read"})
    assert r.status_code == 200
    # the requested scope must be forwarded to Keycloak
    assert caller.token.call_args.kwargs.get("scope") == "openid orders:read"

def test_client_token_no_scope_omits_it(client, monkeypatch):
    monkeypatch.setattr(main, "keycloak_oidc", MagicMock())
    caller = MagicMock()
    caller.token.return_value = {"access_token": "t"}
    monkeypatch.setattr(main, "KeycloakOpenID", lambda **kw: caller)
    r = client.post("/token/client", data={"client_id": "svc", "client_secret": "sek"})
    assert r.status_code == 200
    assert "scope" not in caller.token.call_args.kwargs  # not sent when absent


# ── require_scope dependency (step 3) ───────────────────────────────────────
def test_require_scope_allows_and_denies(monkeypatch):
    # Mount a temp endpoint guarded by require_scope and exercise both paths.
    from fastapi.testclient import TestClient as _TC
    from fastapi import Depends as _Depends
    dep = main.require_scope("orders:read")
    main.app.dependency_overrides[main.require_keycloak_auth] = \
        lambda: {"active": True, "scope": "openid orders:read"}
    try:
        @main.app.get("/_scoped_test")
        def _scoped(ti: dict = _Depends(dep)):
            return {"ok": True}
        c = _TC(main.app)
        assert c.get("/_scoped_test").status_code == 200
        # now a token WITHOUT the scope
        main.app.dependency_overrides[main.require_keycloak_auth] = \
            lambda: {"active": True, "scope": "openid"}
        assert c.get("/_scoped_test").status_code == 403
    finally:
        main.app.dependency_overrides.clear()


# ── service-account role granting (step 2) ──────────────────────────────────
def test_grant_service_account_role(monkeypatch):
    admin = _kc_admin_autospec()
    admin.get_client_service_account_user.return_value = {"id": "sa-uuid"}
    admin.get_realm_role.return_value = {"name": "m2m-service", "id": "r1"}
    main.grant_service_account_role(admin, "client-uuid", "m2m-service")
    admin.assign_realm_roles.assert_called_once()

def test_grant_service_account_role_no_sa_user(monkeypatch):
    admin = _kc_admin_autospec()
    admin.get_client_service_account_user.return_value = {}  # no id
    main.grant_service_account_role(admin, "client-uuid", "m2m-service")
    admin.assign_realm_roles.assert_not_called()  # nothing to grant to

def test_grant_service_account_role_survives_error(monkeypatch):
    admin = _kc_admin_autospec()
    admin.get_client_service_account_user.side_effect = RuntimeError("boom")
    main.grant_service_account_role(admin, "client-uuid", "m2m-service")  # no raise


# ── require_audience dependency (audience restriction) ──────────────────────
def test_require_audience_allows_and_denies(monkeypatch):
    from fastapi.testclient import TestClient as _TC
    from fastapi import Depends as _Depends
    dep = main.require_audience("billing-api")
    main.app.dependency_overrides[main.require_keycloak_auth] = \
        lambda: {"active": True, "aud": ["billing-api", "account"]}
    try:
        @main.app.get("/_aud_test")
        def _aud(ti: dict = _Depends(dep)):
            return {"ok": True}
        c = _TC(main.app)
        assert c.get("/_aud_test").status_code == 200
        # token whose aud lacks the required audience
        main.app.dependency_overrides[main.require_keycloak_auth] = \
            lambda: {"active": True, "aud": ["account"]}
        assert c.get("/_aud_test").status_code == 403
    finally:
        main.app.dependency_overrides.clear()


# ── /protected/service — M2M scope/audience guards in real use (step 2) ──────
def test_protected_service_allows_with_scope(client, monkeypatch):
    monkeypatch.setattr(main, "_SERVICE_AUDIENCE", "")  # audience not required
    main.app.dependency_overrides[main.require_keycloak_auth] = \
        lambda: {"active": True, "scope": "openid m2m:access",
                 "preferred_username": "svc-app"}
    try:
        r = client.get("/protected/service")
        assert r.status_code == 200
        assert r.json()["service"] == "svc-app"
        assert "m2m:access" in r.json()["scopes"]
    finally:
        main.app.dependency_overrides.clear()

def test_protected_service_denies_without_scope(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = \
        lambda: {"active": True, "scope": "openid"}
    try:
        assert client.get("/protected/service").status_code == 403
    finally:
        main.app.dependency_overrides.clear()

def test_protected_service_enforces_audience_when_configured(client, monkeypatch):
    # Scope present but the configured audience is missing -> 403.
    monkeypatch.setattr(main, "_SERVICE_AUDIENCE", "premalytics-api")
    main.app.dependency_overrides[main.require_keycloak_auth] = \
        lambda: {"active": True, "scope": "openid m2m:access", "aud": ["account"]}
    try:
        assert client.get("/protected/service").status_code == 403
    finally:
        main.app.dependency_overrides.clear()

def test_auth0_whoami_returns_verified_subject(client, monkeypatch):
    import authorize
    main.app.dependency_overrides[authorize.get_current_user_with_auth0] = \
        lambda: {"sub": "auth0|xyz", "aud": "https://api"}
    try:
        r = client.get("/auth0/whoami")
        assert r.status_code == 200
        assert r.json()["sub"] == "auth0|xyz"
    finally:
        main.app.dependency_overrides.clear()


# ── /admin/service-accounts/{client_id}/grants — per-client M2M grants (#4) ──
def _admin_token():
    return {"active": True, "realm_access": {"roles": [main.ADMIN_ROLE]}}

def test_sa_grant_requires_admin_role(client, monkeypatch):
    # A non-admin token is rejected by require_role(ADMIN_ROLE) -> 403.
    main.app.dependency_overrides[main.require_keycloak_auth] = \
        lambda: {"active": True, "realm_access": {"roles": ["user"]}}
    try:
        r = client.post("/admin/service-accounts/some-app/grants",
                        data={"role": "m2m-service"})
        assert r.status_code == 403
    finally:
        main.app.dependency_overrides.clear()

def test_sa_grant_422_when_nothing_requested(client, monkeypatch):
    main.app.dependency_overrides[main.require_keycloak_auth] = _admin_token
    try:
        r = client.post("/admin/service-accounts/some-app/grants", data={})
        assert r.status_code == 422
    finally:
        main.app.dependency_overrides.clear()

def test_sa_grant_404_when_client_missing(client, monkeypatch):
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = None
    monkeypatch.setattr(main, "_build_keycloak_admin", lambda: admin)
    main.app.dependency_overrides[main.require_keycloak_auth] = _admin_token
    try:
        r = client.post("/admin/service-accounts/nope/grants",
                        data={"role": "m2m-service"})
        assert r.status_code == 404
    finally:
        main.app.dependency_overrides.clear()

def test_sa_grant_400_when_no_service_account(client, monkeypatch):
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = {"serviceAccountsEnabled": False}
    monkeypatch.setattr(main, "_build_keycloak_admin", lambda: admin)
    main.app.dependency_overrides[main.require_keycloak_auth] = _admin_token
    try:
        r = client.post("/admin/service-accounts/app-x/grants",
                        data={"role": "m2m-service"})
        assert r.status_code == 400
        admin.assign_realm_roles.assert_not_called()
    finally:
        main.app.dependency_overrides.clear()

def test_sa_grant_role_success(client, monkeypatch):
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_client.return_value = {"serviceAccountsEnabled": True}
    admin.get_client_service_account_user.return_value = {"id": "sa-1"}
    admin.get_realm_role.return_value = {"name": "m2m-service"}
    monkeypatch.setattr(main, "_build_keycloak_admin", lambda: admin)
    main.app.dependency_overrides[main.require_keycloak_auth] = _admin_token
    try:
        r = client.post("/admin/service-accounts/app-x/grants",
                        data={"role": "m2m-service"})
        assert r.status_code == 200
        assert r.json()["granted"] == {"role": "m2m-service"}
        admin.assign_realm_roles.assert_called_once()
    finally:
        main.app.dependency_overrides.clear()

def test_sa_grant_audience_success(client, monkeypatch):
    admin = _kc_admin_autospec()
    admin.get_client_id.return_value = "uuid-1"
    admin.get_mappers_from_client.return_value = []
    monkeypatch.setattr(main, "_build_keycloak_admin", lambda: admin)
    main.app.dependency_overrides[main.require_keycloak_auth] = _admin_token
    try:
        r = client.post("/admin/service-accounts/app-x/grants",
                        data={"audience": "premalytics-api"})
        assert r.status_code == 200
        assert r.json()["granted"] == {"audience": "premalytics-api"}
        admin.add_mapper_to_client.assert_called_once()
    finally:
        main.app.dependency_overrides.clear()
