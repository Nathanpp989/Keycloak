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
from unittest.mock import MagicMock

import pytest
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
    """Dependency override that simulates a valid authenticated Keycloak token."""
    return {"active": True, "preferred_username": "caller"}

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
