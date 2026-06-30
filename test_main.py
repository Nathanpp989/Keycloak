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
    fake_admin.create_client_secret.return_value = {"value": "newly-created"}
    monkeypatch.setattr(m, "KeycloakAdmin", lambda **kw: fake_admin)
    monkeypatch.setattr(m, "create_keycloak_user", lambda *a, **k: "uid")
    monkeypatch.delenv("KEYCLOAK_CLIENT_SECRET", raising=False)
    secret = m.setup_keycloak()
    assert secret == "newly-created"
    fake_admin.create_client_secret.assert_called_once()

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
