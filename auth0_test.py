# auth0_test.py
# Test suite for the auth integration. All HTTP is mocked with `responses`,
# so these tests need NO live Keycloak server and NO Auth0 tenant.
#
# Run with:   pytest auth0_test.py -v
# Requires:   pip install pytest responses
#
# Note: auth0_connect.py / auth0_talk.py contain helper functions literally
# named test_token_access / test_login_flow. Pytest would try to collect those
# as tests. We prevent that in two ways: (1) we never `from x import *`, and
# (2) a conftest-style collect filter below ignores non-test modules. To keep
# everything in one file, we simply only define test_* functions here and rely
# on running `pytest auth0_test.py` (collecting this file only).

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest
import responses

from auth0_connect import Auth0Connect, get_keycloak_admin_token
from auth0_talk import KeycloakAdminAPI, Auth0UsersAPI
from auth0_type import (
    UserSystem,
    UserManager,
    derive_username_from_email,
    generate_password,
)

DOMAIN = "test-tenant.us.auth0.com"
KC_URL = "http://localhost:8080"
REALM = "Premkey"


# ──────────────────────────────────────────────
# auth0_type — pure-logic tests (no HTTP needed)
# ──────────────────────────────────────────────
def test_derive_username_basic():
    u = derive_username_from_email("John.Doe@example.com")
    assert u.startswith("john.doe-")
    # suffix is 6 hex chars
    assert re.fullmatch(r"john\.doe-[0-9a-f]{6}", u)

def test_use_real_username():
    n = derive_username_from_email("nathan.katzman@premalytics.com")
    assert n.startswith("nathan")

def test_derive_username_sanitises_plus_and_symbols():
    u = derive_username_from_email("a+b!c@example.com")
    assert u.startswith("a-b-c-") or u.startswith("a-b-c")
    assert "+" not in u and "!" not in u

def test_derive_username_rejects_non_email():
    with pytest.raises(ValueError):
        derive_username_from_email("not-an-email")

def test_generate_password_is_strong():
    pw = generate_password()
    assert len(pw) >= 12
    assert any(c.isdigit() for c in pw)
    assert any(c.isupper() for c in pw)

def test_usernames_are_unique():
    a = derive_username_from_email("same@example.com")
    b = derive_username_from_email("same@example.com")
    assert a != b  # random suffix prevents collision


# ──────────────────────────────────────────────
# auth0_connect — Auth0Connect token + API (HTTP mocked)
# ──────────────────────────────────────────────
@responses.activate
def test_auth0_token_fetch_and_cache():
    responses.add(
        responses.POST,
        f"https://{DOMAIN}/oauth/token",
        json={"access_token": "tok-123", "expires_in": 86400},
        status=200,
    )
    a = Auth0Connect(DOMAIN, "cid", "secret")
    assert a.token == "tok-123"
    # Second access should reuse the cached token (no second HTTP call)
    assert a.token == "tok-123"
    assert len(responses.calls) == 1  # cached, not re-fetched

@responses.activate
def test_auth0_token_missing_access_token_raises():
    responses.add(
        responses.POST,
        f"https://{DOMAIN}/oauth/token",
        json={"not_a_token": "x"},
        status=200,
    )
    a = Auth0Connect(DOMAIN, "cid", "secret")
    with pytest.raises(RuntimeError, match="missing access_token"):
        _ = a.token

@responses.activate
def test_auth0_create_connection_get_or_create():
    # token
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                json={"access_token": "t", "expires_in": 999}, status=200)
    # existing connections list (empty) -> triggers a create
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/connections",
                json=[], status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/connections",
                json={"name": "keycloak-google-oauth2", "strategy": "google-oauth2"},
                status=201)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    result = a.create_connection("keycloak-google-oauth2", "google-oauth2")
    assert result["name"] == "keycloak-google-oauth2"

@responses.activate
def test_auth0_create_connection_reuses_existing():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/connections",
                json=[{"name": "keycloak-google-oauth2", "id": "con_1"}], status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    result = a.create_connection("keycloak-google-oauth2", "google-oauth2")
    assert result["id"] == "con_1"
    # No POST should have happened (reused existing)
    assert not any(c.request.method == "POST" and c.request.url.endswith("/connections")
                for c in responses.calls)


# ──────────────────────────────────────────────
# auth0_connect — Keycloak admin token fetch
# ──────────────────────────────────────────────
@responses.activate
def test_get_keycloak_admin_token():
    responses.add(
        responses.POST,
        f"{KC_URL}/realms/master/protocol/openid-connect/token",
        json={"access_token": "kc-admin-tok"},
        status=200,
    )
    tok = get_keycloak_admin_token(KC_URL, "admin", "admin")
    assert tok == "kc-admin-tok"

@responses.activate
def test_get_keycloak_admin_token_bad_creds():
    responses.add(
        responses.POST,
        f"{KC_URL}/realms/master/protocol/openid-connect/token",
        json={"error": "invalid_grant"},
        status=401,
    )
    with pytest.raises(RuntimeError, match="401"):
        get_keycloak_admin_token(KC_URL, "admin", "wrong")


# ──────────────────────────────────────────────
# auth0_talk — KeycloakAdminAPI (HTTP mocked)
# ──────────────────────────────────────────────
@responses.activate
def test_keycloak_create_user_returns_id_from_location():
    users_url = f"{KC_URL}/admin/realms/{REALM}/users"
    responses.add(
        responses.POST, users_url, status=201,
        headers={"Location": f"{users_url}/abc-123"},
    )
    api = KeycloakAdminAPI(KC_URL, "static-token", REALM)
    uid = api.create_user("alice", "alice@example.com", "pw")
    assert uid == "abc-123"

@responses.activate
def test_keycloak_create_user_conflict_returns_none():
    users_url = f"{KC_URL}/admin/realms/{REALM}/users"
    responses.add(responses.POST, users_url, status=409)
    api = KeycloakAdminAPI(KC_URL, "static-token", REALM)
    assert api.create_user("alice", "alice@example.com", "pw") is None

def test_keycloak_admin_api_token_getter_refreshes():
    # K1 regression test: a callable token source must refresh each request
    counter = {"n": 0}
    def getter():
        counter["n"] += 1
        return f"tok-{counter['n']}"
    api = KeycloakAdminAPI(KC_URL, getter, REALM)
    assert api.headers["Authorization"] == "Bearer tok-1"
    assert api.headers["Authorization"] == "Bearer tok-2"

def test_keycloak_admin_api_accepts_static_string():
    api = KeycloakAdminAPI(KC_URL, "static", REALM)
    assert api.headers["Authorization"] == "Bearer static"


# ──────────────────────────────────────────────
# auth0_talk — Auth0UsersAPI (HTTP mocked)
# ──────────────────────────────────────────────
@responses.activate
def test_auth0_users_list():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/users",
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec")))
    assert len(api.list_users()) == 2

@responses.activate
def test_auth0_users_list_403_gives_clear_message():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/users",
                json={"error": "Forbidden"}, status=403)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    with pytest.raises(RuntimeError, match="read:users"):
        api.list_users()


# ──────────────────────────────────────────────
# auth0_type — UserManager (mock the two API objects directly)
# ──────────────────────────────────────────────
def _make_manager(in_kc: bool, in_a0: bool):
    kc = MagicMock(spec=KeycloakAdminAPI)
    a0 = MagicMock(spec=Auth0UsersAPI)
    mgr = UserManager(kc, a0)
    # Patch the private detection helpers to avoid HTTP
    mgr._in_keycloak = MagicMock(return_value=in_kc)
    mgr._in_auth0 = MagicMock(return_value=in_a0)
    return mgr, kc, a0

def test_determine_user_system_both():
    mgr, _, _ = _make_manager(True, True)
    assert mgr.determine_user_system("u", "e@x.com") == UserSystem.BOTH

def test_determine_user_system_neither():
    mgr, _, _ = _make_manager(False, False)
    assert mgr.determine_user_system("u", "e@x.com") == UserSystem.NEITHER

def test_determine_user_system_keycloak_only():
    mgr, _, _ = _make_manager(True, False)
    assert mgr.determine_user_system("u", "e@x.com") == UserSystem.KEYCLOAK

def test_add_user_creates_in_both_when_neither_exists():
    mgr, kc, a0 = _make_manager(False, False)
    kc.create_user.return_value = "kc-id-1"
    a0.create_user.return_value = {"user_id": "auth0|abc"}
    result = mgr.add_user("new@example.com", password="pw", username="newuser")
    assert result["keycloak_id"] == "kc-id-1"
    assert result["auth0_id"] == "auth0|abc"
    assert result["pre_existing"] == "neither"
    kc.create_user.assert_called_once()
    a0.create_user.assert_called_once()

def test_add_user_skips_systems_where_user_exists():
    mgr, kc, a0 = _make_manager(True, True)
    result = mgr.add_user("new@example.com", password="pw", username="newuser")
    assert result["pre_existing"] == "both"
    kc.create_user.assert_not_called()
    a0.create_user.assert_not_called()

def test_add_user_derives_username_when_omitted():
    mgr, kc, a0 = _make_manager(False, False)
    kc.create_user.return_value = "kc"
    a0.create_user.return_value = {"user_id": "a0"}
    result = mgr.add_user("derived@example.com", password="pw")
    assert result["username"].startswith("derived-")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
