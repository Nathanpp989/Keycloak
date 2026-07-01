# auth0_test.py
# Test suite for the auth integration. All HTTP is mocked with `responses`,
# so these tests need NO live Keycloak server and NO Auth0 tenant.
#
# Run with:   pytest auth0_test.py -v
# Requires:   pip install pytest responses
#
# Only test_* functions are defined here, and we import specific names (never
# `import *`), so pytest never collects the helper functions named
# test_token_access / test_login_flow that live in the application modules.

from __future__ import annotations

import json
import os
import re
import tempfile
from unittest.mock import create_autospec, MagicMock

import pytest
import responses

from auth0_connect import (
    Auth0Connect,
    get_keycloak_admin_token,
    create_server_certificate,
    integrate_with_keycloak,
    test_login_flow as build_login_url,   # aliased: avoid pytest collecting it as a test
)
from login_flow import build_broker_login_url
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
    assert re.fullmatch(r"john\.doe-[0-9a-f]{6}", u)

def test_derive_username_sanitises_plus_and_symbols():
    # T6 FIX: assert the exact sanitised stem, not a loose 'or'
    u = derive_username_from_email("a+b!c@example.com")
    stem = u.rsplit("-", 1)[0]            # strip the random hex suffix
    assert stem == "a-b-c"
    assert "+" not in u and "!" not in u

def test_derive_username_rejects_non_email():
    with pytest.raises(ValueError):
        derive_username_from_email("not-an-email")

def test_derive_username_empty_local_part_falls_back():
    # '@example.com' has an empty local part -> should fall back to 'user'
    u = derive_username_from_email("@example.com")
    assert u.startswith("user-")

def test_generate_password_is_strong():
    pw = generate_password()
    assert len(pw) >= 12
    assert any(c.isdigit() for c in pw)
    assert any(c.isupper() for c in pw)

def test_usernames_are_unique():
    a = derive_username_from_email("same@example.com")
    b = derive_username_from_email("same@example.com")
    assert a != b


# ──────────────────────────────────────────────
# auth0_connect — Auth0Connect token + API (HTTP mocked)
# ──────────────────────────────────────────────
@responses.activate
def test_auth0_token_fetch_and_cache():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "tok-123", "expires_in": 86400}, status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    assert a.token == "tok-123"
    assert a.token == "tok-123"
    assert len(responses.calls) == 1  # cached, not re-fetched

@responses.activate
def test_auth0_token_missing_access_token_raises():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"not_a_token": "x"}, status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    with pytest.raises(RuntimeError, match="missing access_token"):
        _ = a.token

@responses.activate
def test_auth0_token_non_200_raises():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"error": "access_denied"}, status=401)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    with pytest.raises(RuntimeError, match="401"):
        _ = a.token

@responses.activate
def test_auth0_create_connection_get_or_create():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/connections",
                  json=[], status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/connections",
                  json={"name": "keycloak-google-oauth2", "strategy": "google-oauth2"},
                  status=201)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    result = a.create_connection("keycloak-google-oauth2", "google-oauth2")
    assert result["name"] == "keycloak-google-oauth2"
    # A POST to /connections must have happened
    assert any(c.request.method == "POST" and "/connections" in c.request.url
               for c in responses.calls)

@responses.activate
def test_auth0_create_connection_reuses_existing():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/connections",
                  json=[{"name": "keycloak-google-oauth2", "id": "con_1"}], status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    result = a.create_connection("keycloak-google-oauth2", "google-oauth2")
    assert result["id"] == "con_1"
    # T3 FIX: robust check — no POST to the connections collection at all
    posted = [c for c in responses.calls
              if c.request.method == "POST" and "/api/v2/connections" in c.request.url]
    assert posted == []


# ──────────────────────────────────────────────
# auth0_connect — Keycloak admin token fetch
# ──────────────────────────────────────────────
@responses.activate
def test_get_keycloak_admin_token():
    responses.add(responses.POST,
                  f"{KC_URL}/realms/master/protocol/openid-connect/token",
                  json={"access_token": "kc-admin-tok"}, status=200)
    assert get_keycloak_admin_token(KC_URL, "admin", "admin") == "kc-admin-tok"

@responses.activate
def test_get_keycloak_admin_token_bad_creds():
    responses.add(responses.POST,
                  f"{KC_URL}/realms/master/protocol/openid-connect/token",
                  json={"error": "invalid_grant"}, status=401)
    with pytest.raises(RuntimeError, match="401"):
        get_keycloak_admin_token(KC_URL, "admin", "wrong")


# ──────────────────────────────────────────────
# auth0_talk — KeycloakAdminAPI (HTTP mocked)
# ──────────────────────────────────────────────
@responses.activate
def test_keycloak_create_user_returns_id_from_location():
    users_url = f"{KC_URL}/admin/realms/{REALM}/users"
    responses.add(responses.POST, users_url, status=201,
                  headers={"Location": f"{users_url}/abc-123"})
    api = KeycloakAdminAPI(KC_URL, "static-token", REALM)
    assert api.create_user("alice", "alice@example.com", "pw") == "abc-123"

@responses.activate
def test_keycloak_create_user_conflict_returns_none():
    users_url = f"{KC_URL}/admin/realms/{REALM}/users"
    responses.add(responses.POST, users_url, status=409)
    api = KeycloakAdminAPI(KC_URL, "static-token", REALM)
    assert api.create_user("alice", "alice@example.com", "pw") is None

@responses.activate
def test_keycloak_update_user_read_modify_write():
    # T4 FIX: cover the read-modify-write path of update_user.
    user_url = f"{KC_URL}/admin/realms/{REALM}/users/u-1"
    # First the GET (read) returns the existing representation
    responses.add(responses.GET, user_url,
                  json={"id": "u-1", "username": "alice", "email": "old@x.com",
                        "enabled": True}, status=200)
    # Then the PUT (write) succeeds
    responses.add(responses.PUT, user_url, status=204)
    api = KeycloakAdminAPI(KC_URL, "static-token", REALM)
    api.update_user("u-1", email="new@x.com")
    # The PUT body must contain the merged representation: original fields kept,
    # email overwritten.
    put_call = [c for c in responses.calls if c.request.method == "PUT"][0]
    body = json.loads(put_call.request.body)
    assert body["username"] == "alice"      # preserved
    assert body["email"] == "new@x.com"     # updated
    assert body["enabled"] is True          # preserved

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
                  json=[{"email": "a@x.com"}, {"email": "b@x.com"}], status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
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
# auth0_type — UserManager
# T1 FIX: use create_autospec so calls are validated against REAL signatures.
# Wrong-arity calls now fail the test instead of silently passing.
# ──────────────────────────────────────────────
def _make_manager(in_kc: bool, in_a0: bool):
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    mgr._in_keycloak = lambda username, email: in_kc
    mgr._in_auth0 = lambda email: in_a0
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

def test_determine_user_system_auth0_only():
    mgr, _, _ = _make_manager(False, True)
    assert mgr.determine_user_system("u", "e@x.com") == UserSystem.AUTH0

def test_add_user_creates_in_both_when_neither_exists():
    mgr, kc, a0 = _make_manager(False, False)
    kc.create_user.return_value = "kc-id-1"
    a0.create_user.return_value = {"user_id": "auth0|abc"}
    result = mgr.add_user("new@example.com", password="pw", username="newuser")
    assert result["keycloak_id"] == "kc-id-1"
    assert result["auth0_id"] == "auth0|abc"
    assert result["pre_existing"] == "neither"
    # T1 FIX: assert the EXACT call arguments, not just that it was called
    kc.create_user.assert_called_once_with("newuser", "new@example.com", "pw")
    a0.create_user.assert_called_once_with("new@example.com", "pw")

def test_add_user_skips_systems_where_user_exists():
    mgr, kc, a0 = _make_manager(True, True)
    result = mgr.add_user("new@example.com", password="pw", username="newuser")
    assert result["pre_existing"] == "both"
    # T2 FIX: verify the summary is still well-formed even when nothing is created
    assert result["username"] == "newuser"
    assert result["email"] == "new@example.com"
    assert result["keycloak_id"] is None
    assert result["auth0_id"] is None
    kc.create_user.assert_not_called()
    a0.create_user.assert_not_called()

def test_add_user_derives_username_when_omitted():
    mgr, kc, a0 = _make_manager(False, False)
    kc.create_user.return_value = "kc"
    a0.create_user.return_value = {"user_id": "a0"}
    result = mgr.add_user("derived@example.com", password="pw")
    assert result["username"].startswith("derived-")

@responses.activate
def test_in_keycloak_checks_email_not_just_username():
    # N1 regression: _in_keycloak must detect an existing account by EMAIL,
    # because the derived username carries a random suffix that would never match.
    users_url = f"{KC_URL}/admin/realms/{REALM}/users"
    # Email query returns a hit (user exists under this email)
    responses.add(responses.GET, users_url,
                  json=[{"id": "u-1", "email": "taken@x.com"}], status=200)
    kc = KeycloakAdminAPI(KC_URL, "tok", REALM)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    # A brand-new random username, but the email is already taken
    assert mgr._in_keycloak("brand-new-9f9f9f", "taken@x.com") is True
    # The first query must have filtered by email
    assert "email=taken" in responses.calls[0].request.url


# ──────────────────────────────────────────────
# auth0_connect — create_client secret-refetch path
# ──────────────────────────────────────────────
@responses.activate
def test_auth0_create_client_new():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json=[], status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/clients",
                  json={"client_id": "new-id", "client_secret": "new-sec"}, status=201)
    a = Auth0Connect(DOMAIN, "cid", "sec")
    result = a.create_client("my-app", ["http://localhost/cb"])
    assert result["client_id"] == "new-id"
    assert result["client_secret"] == "new-sec"

@responses.activate
def test_auth0_create_client_refetches_secret_when_existing():
    # Regression for the documented bug: GET /clients omits client_secret, so an
    # existing client must be re-fetched individually to obtain the secret.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    # List (no secret present)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json=[{"name": "my-app", "client_id": "exist-id"}], status=200)
    # Single-client fetch (includes secret)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients/exist-id",
                  json={"client_id": "exist-id", "client_secret": "real-sec"}, status=200)
    a = Auth0Connect(DOMAIN, "cid", "sec")
    result = a.create_client("my-app", ["http://localhost/cb"])
    assert result["client_secret"] == "real-sec"
    # And it must NOT have POSTed a new client
    assert not any(c.request.method == "POST" and c.request.url.endswith("/api/v2/clients")
                   for c in responses.calls)


# ──────────────────────────────────────────────
# auth0_connect — login URL builder (test_login_flow)
# ──────────────────────────────────────────────
def test_build_login_url_encodes_redirect():
    a = Auth0Connect(DOMAIN, "cid", "sec")
    url = build_login_url(a, "http://localhost:8080/callback")
    assert url.startswith(f"https://{DOMAIN}/authorize?")
    assert "response_type=code" in url
    assert "client_id=cid" in url
    # redirect_uri must be percent-encoded
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback" in url
    assert "scope=openid%20profile%20email" in url


# ──────────────────────────────────────────────
# auth0_connect — self-signed certificate generation
# ──────────────────────────────────────────────
def test_create_server_certificate_writes_files_with_600_key():
    with tempfile.TemporaryDirectory() as d:
        cert_path = os.path.join(d, "s.crt")
        key_path = os.path.join(d, "s.key")
        c, k = create_server_certificate("example.com", cert_path, key_path)
        assert os.path.exists(c) and os.path.exists(k)
        # Cert is PEM
        with open(c, "rb") as f:
            assert b"BEGIN CERTIFICATE" in f.read()
        # Private key file must be 0600 (owner read/write only)
        assert oct(os.stat(k).st_mode)[-3:] == "600"


# ──────────────────────────────────────────────
# auth0_connect — integrate_with_keycloak status handling
# ──────────────────────────────────────────────
def _auth0_for_kc():
    # No token endpoint needed: integrate_with_keycloak only reads auth0.domain
    return Auth0Connect(DOMAIN, "cid", "sec")

@responses.activate
def test_integrate_with_keycloak_created():
    url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances"
    responses.add(responses.POST, url, status=201)
    integrate_with_keycloak(_auth0_for_kc(), KC_URL, REALM, "kc-tok", "oid", "osec")
    assert len(responses.calls) == 1

@responses.activate
def test_integrate_with_keycloak_conflict_is_ok():
    url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances"
    responses.add(responses.POST, url, status=409)
    # 409 should be treated as success (idempotent re-run) — no exception
    integrate_with_keycloak(_auth0_for_kc(), KC_URL, REALM, "kc-tok", "oid", "osec")

@responses.activate
def test_integrate_with_keycloak_falls_back_to_legacy_path():
    modern = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances"
    legacy = f"{KC_URL}/auth/admin/realms/{REALM}/identity-provider/instances"
    responses.add(responses.POST, modern, status=404)   # modern path missing
    responses.add(responses.POST, legacy, status=201)   # legacy path works
    integrate_with_keycloak(_auth0_for_kc(), KC_URL, REALM, "kc-tok", "oid", "osec")
    assert len(responses.calls) == 2  # tried modern, then legacy

@responses.activate
def test_integrate_with_keycloak_realm_not_found():
    modern = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances"
    legacy = f"{KC_URL}/auth/admin/realms/{REALM}/identity-provider/instances"
    responses.add(responses.POST, modern, status=404)
    responses.add(responses.POST, legacy, status=404)
    with pytest.raises(RuntimeError, match="not found"):
        integrate_with_keycloak(_auth0_for_kc(), KC_URL, REALM, "kc-tok", "oid", "osec")


# ──────────────────────────────────────────────
# auth0_talk — remaining KeycloakAdminAPI methods
# ──────────────────────────────────────────────
@responses.activate
def test_keycloak_read_user():
    url = f"{KC_URL}/admin/realms/{REALM}/users/u-9"
    responses.add(responses.GET, url, json={"id": "u-9", "username": "bob"}, status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    assert api.read_user("u-9")["username"] == "bob"

@responses.activate
def test_keycloak_list_users_passes_pagination_params():
    url = f"{KC_URL}/admin/realms/{REALM}/users"
    responses.add(responses.GET, url, json=[{"id": "1"}], status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.list_users(first=10, max_results=25)
    q = responses.calls[0].request.url
    assert "first=10" in q and "max=25" in q

@responses.activate
def test_keycloak_delete_user():
    url = f"{KC_URL}/admin/realms/{REALM}/users/u-3"
    responses.add(responses.DELETE, url, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.delete_user("u-3")  # should not raise

@responses.activate
def test_keycloak_delete_user_error_raises():
    url = f"{KC_URL}/admin/realms/{REALM}/users/u-3"
    responses.add(responses.DELETE, url, status=500)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    with pytest.raises(Exception):
        api.delete_user("u-3")


# ──────────────────────────────────────────────
# auth0_talk — remaining Auth0UsersAPI methods
# ──────────────────────────────────────────────
@responses.activate
def test_auth0_create_user():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/users",
                  json={"user_id": "auth0|new"}, status=201)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.create_user("x@y.com", "pw")["user_id"] == "auth0|new"

@responses.activate
def test_auth0_create_user_403_names_scope():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/users",
                  json={"error": "Forbidden"}, status=403)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    with pytest.raises(RuntimeError, match="create:users"):
        api.create_user("x@y.com", "pw")

@responses.activate
def test_auth0_update_user():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.PATCH, f"https://{DOMAIN}/api/v2/users/auth0|1",
                  json={"user_id": "auth0|1", "name": "New"}, status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.update_user("auth0|1", name="New")["name"] == "New"

@responses.activate
def test_auth0_delete_user():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.DELETE, f"https://{DOMAIN}/api/v2/users/auth0|1", status=204)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    api.delete_user("auth0|1")  # should not raise


# ──────────────────────────────────────────────
# auth0_connect — rotate_client_secret
# ──────────────────────────────────────────────
@responses.activate
def test_rotate_client_secret_returns_new_secret():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "brand-new-secret"},
                  status=200)
    a = Auth0Connect(DOMAIN, "cid", "old-secret")
    new = a.rotate_client_secret("cid")
    assert new == "brand-new-secret"

@responses.activate
def test_rotate_client_secret_missing_secret_raises():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid"}, status=200)  # no client_secret
    a = Auth0Connect(DOMAIN, "cid", "old")
    with pytest.raises(RuntimeError, match="no client_secret"):
        a.rotate_client_secret("cid")

@responses.activate
def test_rotate_updates_own_instance_secret():
    # P1 regression: rotating this instance's own client must update the stored
    # secret, so a later token refresh uses the new one (not the invalidated old).
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "fresh"}, status=200)
    a = Auth0Connect(DOMAIN, "cid", "old-secret")
    _ = a.token  # prime the token cache
    a.rotate_client_secret("cid")
    assert a.client_secret == "fresh"  # instance secret was updated

@responses.activate
def test_rotate_other_client_does_not_touch_instance_secret():
    # Rotating a DIFFERENT client must NOT change this instance's secret.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/other-id/rotate-secret",
                  json={"client_id": "other-id", "client_secret": "fresh"}, status=200)
    a = Auth0Connect(DOMAIN, "cid", "my-secret")
    a.rotate_client_secret("other-id")
    assert a.client_secret == "my-secret"  # unchanged


# ──────────────────────────────────────────────
# login_flow — broker login URL builder
# ──────────────────────────────────────────────
def test_build_broker_login_url_includes_idp_hint():
    url = build_broker_login_url(
        "http://localhost:8080", "Premkey", "Hello-World-app",
        "http://localhost:8000/protected",
    )
    assert url.startswith("http://localhost:8080/realms/Premkey/protocol/openid-connect/auth?")
    assert "kc_idp_hint=auth0" in url
    assert "response_type=code" in url
    assert "client_id=Hello-World-app" in url
    # redirect_uri must be URL-encoded
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fprotected" in url

def test_build_broker_login_url_strips_trailing_slash():
    url = build_broker_login_url(
        "http://localhost:8080/", "R", "C", "http://x/cb", idp_alias="auth0",
    )
    # No double slash before /realms
    assert "8080//realms" not in url
    assert "/realms/R/" in url


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


# ──────────────────────────────────────────────
# Group + role membership (KeycloakAdminAPI / Auth0UsersAPI / Authz Extension)
# ──────────────────────────────────────────────
@responses.activate
def test_keycloak_get_user_groups_marks_subgroups():
    from auth0_talk import KeycloakAdminAPI
    url = f"{KC_URL}/admin/realms/{REALM}/users/u-1/groups"
    responses.add(responses.GET, url, json=[
        {"name": "admins", "path": "/admins"},
        {"name": "billing", "path": "/finance/billing"},
    ], status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    groups = api.get_user_groups("u-1")
    by_name = {g["name"]: g for g in groups}
    assert by_name["admins"]["is_subgroup"] is False     # top-level
    assert by_name["billing"]["is_subgroup"] is True      # nested under /finance

@responses.activate
def test_keycloak_get_user_roles_realm_and_client():
    from auth0_talk import KeycloakAdminAPI
    base = f"{KC_URL}/admin/realms/{REALM}/users/u-1/role-mappings"
    responses.add(responses.GET, f"{base}/realm",
                  json=[{"name": "offline_access"}, {"name": "admin"}], status=200)
    responses.add(responses.GET, base, json={
        "realmMappings": [{"name": "admin"}],
        "clientMappings": {
            "account": {"mappings": [{"name": "view-profile"}, {"name": "manage-account"}]}
        },
    }, status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    roles = api.get_user_roles("u-1")
    assert "admin" in roles["realm"]
    assert "manage-account" in roles["client"]

@responses.activate
def test_auth0_get_user_roles():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/users/auth0|1/roles",
                  json=[{"name": "editor"}, {"name": "viewer"}], status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.get_user_roles("auth0|1") == ["editor", "viewer"]

@responses.activate
def test_auth0_get_user_roles_403_names_scope():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/users/auth0|1/roles",
                  json={"error": "Forbidden"}, status=403)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    with pytest.raises(RuntimeError, match="read:roles"):
        api.get_user_roles("auth0|1")

@responses.activate
def test_authz_extension_get_user_groups():
    from auth0_talk import Auth0AuthzExtensionAPI
    ext_url = "https://tenant.us.webtask.io/abc/api"
    # The extension fetches its own token (audience urn:auth0-authz-api)
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "ext-tok", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"{ext_url}/users/auth0|1/groups", json=[
        {"name": "engineering"},
        {"name": "backend", "parent": "engineering"},
    ], status=200)
    ext = Auth0AuthzExtensionAPI(Auth0Connect(DOMAIN, "cid", "sec"), ext_url)
    groups = ext.get_user_groups("auth0|1")
    by_name = {g["name"]: g for g in groups}
    assert by_name["engineering"]["is_subgroup"] is False
    assert by_name["backend"]["is_subgroup"] is True


# ──────────────────────────────────────────────
# UserManager.get_membership — cross-system correlation
# ──────────────────────────────────────────────
def test_get_membership_correlates_groups_and_roles(monkeypatch):
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    authz = MagicMock()
    mgr = UserManager(kc, a0, auth0_authz=authz)

    # Resolve ids
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    mgr._auth0_user_id = lambda e: "auth0|1"

    kc.get_user_groups.return_value = [
        {"name": "Admins", "path": "/Admins", "is_subgroup": False},
        {"name": "KCOnly", "path": "/KCOnly", "is_subgroup": False},
    ]
    kc.get_user_roles.return_value = {"realm": ["editor"], "client": ["view-profile"]}
    a0.get_user_roles.return_value = ["editor", "auth0only"]
    authz.get_user_groups.return_value = [
        {"name": "admins", "is_subgroup": False},     # same as KC "Admins" (case-insensitive)
        {"name": "A0Only", "is_subgroup": False},
    ]

    m = mgr.get_membership("user", "user@example.com")
    assert m["keycloak"]["found"] is True
    assert m["auth0"]["found"] is True
    corr = m["correlation"]
    assert "admins" in corr["groups_in_both"]          # Admins == admins
    assert "kconly" in corr["groups_keycloak_only"]
    assert "a0only" in corr["groups_auth0_only"]
    assert "editor" in corr["roles_in_both"]
    assert "auth0only" in corr["roles_auth0_only"]
    assert "view-profile" in corr["roles_keycloak_only"]

def test_get_membership_user_missing_in_auth0(monkeypatch):
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)  # no authz extension
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    mgr._auth0_user_id = lambda e: None  # not in Auth0
    kc.get_user_groups.return_value = [{"name": "g", "path": "/g", "is_subgroup": False}]
    kc.get_user_roles.return_value = {"realm": ["r"], "client": []}
    m = mgr.get_membership("user", "user@example.com")
    assert m["auth0"]["found"] is False
    assert m["auth0"]["groups"] == []          # no authz extension -> empty
    assert "g" in m["correlation"]["groups_keycloak_only"]

def test_get_membership_without_authz_extension_skips_groups():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0, auth0_authz=None)
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    mgr._auth0_user_id = lambda e: "auth0|1"
    kc.get_user_groups.return_value = []
    kc.get_user_roles.return_value = {"realm": [], "client": []}
    a0.get_user_roles.return_value = ["x"]
    m = mgr.get_membership("user", "user@example.com")
    # Auth0 found, roles present, but groups empty because no extension configured
    assert m["auth0"]["found"] is True
    assert m["auth0"]["groups"] == []
    assert m["auth0"]["roles"] == ["x"]


# ──────────────────────────────────────────────
# Keycloak group management (create / subgroup / add / revoke)
# ──────────────────────────────────────────────
@responses.activate
def test_keycloak_create_top_level_group():
    from auth0_talk import KeycloakAdminAPI
    url = f"{KC_URL}/admin/realms/{REALM}/groups"
    responses.add(responses.POST, url, status=201,
                  headers={"Location": f"{url}/grp-1"})
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    assert api.create_group("admins") == "grp-1"

@responses.activate
def test_keycloak_create_subgroup_uses_children_endpoint():
    from auth0_talk import KeycloakAdminAPI
    children_url = f"{KC_URL}/admin/realms/{REALM}/groups/parent-1/children"
    responses.add(responses.POST, children_url, status=201,
                  headers={"Location": f"{children_url}/sub-1"})
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    assert api.create_group("billing", parent_id="parent-1") == "sub-1"

@responses.activate
def test_keycloak_create_group_conflict_reuses_existing():
    from auth0_talk import KeycloakAdminAPI
    url = f"{KC_URL}/admin/realms/{REALM}/groups"
    responses.add(responses.POST, url, status=409)
    responses.add(responses.GET, url,
                  json=[{"name": "admins", "id": "existing-1"}], status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    assert api.create_group("admins") == "existing-1"

@responses.activate
def test_keycloak_find_group_by_path_nested():
    from auth0_talk import KeycloakAdminAPI
    url = f"{KC_URL}/admin/realms/{REALM}/groups"
    responses.add(responses.GET, url, json=[
        {"name": "finance", "id": "f-1", "path": "/finance", "subGroups": [
            {"name": "billing", "id": "b-1", "path": "/finance/billing", "subGroups": []},
        ]},
    ], status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    found = api.find_group_by_path("/finance/billing")
    assert found["id"] == "b-1"

@responses.activate
def test_keycloak_add_user_to_group():
    from auth0_talk import KeycloakAdminAPI
    url = f"{KC_URL}/admin/realms/{REALM}/users/u-1/groups/g-1"
    responses.add(responses.PUT, url, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.add_user_to_group("u-1", "g-1")  # no raise

@responses.activate
def test_keycloak_remove_user_from_group():
    from auth0_talk import KeycloakAdminAPI
    url = f"{KC_URL}/admin/realms/{REALM}/users/u-1/groups/g-1"
    responses.add(responses.DELETE, url, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.remove_user_from_group("u-1", "g-1")  # no raise


# ──────────────────────────────────────────────
# Auth0 Authorization Extension group management
# ──────────────────────────────────────────────
EXT_URL = "https://tenant.us.webtask.io/abc/api"

def _ext_token():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "ext-tok", "expires_in": 999}, status=200)

@responses.activate
def test_authz_create_group_new():
    from auth0_talk import Auth0AuthzExtensionAPI
    _ext_token()
    responses.add(responses.GET, f"{EXT_URL}/groups", json={"groups": []}, status=200)
    responses.add(responses.POST, f"{EXT_URL}/groups",
                  json={"_id": "eg-1", "name": "engineering"}, status=200)
    ext = Auth0AuthzExtensionAPI(Auth0Connect(DOMAIN, "cid", "sec"), EXT_URL)
    g = ext.create_group("engineering")
    assert g["_id"] == "eg-1"

@responses.activate
def test_authz_create_group_reuses_existing():
    from auth0_talk import Auth0AuthzExtensionAPI
    _ext_token()
    responses.add(responses.GET, f"{EXT_URL}/groups",
                  json={"groups": [{"_id": "eg-1", "name": "Engineering"}]}, status=200)
    ext = Auth0AuthzExtensionAPI(Auth0Connect(DOMAIN, "cid", "sec"), EXT_URL)
    g = ext.create_group("engineering")  # case-insensitive match
    assert g["_id"] == "eg-1"

@responses.activate
def test_authz_create_nested_group():
    from auth0_talk import Auth0AuthzExtensionAPI
    _ext_token()
    responses.add(responses.GET, f"{EXT_URL}/groups", json={"groups": []}, status=200)
    responses.add(responses.POST, f"{EXT_URL}/groups",
                  json={"_id": "child-1", "name": "backend"}, status=200)
    responses.add(responses.PATCH, f"{EXT_URL}/groups/parent-1/nested", json={}, status=200)
    ext = Auth0AuthzExtensionAPI(Auth0Connect(DOMAIN, "cid", "sec"), EXT_URL)
    g = ext.create_group("backend", parent_group_id="parent-1")
    assert g["_id"] == "child-1"
    # The nested PATCH must have been called
    assert any(c.request.method == "PATCH" and "/nested" in c.request.url
               for c in responses.calls)

@responses.activate
def test_authz_add_and_remove_member():
    from auth0_talk import Auth0AuthzExtensionAPI
    _ext_token()
    responses.add(responses.PATCH, f"{EXT_URL}/groups/g-1/members", status=204)
    responses.add(responses.DELETE, f"{EXT_URL}/groups/g-1/members", status=204)
    ext = Auth0AuthzExtensionAPI(Auth0Connect(DOMAIN, "cid", "sec"), EXT_URL)
    ext.add_user_to_group("g-1", "auth0|1")     # no raise
    ext.remove_user_from_group("g-1", "auth0|1")  # no raise


# ──────────────────────────────────────────────
# UserManager cross-system group ops
# ──────────────────────────────────────────────
def test_manager_create_group_both_systems():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    authz = MagicMock()
    kc.create_group.return_value = "kc-grp-1"
    authz.create_group.return_value = {"_id": "a0-grp-1", "name": "admins"}
    mgr = UserManager(kc, a0, auth0_authz=authz)
    result = mgr.create_group("admins")
    assert result["keycloak_id"] == "kc-grp-1"
    assert result["auth0_group"]["_id"] == "a0-grp-1"
    kc.create_group.assert_called_once_with("admins", parent_id=None)

def test_manager_create_subgroup_resolves_parent():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    kc.find_group_by_path.return_value = {"id": "parent-1", "path": "/finance"}
    kc.create_group.return_value = "sub-1"
    mgr = UserManager(kc, a0)  # no authz
    result = mgr.create_group("billing", parent_path="/finance")
    assert result["keycloak_id"] == "sub-1"
    kc.create_group.assert_called_once_with("billing", parent_id="parent-1")

def test_manager_create_subgroup_missing_parent_raises():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    kc.find_group_by_path.return_value = None
    mgr = UserManager(kc, a0)
    with pytest.raises(ValueError, match="parent group"):
        mgr.create_group("billing", parent_path="/nonexistent")

def test_manager_set_group_membership_add():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    kc.find_group_by_path.return_value = {"id": "g-1"}
    summary = mgr.set_group_membership("user", "u@x.com", "admins", add=True)
    assert summary["keycloak"] == "added"
    kc.add_user_to_group.assert_called_once_with("kc-1", "g-1")

def test_manager_set_group_membership_revoke():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    kc.find_group_by_path.return_value = {"id": "g-1"}
    summary = mgr.set_group_membership("user", "u@x.com", "admins", add=False)
    assert summary["keycloak"] == "removed"
    kc.remove_user_from_group.assert_called_once_with("kc-1", "g-1")

def test_manager_set_group_membership_user_not_found():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    mgr._keycloak_user_id = lambda u, e: None
    summary = mgr.set_group_membership("ghost", "ghost@x.com", "admins", add=True)
    assert summary["keycloak"] == "user-not-found"
    kc.add_user_to_group.assert_not_called()


# ──────────────────────────────────────────────
# Keycloak realm-role assign / revoke
# ──────────────────────────────────────────────
@responses.activate
def test_keycloak_assign_realm_role():
    from auth0_talk import KeycloakAdminAPI
    role_url = f"{KC_URL}/admin/realms/{REALM}/roles/admin"
    map_url = f"{KC_URL}/admin/realms/{REALM}/users/u-1/role-mappings/realm"
    responses.add(responses.GET, role_url, json={"id": "r-1", "name": "admin"}, status=200)
    responses.add(responses.POST, map_url, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.assign_realm_role("u-1", "admin")  # no raise
    # The POST body must be the full role representation
    post = [c for c in responses.calls if c.request.method == "POST"][0]
    assert json.loads(post.request.body)[0]["id"] == "r-1"

@responses.activate
def test_keycloak_assign_realm_role_unknown_raises():
    from auth0_talk import KeycloakAdminAPI
    responses.add(responses.GET, f"{KC_URL}/admin/realms/{REALM}/roles/ghost", status=404)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    with pytest.raises(ValueError, match="not found"):
        api.assign_realm_role("u-1", "ghost")

@responses.activate
def test_keycloak_revoke_realm_role():
    from auth0_talk import KeycloakAdminAPI
    role_url = f"{KC_URL}/admin/realms/{REALM}/roles/admin"
    map_url = f"{KC_URL}/admin/realms/{REALM}/users/u-1/role-mappings/realm"
    responses.add(responses.GET, role_url, json={"id": "r-1", "name": "admin"}, status=200)
    responses.add(responses.DELETE, map_url, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.revoke_realm_role("u-1", "admin")  # no raise


# ──────────────────────────────────────────────
# Auth0 role assign / revoke
# ──────────────────────────────────────────────
@responses.activate
def test_auth0_assign_role():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/roles",
                  json=[{"id": "rol_1", "name": "editor"}], status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/users/auth0|1/roles", status=204)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    api.assign_role("auth0|1", "editor")  # no raise
    post = [c for c in responses.calls if c.request.method == "POST"
            and c.request.url.endswith("/roles")][0]
    assert json.loads(post.request.body)["roles"] == ["rol_1"]

@responses.activate
def test_auth0_assign_role_unknown_raises():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/roles", json=[], status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    with pytest.raises(ValueError, match="not found"):
        api.assign_role("auth0|1", "ghost")

@responses.activate
def test_auth0_get_role_by_name_exact_match():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    # name_filter is a substring match; ensure we pick the EXACT name
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/roles",
                  json=[{"id": "r1", "name": "editor"}, {"id": "r2", "name": "editor-lite"}],
                  status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    role = api.get_role_by_name("editor")
    assert role["id"] == "r1"

@responses.activate
def test_auth0_revoke_role():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/roles",
                  json=[{"id": "rol_1", "name": "editor"}], status=200)
    responses.add(responses.DELETE, f"https://{DOMAIN}/api/v2/users/auth0|1/roles", status=204)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    api.revoke_role("auth0|1", "editor")  # no raise


# ──────────────────────────────────────────────
# UserManager.set_role — symmetric cross-system
# ──────────────────────────────────────────────
def test_manager_set_role_assign_both():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    mgr._auth0_user_id = lambda e: "auth0|1"
    summary = mgr.set_role("user", "u@x.com", "admin", assign=True)
    assert summary["keycloak"] == "assigned"
    assert summary["auth0"] == "assigned"
    kc.assign_realm_role.assert_called_once_with("kc-1", "admin")
    a0.assign_role.assert_called_once_with("auth0|1", "admin")

def test_manager_set_role_revoke_both():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    mgr._auth0_user_id = lambda e: "auth0|1"
    summary = mgr.set_role("user", "u@x.com", "admin", assign=False)
    assert summary["keycloak"] == "revoked"
    assert summary["auth0"] == "revoked"

def test_manager_set_role_unknown_role_per_system():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    kc.assign_realm_role.side_effect = ValueError("not found")
    a0.assign_role.side_effect = ValueError("not found")
    mgr = UserManager(kc, a0)
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    mgr._auth0_user_id = lambda e: "auth0|1"
    summary = mgr.set_role("user", "u@x.com", "ghost", assign=True)
    assert summary["keycloak"] == "role-not-found"
    assert summary["auth0"] == "role-not-found"

def test_manager_set_role_user_missing():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    mgr._keycloak_user_id = lambda u, e: None
    mgr._auth0_user_id = lambda e: None
    summary = mgr.set_role("ghost", "ghost@x.com", "admin", assign=True)
    assert summary["keycloak"] == "user-not-found"
    assert summary["auth0"] == "user-not-found"
    kc.assign_realm_role.assert_not_called()


# ──────────────────────────────────────────────
# Q1 regression: Auth0 list responses may be bare lists OR wrapped objects
# ({"roles": [...]} / {"users": [...]}) when include_totals is set. These must
# not crash with AttributeError.
# ──────────────────────────────────────────────
@responses.activate
def test_get_role_by_name_handles_wrapped_response():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    # Wrapped form (include_totals style)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/roles",
                  json={"roles": [{"id": "r1", "name": "editor"}], "total": 1}, status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    role = api.get_role_by_name("editor")
    assert role["id"] == "r1"

@responses.activate
def test_get_user_roles_handles_wrapped_response():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/users/auth0|1/roles",
                  json={"roles": [{"name": "editor"}], "total": 1}, status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.get_user_roles("auth0|1") == ["editor"]

@responses.activate
def test_list_users_handles_wrapped_response():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/users",
                  json={"users": [{"email": "a@x.com"}], "total": 1}, status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert len(api.list_users()) == 1


# ──────────────────────────────────────────────
# Auth0 Organizations API (CRUD + members)
# ──────────────────────────────────────────────
def _org_token():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)

ORG_BASE = f"https://{DOMAIN}/api/v2/organizations"

@responses.activate
def test_org_list_handles_wrapped():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, ORG_BASE,
                  json={"organizations": [{"id": "org_1", "name": "acme"}], "total": 1},
                  status=200)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    orgs = api.list_organizations()
    assert len(orgs) == 1 and orgs[0]["id"] == "org_1"

@responses.activate
def test_org_get_by_name_found():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/name/acme",
                  json={"id": "org_1", "name": "acme"}, status=200)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.get_organization_by_name("acme")["id"] == "org_1"

@responses.activate
def test_org_get_by_name_missing_returns_none():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/name/ghost", status=404)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.get_organization_by_name("ghost") is None

@responses.activate
def test_org_create_new():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/name/acme", status=404)  # not existing
    responses.add(responses.POST, ORG_BASE,
                  json={"id": "org_1", "name": "acme"}, status=201)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.create_organization("acme")["id"] == "org_1"

@responses.activate
def test_org_create_reuses_existing():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/name/acme",
                  json={"id": "org_ex", "name": "acme"}, status=200)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.create_organization("acme")["id"] == "org_ex"
    assert not any(c.request.method == "POST" and c.request.url == ORG_BASE
                   for c in responses.calls)

@responses.activate
def test_org_update():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.PATCH, f"{ORG_BASE}/org_1",
                  json={"id": "org_1", "display_name": "Acme Inc"}, status=200)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.update_organization("org_1", display_name="Acme Inc")["display_name"] == "Acme Inc"

@responses.activate
def test_org_delete_idempotent():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.DELETE, f"{ORG_BASE}/org_1", status=404)  # already gone
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    api.delete_organization("org_1")  # no raise

@responses.activate
def test_org_add_and_remove_members():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.POST, f"{ORG_BASE}/org_1/members", status=204)
    responses.add(responses.DELETE, f"{ORG_BASE}/org_1/members", status=204)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    api.add_members("org_1", ["auth0|1"])       # no raise
    api.remove_members("org_1", ["auth0|1"])    # no raise

@responses.activate
def test_org_list_403_names_scope():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, ORG_BASE, json={"error": "Forbidden"}, status=403)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    with pytest.raises(RuntimeError, match="read:organizations"):
        api.list_organizations()


# ──────────────────────────────────────────────
# Keycloak group update / delete
# ──────────────────────────────────────────────
@responses.activate
def test_keycloak_update_group_read_modify_write():
    from auth0_talk import KeycloakAdminAPI
    url = f"{KC_URL}/admin/realms/{REALM}/groups/g-1"
    responses.add(responses.GET, url,
                  json={"id": "g-1", "name": "old", "path": "/old",
                        "attributes": {"k": ["v"]}}, status=200)
    responses.add(responses.PUT, url, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.update_group("g-1", name="new")
    put = [c for c in responses.calls if c.request.method == "PUT"][0]
    body = json.loads(put.request.body)
    assert body["name"] == "new"                 # updated
    assert body["attributes"] == {"k": ["v"]}    # preserved

@responses.activate
def test_keycloak_delete_group_idempotent():
    from auth0_talk import KeycloakAdminAPI
    url = f"{KC_URL}/admin/realms/{REALM}/groups/g-1"
    responses.add(responses.DELETE, url, status=404)  # already gone
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.delete_group("g-1")  # no raise


# ──────────────────────────────────────────────
# Authz Extension group update / delete
# ──────────────────────────────────────────────
@responses.activate
def test_authz_update_group():
    from auth0_talk import Auth0AuthzExtensionAPI
    _ext_token()
    responses.add(responses.PUT, f"{EXT_URL}/groups/g-1",
                  json={"_id": "g-1", "name": "new"}, status=200)
    ext = Auth0AuthzExtensionAPI(Auth0Connect(DOMAIN, "cid", "sec"), EXT_URL)
    assert ext.update_group("g-1", name="new")["name"] == "new"

@responses.activate
def test_authz_delete_group_idempotent():
    from auth0_talk import Auth0AuthzExtensionAPI
    _ext_token()
    responses.add(responses.DELETE, f"{EXT_URL}/groups/g-1", status=404)
    ext = Auth0AuthzExtensionAPI(Auth0Connect(DOMAIN, "cid", "sec"), EXT_URL)
    ext.delete_group("g-1")  # no raise


# ──────────────────────────────────────────────
# UserManager: org membership + group update/delete orchestration
# ──────────────────────────────────────────────
def test_manager_set_org_membership_add():
    from auth0_type import UserManager
    from auth0_talk import Auth0OrganizationsAPI
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    orgs = create_autospec(Auth0OrganizationsAPI, instance=True)
    orgs.get_organization_by_name.return_value = {"id": "org_1", "name": "acme"}
    mgr = UserManager(kc, a0, auth0_orgs=orgs)
    mgr._auth0_user_id = lambda e: "auth0|1"
    assert mgr.set_organization_membership("u@x.com", "acme", add=True) == "added"
    orgs.add_members.assert_called_once_with("org_1", ["auth0|1"])

def test_manager_set_org_membership_no_api():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)  # no orgs api
    assert mgr.set_organization_membership("u@x.com", "acme", add=True) == "no-orgs-api"

def test_manager_set_org_membership_org_missing():
    from auth0_type import UserManager
    from auth0_talk import Auth0OrganizationsAPI
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    orgs = create_autospec(Auth0OrganizationsAPI, instance=True)
    orgs.get_organization_by_name.return_value = None
    mgr = UserManager(kc, a0, auth0_orgs=orgs)
    assert mgr.set_organization_membership("u@x.com", "ghost", add=True) == "org-not-found"

def test_manager_update_group_keycloak_only():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    kc.find_group_by_path.return_value = {"id": "g-1"}
    mgr = UserManager(kc, a0)
    summary = mgr.update_group("/admins", "superadmins")
    assert summary["keycloak"] == "updated"
    kc.update_group.assert_called_once_with("g-1", name="superadmins")

def test_manager_delete_group_not_found():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    kc.find_group_by_path.return_value = None
    kc.list_groups.return_value = []
    mgr = UserManager(kc, a0)
    summary = mgr.delete_group("ghost")
    assert summary["keycloak"] == "group-not-found"
    kc.delete_group.assert_not_called()
