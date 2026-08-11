#!/usr/bin/env python3
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
from fastapi import HTTPException as HTTPExceptionType
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
    # K1 + E1: a callable token source is cached for a short TTL (E1 efficiency
    # fix — no fresh password-grant per request) but MUST refresh once the TTL
    # lapses, preserving the K1 guarantee that a long-running app never uses a
    # stale admin token.
    counter = {"n": 0}
    def getter():
        counter["n"] += 1
        return f"tok-{counter['n']}"
    api = KeycloakAdminAPI(KC_URL, getter, REALM)
    assert api.headers["Authorization"] == "Bearer tok-1"
    # Within the TTL the cached token is reused — the getter is NOT re-invoked.
    assert api.headers["Authorization"] == "Bearer tok-1"
    assert counter["n"] == 1
    # Simulate the TTL lapsing: the next access must mint a fresh token (K1).
    api._token_fetched_at -= api._token_ttl + 1
    assert api.headers["Authorization"] == "Bearer tok-2"
    assert counter["n"] == 2

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
    # The single-client GET must explicitly request the secret field, or Auth0
    # may omit it depending on tenant/token config.
    single = [c for c in responses.calls
              if c.request.url.startswith(f"https://{DOMAIN}/api/v2/clients/exist-id")][0]
    assert "client_secret" in single.request.url  # fields=...client_secret...
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
    # After registering the IdP it also provisions the first-broker-login
    # mappers, so a fresh environment can complete a login without manual setup.
    responses.add(responses.GET, f"{url}/auth0/mappers", json=[], status=200)
    responses.add(responses.POST, f"{url}/auth0/mappers", status=201)
    integrate_with_keycloak(_auth0_for_kc(), KC_URL, REALM, "kc-tok", "oid", "osec")
    idp_post = [c for c in responses.calls
                if c.request.method == "POST" and c.request.url.endswith("/instances")]
    assert len(idp_post) == 1
    # IdP config carries the settings this whole integration needed.
    body = json.loads(idp_post[0].request.body)
    assert body["trustEmail"] is True
    assert body["config"]["disableUserInfo"] == "false"
    assert body["config"]["clientAuthMethod"] == "client_secret_post"
    # All four mappers created.
    made = [json.loads(c.request.body)["name"] for c in responses.calls
            if c.request.method == "POST" and c.request.url.endswith("/mappers")]
    assert set(made) == {"email", "username", "firstName", "lastName"}

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
    responses.add(responses.GET, f"{legacy}/auth0/mappers", json=[], status=200)
    responses.add(responses.POST, f"{legacy}/auth0/mappers", status=201)
    integrate_with_keycloak(_auth0_for_kc(), KC_URL, REALM, "kc-tok", "oid", "osec")
    instance_posts = [c for c in responses.calls
                      if c.request.method == "POST"
                      and c.request.url.endswith("/instances")]
    assert len(instance_posts) == 2          # tried modern, then legacy
    # Mappers are provisioned against the LEGACY path that actually worked.
    assert all("/auth/admin/" in c.request.url for c in responses.calls
               if c.request.url.endswith("/mappers"))

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


# ──────────────────────────────────────────────
# Q3 regression: Auth0 organization name normalization/validation
# ──────────────────────────────────────────────
def test_org_normalize_name_basic():
    from auth0_talk import Auth0OrganizationsAPI
    assert Auth0OrganizationsAPI.normalize_org_name("Acme Corp") == "acme-corp"
    assert Auth0OrganizationsAPI.normalize_org_name("My_Org") == "my_org"
    assert Auth0OrganizationsAPI.normalize_org_name("already-valid") == "already-valid"

def test_org_normalize_name_too_short_raises():
    from auth0_talk import Auth0OrganizationsAPI
    with pytest.raises(ValueError, match="valid Auth0 organization name"):
        Auth0OrganizationsAPI.normalize_org_name("ab")   # < 3 chars after cleaning

@responses.activate
def test_org_create_normalizes_name_and_keeps_display():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    # get-or-create checks the NORMALIZED name
    responses.add(responses.GET, f"{ORG_BASE}/name/acme-corp", status=404)
    responses.add(responses.POST, ORG_BASE,
                  json={"id": "org_1", "name": "acme-corp", "display_name": "Acme Corp"},
                  status=201)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    org = api.create_organization("Acme Corp")
    assert org["name"] == "acme-corp"
    # The POST body must send the normalized name but keep the original as display_name
    post = [c for c in responses.calls if c.request.method == "POST" and c.request.url == ORG_BASE][0]
    body = json.loads(post.request.body)
    assert body["name"] == "acme-corp"
    assert body["display_name"] == "Acme Corp"


# ──────────────────────────────────────────────
# Q4 regression: get_organization_by_name must normalise the name, so a lookup
# with a human-readable label resolves to the org created under its slug.
# ──────────────────────────────────────────────
@responses.activate
def test_org_get_by_name_normalizes_lookup():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    # Org exists as 'acme-corp'; caller looks it up as 'Acme Corp'
    responses.add(responses.GET, f"{ORG_BASE}/name/acme-corp",
                  json={"id": "org_1", "name": "acme-corp"}, status=200)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    org = api.get_organization_by_name("Acme Corp")
    assert org is not None and org["id"] == "org_1"

@responses.activate
def test_org_get_by_name_uninormalizable_returns_none():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    # 'a' can't be a valid org name -> no HTTP call, just None
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.get_organization_by_name("a") is None

def test_manager_org_membership_with_display_name():
    # Q4 end-to-end: membership by human-readable name resolves the slugged org.
    from auth0_type import UserManager
    from auth0_talk import Auth0OrganizationsAPI
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    orgs = create_autospec(Auth0OrganizationsAPI, instance=True)
    # The real get_organization_by_name would normalize; the autospec just returns the org
    orgs.get_organization_by_name.return_value = {"id": "org_1", "name": "acme-corp"}
    mgr = UserManager(kc, a0, auth0_orgs=orgs)
    mgr._auth0_user_id = lambda e: "auth0|1"
    result = mgr.set_organization_membership("u@x.com", "Acme Corp", add=True)
    assert result == "added"
    orgs.add_members.assert_called_once_with("org_1", ["auth0|1"])


# ──────────────────────────────────────────────
# Q5 regression: cross-system group ops with a Keycloak SUBGROUP path must match
# the Auth0 Authorization Extension's FLAT group by the leaf name.
# ──────────────────────────────────────────────
def test_manager_update_subgroup_matches_auth0_leaf_name():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    authz = MagicMock()
    kc.find_group_by_path.return_value = {"id": "kc-sub"}
    authz.find_group_by_name.return_value = {"_id": "a0-billing"}
    mgr = UserManager(kc, a0, auth0_authz=authz)
    summary = mgr.update_group("finance/billing", "invoicing")
    assert summary["keycloak"] == "updated"
    assert summary["auth0"] == "updated"
    # The Auth0 lookup must use the LEAF name 'billing', not 'finance/billing'
    authz.find_group_by_name.assert_called_once_with("billing")

def test_manager_delete_subgroup_matches_auth0_leaf_name():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    authz = MagicMock()
    kc.find_group_by_path.return_value = {"id": "kc-sub"}
    authz.find_group_by_name.return_value = {"_id": "a0-billing"}
    mgr = UserManager(kc, a0, auth0_authz=authz)
    summary = mgr.delete_group("/finance/billing/")
    assert summary["auth0"] == "deleted"
    authz.find_group_by_name.assert_called_once_with("billing")

def test_manager_membership_subgroup_matches_auth0_leaf_name():
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    authz = MagicMock()
    kc.find_group_by_path.return_value = {"id": "kc-sub"}
    authz.find_group_by_name.return_value = {"_id": "a0-billing"}
    mgr = UserManager(kc, a0, auth0_authz=authz)
    mgr._keycloak_user_id = lambda u, e: "kc-1"
    mgr._auth0_user_id = lambda e: "auth0|1"
    summary = mgr.set_group_membership("user", "u@x.com", "finance/billing", add=True)
    assert summary["auth0"] == "added"
    authz.find_group_by_name.assert_called_once_with("billing")
    authz.add_user_to_group.assert_called_once_with("a0-billing", "auth0|1")


# ──────────────────────────────────────────────
# Q6 regression: Keycloak 23+ (project targets 26) does NOT return subGroups
# inline. find_group_by_path and the 409-subgroup-reuse must fetch /children.
# ──────────────────────────────────────────────
@responses.activate
def test_find_group_by_path_lazy_loads_children_kc26():
    from auth0_talk import KeycloakAdminAPI
    groups_url = f"{KC_URL}/admin/realms/{REALM}/groups"
    # Top-level list: finance has NO inline subGroups (KC26 behavior)
    responses.add(responses.GET, groups_url,
                  json=[{"name": "finance", "id": "f-1", "path": "/finance"}], status=200)
    # Children fetched lazily via /children
    responses.add(responses.GET, f"{groups_url}/f-1/children",
                  json=[{"name": "billing", "id": "b-1", "path": "/finance/billing"}],
                  status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    found = api.find_group_by_path("/finance/billing")
    assert found is not None and found["id"] == "b-1"

@responses.activate
def test_create_subgroup_conflict_resolves_via_children_kc26():
    from auth0_talk import KeycloakAdminAPI
    children_url = f"{KC_URL}/admin/realms/{REALM}/groups/parent-1/children"
    # POST child -> 409 conflict
    responses.add(responses.POST, children_url, status=409)
    # Reuse path must GET /children (not rely on inline subGroups)
    responses.add(responses.GET, children_url,
                  json=[{"name": "billing", "id": "existing-sub"}], status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    assert api.create_group("billing", parent_id="parent-1") == "existing-sub"

@responses.activate
def test_find_group_by_path_children_endpoint_404_falls_back():
    # Older Keycloak: /children returns 404 -> fall back to inline subGroups
    from auth0_talk import KeycloakAdminAPI
    groups_url = f"{KC_URL}/admin/realms/{REALM}/groups"
    responses.add(responses.GET, groups_url,
                  json=[{"name": "finance", "id": "f-1", "path": "/finance"}], status=200)
    responses.add(responses.GET, f"{groups_url}/f-1/children", status=404)
    responses.add(responses.GET, f"{groups_url}/f-1",
                  json={"name": "finance", "id": "f-1", "path": "/finance",
                        "subGroups": [{"name": "billing", "id": "b-old",
                                       "path": "/finance/billing"}]}, status=200)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    found = api.find_group_by_path("/finance/billing")
    assert found is not None and found["id"] == "b-old"


# ──────────────────────────────────────────────
# Coverage for previously-untested org API methods: get_organization (by id)
# and list_members.
# ──────────────────────────────────────────────
@responses.activate
def test_org_get_by_id():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/org_1",
                  json={"id": "org_1", "name": "acme"}, status=200)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.get_organization("org_1")["name"] == "acme"

@responses.activate
def test_org_get_by_id_403_names_scope():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/org_1", json={}, status=403)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    with pytest.raises(RuntimeError, match="read:organizations"):
        api.get_organization("org_1")

@responses.activate
def test_org_list_members_bare_list():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/org_1/members",
                  json=[{"user_id": "auth0|1"}, {"user_id": "auth0|2"}], status=200)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    members = api.list_members("org_1")
    assert len(members) == 2

@responses.activate
def test_org_list_members_wrapped():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/org_1/members",
                  json={"members": [{"user_id": "auth0|1"}], "total": 1}, status=200)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert len(api.list_members("org_1")) == 1

@responses.activate
def test_org_list_members_403_names_scope():
    from auth0_talk import Auth0OrganizationsAPI
    _org_token()
    responses.add(responses.GET, f"{ORG_BASE}/org_1/members", json={}, status=403)
    api = Auth0OrganizationsAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    with pytest.raises(RuntimeError, match="read:organization_members"):
        api.list_members("org_1")


# ──────────────────────────────────────────────
# Coverage for authorize.verify_auth0_token (RS256 Auth0 JWT validation).
# The crypto chain (JWKS/signing key) is mocked; we verify the decode call and
# the error->401 mapping.
# ──────────────────────────────────────────────
def test_verify_auth0_token_valid(monkeypatch):
    import authorize
    monkeypatch.setattr(authorize, "get_secret", lambda k: "aud-123")
    monkeypatch.setattr(authorize, "_get_signing_key", lambda d, t: "signing-key")
    monkeypatch.setattr(authorize.jwt, "decode",
                        lambda *a, **k: {"sub": "user|1", "aud": "aud-123"})
    claims = authorize.verify_auth0_token("some.jwt.token")
    assert claims["sub"] == "user|1"

def test_verify_auth0_token_expired_maps_to_401(monkeypatch):
    import authorize
    from jose.exceptions import ExpiredSignatureError
    monkeypatch.setattr(authorize, "get_secret", lambda k: "aud-123")
    monkeypatch.setattr(authorize, "_get_signing_key", lambda d, t: "signing-key")
    def _raise(*a, **k):
        raise ExpiredSignatureError("expired")
    monkeypatch.setattr(authorize.jwt, "decode", _raise)
    with pytest.raises(HTTPExceptionType) as exc:
        authorize.verify_auth0_token("some.jwt.token")
    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail.lower()

def test_verify_auth0_token_invalid_maps_to_401(monkeypatch):
    import authorize
    from jose import JWTError
    monkeypatch.setattr(authorize, "get_secret", lambda k: "aud-123")
    monkeypatch.setattr(authorize, "_get_signing_key", lambda d, t: "signing-key")
    def _raise(*a, **k):
        raise JWTError("bad signature")
    monkeypatch.setattr(authorize.jwt, "decode", _raise)
    with pytest.raises(HTTPExceptionType) as exc:
        authorize.verify_auth0_token("some.jwt.token")
    assert exc.value.status_code == 401


# ──────────────────────────────────────────────
# Account lifecycle — Keycloak side
# ──────────────────────────────────────────────
@responses.activate
def test_kc_set_user_attributes_merges_and_wraps_scalars():
    from auth0_talk import KeycloakAdminAPI
    u = f"{KC_URL}/admin/realms/{REALM}/users/u-1"
    responses.add(responses.GET, u, json={"id": "u-1", "attributes": {"kept": ["1"]}}, status=200)  # get_user_attributes read
    responses.add(responses.GET, u, json={"id": "u-1", "attributes": {"kept": ["1"]}}, status=200)  # update_user read
    responses.add(responses.PUT, u, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.set_user_attributes("u-1", {"dept": "eng", "tags": ["a", "b"]})
    put = [c for c in responses.calls if c.request.method == "PUT"][0]
    attrs = json.loads(put.request.body)["attributes"]
    assert attrs["dept"] == ["eng"]        # scalar wrapped in list
    assert attrs["tags"] == ["a", "b"]     # list passed through
    assert attrs["kept"] == ["1"]          # existing preserved

@responses.activate
def test_kc_set_user_enabled_and_email_verified():
    from auth0_talk import KeycloakAdminAPI
    u = f"{KC_URL}/admin/realms/{REALM}/users/u-1"
    for _ in range(2):
        responses.add(responses.GET, u, json={"id": "u-1"}, status=200)
        responses.add(responses.PUT, u, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.set_user_enabled("u-1", False)
    api.set_email_verified("u-1", True)
    puts = [json.loads(c.request.body) for c in responses.calls if c.request.method == "PUT"]
    assert puts[0]["enabled"] is False
    assert puts[1]["emailVerified"] is True

@responses.activate
def test_kc_send_verify_email_and_reset_password():
    from auth0_talk import KeycloakAdminAPI
    base = f"{KC_URL}/admin/realms/{REALM}/users/u-1"
    responses.add(responses.PUT, f"{base}/send-verify-email", status=204)
    responses.add(responses.PUT, f"{base}/reset-password", status=204)
    responses.add(responses.PUT, f"{base}/execute-actions-email", status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.send_verify_email("u-1")
    api.reset_password("u-1", "NewPw123!", temporary=True)
    api.send_reset_password_email("u-1")
    bodies = [c.request for c in responses.calls if c.request.method == "PUT"]
    pw = json.loads(bodies[1].body)
    assert pw == {"type": "password", "value": "NewPw123!", "temporary": True}
    assert json.loads(bodies[2].body) == ["UPDATE_PASSWORD"]

@responses.activate
def test_kc_sessions_and_logout():
    from auth0_talk import KeycloakAdminAPI
    base = f"{KC_URL}/admin/realms/{REALM}/users/u-1"
    responses.add(responses.GET, f"{base}/sessions",
                  json=[{"id": "sess-1"}], status=200)
    responses.add(responses.POST, f"{base}/logout", status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    assert api.list_user_sessions("u-1") == [{"id": "sess-1"}]
    api.logout_user("u-1")  # no raise


# ──────────────────────────────────────────────
# Account lifecycle — Auth0 side
# ──────────────────────────────────────────────
@responses.activate
def test_a0_get_user_and_set_metadata():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/users/auth0|1",
                  json={"user_id": "auth0|1", "email": "a@x.com"}, status=200)
    responses.add(responses.PATCH, f"https://{DOMAIN}/api/v2/users/auth0|1",
                  json={"user_id": "auth0|1", "app_metadata": {"dept": "eng"}}, status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.get_user("auth0|1")["email"] == "a@x.com"
    out = api.set_user_metadata("auth0|1", app_metadata={"dept": "eng"})
    patch = [c for c in responses.calls if c.request.method == "PATCH"][0]
    body = json.loads(patch.request.body)
    assert body == {"app_metadata": {"dept": "eng"}}   # only what was provided
    assert out["app_metadata"]["dept"] == "eng"

def test_a0_set_metadata_no_args_is_noop():
    api = Auth0UsersAPI.__new__(Auth0UsersAPI)  # no HTTP needed
    assert api.set_user_metadata("auth0|1") == {}

@responses.activate
def test_a0_set_blocked():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.PATCH, f"https://{DOMAIN}/api/v2/users/auth0|1",
                  json={"blocked": True}, status=200)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    api.set_user_blocked("auth0|1", True)
    body = json.loads([c for c in responses.calls if c.request.method == "PATCH"][0].request.body)
    assert body == {"blocked": True}

@responses.activate
def test_a0_send_verification_email_jobs_endpoint():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/jobs/verification-email",
                  json={"id": "job_1", "status": "pending"}, status=201)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    job = api.send_verification_email("auth0|1")
    assert job["id"] == "job_1"

@responses.activate
def test_a0_password_reset_ticket():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/tickets/password-change",
                  json={"ticket": "https://x/reset?t=abc"}, status=201)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    assert api.create_password_reset_ticket("auth0|1").startswith("https://")

@responses.activate
def test_a0_password_reset_ticket_missing_raises():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST, f"https://{DOMAIN}/api/v2/tickets/password-change",
                  json={}, status=201)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    with pytest.raises(RuntimeError, match="no ticket"):
        api.create_password_reset_ticket("auth0|1")

@responses.activate
def test_a0_delete_sessions_and_revoke_grants():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.DELETE, f"https://{DOMAIN}/api/v2/users/auth0|1/sessions", status=202)
    responses.add(responses.DELETE, f"https://{DOMAIN}/api/v2/grants", status=204)
    api = Auth0UsersAPI(Auth0Connect(DOMAIN, "cid", "sec"))
    api.delete_sessions("auth0|1")
    api.revoke_grants("auth0|1")
    grants = [c for c in responses.calls if "grants" in c.request.url][0]
    assert "user_id=auth0%7C1" in grants.request.url  # user_id param present


# ──────────────────────────────────────────────
# UserManager — the five cross-system pairs
# ──────────────────────────────────────────────
def _lifecycle_mgr(kc_id="kc-1", a0_id="auth0|1"):
    from auth0_type import UserManager
    kc = create_autospec(KeycloakAdminAPI, instance=True)
    a0 = create_autospec(Auth0UsersAPI, instance=True)
    mgr = UserManager(kc, a0)
    mgr._keycloak_user_id = lambda u, e: kc_id
    mgr._auth0_user_id = lambda e: a0_id
    return mgr, kc, a0

def test_pair1_metadata_both_systems():
    mgr, kc, a0 = _lifecycle_mgr()
    s = mgr.set_user_metadata("u", "u@x.com", {"dept": "eng"})
    assert s == {"keycloak": "updated", "auth0": "updated"}
    kc.set_user_attributes.assert_called_once_with("kc-1", {"dept": "eng"})
    a0.set_user_metadata.assert_called_once_with("auth0|1", app_metadata={"dept": "eng"})

def test_pair2_active_semantics():
    mgr, kc, a0 = _lifecycle_mgr()
    s = mgr.set_user_active("u", "u@x.com", False)   # deactivate
    assert s == {"keycloak": "disabled", "auth0": "blocked"}
    kc.set_user_enabled.assert_called_once_with("kc-1", False)
    a0.set_user_blocked.assert_called_once_with("auth0|1", True)  # blocked = NOT active

def test_pair3_email_verified_and_send():
    mgr, kc, a0 = _lifecycle_mgr()
    assert mgr.set_email_verified("u", "u@x.com")["keycloak"] == "set"
    kc.set_email_verified.assert_called_once_with("kc-1", True)
    assert mgr.send_verification_email("u", "u@x.com")["auth0"] == "sent"
    a0.send_verification_email.assert_called_once_with("auth0|1")

def test_pair4_password_reset_returns_ticket():
    mgr, kc, a0 = _lifecycle_mgr()
    a0.create_password_reset_ticket.return_value = "https://x/reset?t=1"
    s = mgr.trigger_password_reset("u", "u@x.com")
    assert s["keycloak"] == "email-sent"
    assert s["auth0"] == "ticket-created"
    assert s["auth0_ticket"] == "https://x/reset?t=1"

def test_pair5_logout_everywhere():
    mgr, kc, a0 = _lifecycle_mgr()
    s = mgr.logout_everywhere("u", "u@x.com")
    assert s == {"keycloak": "logged-out", "auth0": "sessions-and-grants-revoked"}
    kc.logout_user.assert_called_once_with("kc-1")
    a0.delete_sessions.assert_called_once_with("auth0|1")
    a0.revoke_grants.assert_called_once_with("auth0|1")

def test_pairs_user_missing_everywhere():
    mgr, kc, a0 = _lifecycle_mgr(kc_id=None, a0_id=None)
    for s in (mgr.set_user_metadata("u", "e", {}), mgr.set_user_active("u", "e", True),
              mgr.set_email_verified("u", "e"), mgr.logout_everywhere("u", "e")):
        assert s["keycloak"] == "user-not-found"
        assert s["auth0"] == "user-not-found"
    kc.set_user_attributes.assert_not_called()
    a0.set_user_blocked.assert_not_called()


@responses.activate
def test_kc_set_user_attributes_stringifies_list_elements():
    # S1 regression: Keycloak attribute values are list[str]; non-string list
    # elements (e.g. ints) must be stringified, matching the scalar behaviour.
    from auth0_talk import KeycloakAdminAPI
    u = f"{KC_URL}/admin/realms/{REALM}/users/u-1"
    responses.add(responses.GET, u, json={"id": "u-1", "attributes": {}}, status=200)
    responses.add(responses.GET, u, json={"id": "u-1", "attributes": {}}, status=200)
    responses.add(responses.PUT, u, status=204)
    api = KeycloakAdminAPI(KC_URL, "tok", REALM)
    api.set_user_attributes("u-1", {"scores": [1, 2], "level": 3})
    attrs = json.loads([c for c in responses.calls
                        if c.request.method == "PUT"][0].request.body)["attributes"]
    assert attrs["scores"] == ["1", "2"]   # list elements stringified
    assert attrs["level"] == ["3"]         # scalar behaviour unchanged


# ──────────────────────────────────────────────
# GitHub fetch helper (fetch_github) — SSRF allow-list + error handling
# ──────────────────────────────────────────────
@responses.activate
def test_fetch_github_repo_ok():
    import main
    responses.add(responses.GET, "https://api.github.com/repos/octocat/hello",
                  json={"full_name": "octocat/hello", "stars": 1}, status=200)
    out = main.fetch_github("repo", {"owner": "octocat", "repo": "hello"})
    assert out["status"] == 200 and out["data"]["full_name"] == "octocat/hello"

def test_fetch_github_unknown_resource_is_400():
    import main
    out = main.fetch_github("secrets", {"anything": "x"})
    assert out["status"] == 400 and "unknown resource" in out["error"]

def test_fetch_github_missing_params_is_400():
    import main
    out = main.fetch_github("repo", {"owner": "octocat"})  # missing 'repo'
    assert out["status"] == 400 and "missing parameters" in out["error"]

@responses.activate
def test_fetch_github_network_error_is_502():
    import main
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("down")
    responses.add_callback(responses.GET,
                           "https://api.github.com/users/ghost", callback=boom)
    out = main.fetch_github("user", {"username": "ghost"})
    assert out["status"] == 502 and "failed" in out["error"]

@responses.activate
def test_fetch_github_sends_token_when_present(monkeypatch):
    import main
    # No secret store configured in tests -> resolver falls back to the env var.
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    # Force the store lookup to miss so we exercise the env fallback cleanly
    # (a real KV/OpenBao would be consulted first in production).
    monkeypatch.setattr(main, "_resolve_github_token",
                        lambda: os.environ.get("GITHUB_TOKEN"))
    responses.add(responses.GET, "https://api.github.com/users/octocat",
                  json={"login": "octocat"}, status=200)
    main.fetch_github("user", {"username": "octocat"})
    assert responses.calls[0].request.headers.get("Authorization") == "Bearer ghp_secret"


def test_resolve_github_token_prefers_secret_store(monkeypatch):
    import main
    import authorize
    # Store returns a value -> that wins over the env var.
    monkeypatch.setattr(authorize, "get_secret", lambda n: "from-store")
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    assert main._resolve_github_token() == "from-store"

def test_resolve_github_token_falls_back_to_env(monkeypatch):
    import main
    import authorize
    def boom(n):
        raise RuntimeError("no store")
    monkeypatch.setattr(authorize, "get_secret", boom)
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    assert main._resolve_github_token() == "from-env"

def test_resolve_github_token_none_when_nowhere(monkeypatch):
    import main
    import authorize
    def boom(n):
        raise RuntimeError("no store")
    monkeypatch.setattr(authorize, "get_secret", boom)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert main._resolve_github_token() is None


# ──────────────────────────────────────────────
# authorize.py — Auth0 M2M token machinery (previously 36% covered)
# ──────────────────────────────────────────────
def _reset_authorize_caches(monkeypatch):
    import authorize
    from datetime import datetime, timezone
    monkeypatch.setattr(authorize, "_auth0_token_cache", None)
    monkeypatch.setattr(authorize, "_auth0_token_expiry",
                        datetime.now(timezone.utc))
    monkeypatch.setattr(authorize, "_jwks_cache", None)

@responses.activate
def test_authenticate_with_auth0_happy_path(monkeypatch):
    import authorize
    monkeypatch.setenv("AUTH0_DOMAIN", DOMAIN)
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "m2m-tok", "expires_in": 3600}, status=200)
    token, exp = authorize.authenticate_with_auth0("cid", "sec", "aud")
    assert token == "m2m-tok" and exp == 3600

@responses.activate
def test_authenticate_with_auth0_bad_status_is_401(monkeypatch):
    import authorize
    monkeypatch.setenv("AUTH0_DOMAIN", DOMAIN)
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"error": "access_denied"}, status=403)
    with pytest.raises(HTTPExceptionType) as e:
        authorize.authenticate_with_auth0("cid", "sec", "aud")
    assert e.value.status_code == 401

@responses.activate
def test_authenticate_with_auth0_missing_token_is_502(monkeypatch):
    import authorize
    monkeypatch.setenv("AUTH0_DOMAIN", DOMAIN)
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"expires_in": 3600}, status=200)  # no access_token
    with pytest.raises(HTTPExceptionType) as e:
        authorize.authenticate_with_auth0("cid", "sec", "aud")
    assert e.value.status_code == 502

@responses.activate
def test_authenticate_with_auth0_network_error_is_503(monkeypatch):
    import authorize
    monkeypatch.setenv("AUTH0_DOMAIN", DOMAIN)
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("down")
    responses.add_callback(responses.POST, f"https://{DOMAIN}/oauth/token",
                           callback=boom)
    with pytest.raises(HTTPExceptionType) as e:
        authorize.authenticate_with_auth0("cid", "sec", "aud")
    assert e.value.status_code == 503

@responses.activate
def test_get_auth0_token_caches_until_expiry(monkeypatch):
    import authorize
    from datetime import datetime, timezone, timedelta
    _reset_authorize_caches(monkeypatch)
    monkeypatch.setenv("AUTH0_DOMAIN", DOMAIN)
    secrets = {"n": 0}
    def fake_secret(name):
        secrets["n"] += 1
        return name.lower()
    monkeypatch.setattr(authorize, "get_secret", fake_secret)
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "tok-1", "expires_in": 3600}, status=200)
    assert authorize.get_auth0_token() == "tok-1"
    first_fetches = secrets["n"]
    # Second call within expiry: cached — no new KV reads, no new HTTP call.
    assert authorize.get_auth0_token() == "tok-1"
    assert secrets["n"] == first_fetches
    assert len(responses.calls) == 1
    # Force expiry: must refresh.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "tok-2", "expires_in": 3600}, status=200)
    monkeypatch.setattr(authorize, "_auth0_token_expiry",
                        datetime.now(timezone.utc) - timedelta(seconds=1))
    assert authorize.get_auth0_token() == "tok-2"

@responses.activate
def test_jwks_fetch_error_raises_runtime(monkeypatch):
    import authorize
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("down")
    responses.add_callback(responses.GET,
                           f"https://{DOMAIN}/.well-known/jwks.json", callback=boom)
    with pytest.raises(RuntimeError, match="Could not fetch"):
        authorize._fetch_jwks(DOMAIN)

@responses.activate
def test_get_jwks_caches(monkeypatch):
    import authorize
    _reset_authorize_caches(monkeypatch)
    responses.add(responses.GET, f"https://{DOMAIN}/.well-known/jwks.json",
                  json={"keys": [{"kid": "k1"}]}, status=200)
    assert authorize._get_jwks(DOMAIN)["keys"][0]["kid"] == "k1"
    assert authorize._get_jwks(DOMAIN)["keys"][0]["kid"] == "k1"
    assert len(responses.calls) == 1   # second hit served from cache

def test_signing_key_missing_kid_is_401(monkeypatch):
    import authorize
    monkeypatch.setattr(authorize.jwt, "get_unverified_header", lambda t: {})
    with pytest.raises(HTTPExceptionType) as e:
        authorize._get_signing_key(DOMAIN, "tok")
    assert e.value.status_code == 401
    assert "kid" in e.value.detail

@responses.activate
def test_signing_key_rotation_refetches_jwks(monkeypatch):
    # kid not in cached JWKS -> cache cleared -> refetched once -> key found.
    import authorize
    _reset_authorize_caches(monkeypatch)
    monkeypatch.setattr(authorize, "_jwks_cache", {"keys": [{"kid": "stale"}]})
    monkeypatch.setattr(authorize.jwt, "get_unverified_header",
                        lambda t: {"kid": "fresh"})
    constructed = {}
    monkeypatch.setattr(authorize.jwk, "construct",
                        lambda kd: constructed.setdefault("kid", kd["kid"]))
    responses.add(responses.GET, f"https://{DOMAIN}/.well-known/jwks.json",
                  json={"keys": [{"kid": "fresh"}]}, status=200)
    authorize._get_signing_key(DOMAIN, "tok")
    assert constructed["kid"] == "fresh"
    assert len(responses.calls) == 1   # exactly one refetch

def test_signing_key_never_found_is_401(monkeypatch):
    import authorize
    _reset_authorize_caches(monkeypatch)
    monkeypatch.setattr(authorize.jwt, "get_unverified_header",
                        lambda t: {"kid": "ghost"})
    monkeypatch.setattr(authorize, "_fetch_jwks", lambda d: {"keys": []})
    with pytest.raises(HTTPExceptionType) as e:
        authorize._get_signing_key(DOMAIN, "tok")
    assert e.value.status_code == 401


# ──────────────────────────────────────────────
# login_flow.build_broker_login_url (previously untested)
# ──────────────────────────────────────────────
def test_build_broker_login_url():
    from login_flow import build_broker_login_url
    url = build_broker_login_url("http://localhost:8080/", "Premkey",
                                 "Hello-World-app", "http://localhost:8000/cb")
    assert url.startswith(
        "http://localhost:8080/realms/Premkey/protocol/openid-connect/auth?")
    assert "kc_idp_hint=auth0" in url
    assert "response_type=code" in url
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcb" in url

def test_build_broker_login_url_custom_idp_and_scope():
    from login_flow import build_broker_login_url
    url = build_broker_login_url("http://kc", "R", "c", "http://cb",
                                 idp_alias="okta", scope="openid")
    assert "kc_idp_hint=okta" in url and "scope=openid" in url


# ──────────────────────────────────────────────
# verify_auth0_token END-TO-END: real RS256 keypair, real signature check,
# real JWKS resolution — nothing in the crypto chain mocked.
# ──────────────────────────────────────────────
def _rs256_fixture():
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives import serialization as _ser
    from jose.backends import RSAKey
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                                 _ser.NoEncryption()).decode()
    pub_pem = key.public_key().public_bytes(
        _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()
    jwk_dict = RSAKey(pub_pem, algorithm="RS256").to_dict()
    jwk_dict["kid"] = "e2e-kid"
    return priv_pem, jwk_dict

def _e2e_verify_env(monkeypatch, jwk_dict):
    import authorize
    monkeypatch.setenv("AUTH0_DOMAIN", DOMAIN)
    monkeypatch.setattr(authorize, "_jwks_cache", None)
    monkeypatch.setattr(authorize, "get_secret", lambda n: "e2e-aud")
    responses.add(responses.GET, f"https://{DOMAIN}/.well-known/jwks.json",
                  json={"keys": [jwk_dict]}, status=200)

@responses.activate
def test_verify_auth0_token_end_to_end_valid(monkeypatch):
    import authorize, time as _t
    from jose import jwt as _jwt
    priv, jwk_dict = _rs256_fixture()
    _e2e_verify_env(monkeypatch, jwk_dict)
    tok = _jwt.encode({"sub": "auth0|42", "aud": "e2e-aud",
                       "iss": f"https://{DOMAIN}/",
                       "exp": int(_t.time()) + 300},
                      priv, algorithm="RS256", headers={"kid": "e2e-kid"})
    claims = authorize.verify_auth0_token(tok)
    assert claims["sub"] == "auth0|42"

@responses.activate
def test_verify_auth0_token_end_to_end_expired(monkeypatch):
    import authorize, time as _t
    from jose import jwt as _jwt
    priv, jwk_dict = _rs256_fixture()
    _e2e_verify_env(monkeypatch, jwk_dict)
    tok = _jwt.encode({"sub": "auth0|42", "aud": "e2e-aud",
                       "iss": f"https://{DOMAIN}/",
                       "exp": int(_t.time()) - 10},
                      priv, algorithm="RS256", headers={"kid": "e2e-kid"})
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(tok)
    assert e.value.status_code == 401 and "expired" in e.value.detail.lower()

@responses.activate
def test_verify_auth0_token_end_to_end_wrong_audience(monkeypatch):
    import authorize, time as _t
    from jose import jwt as _jwt
    priv, jwk_dict = _rs256_fixture()
    _e2e_verify_env(monkeypatch, jwk_dict)
    tok = _jwt.encode({"sub": "auth0|42", "aud": "SOMEONE-ELSE",
                       "iss": f"https://{DOMAIN}/",
                       "exp": int(_t.time()) + 300},
                      priv, algorithm="RS256", headers={"kid": "e2e-kid"})
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(tok)
    assert e.value.status_code == 401

@responses.activate
def test_verify_auth0_token_end_to_end_forged_signature(monkeypatch):
    # Token signed by an ATTACKER's key but claiming the legit kid: the JWKS
    # holds the real public key, so the signature check must fail.
    import authorize, time as _t
    from jose import jwt as _jwt
    _, legit_jwk = _rs256_fixture()          # the key JWKS serves
    attacker_priv, _ = _rs256_fixture()      # a different keypair
    _e2e_verify_env(monkeypatch, legit_jwk)
    forged = _jwt.encode({"sub": "auth0|42", "aud": "e2e-aud",
                          "exp": int(_t.time()) + 300},
                         attacker_priv, algorithm="RS256",
                         headers={"kid": "e2e-kid"})
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(forged)
    assert e.value.status_code == 401


@responses.activate
def test_verify_auth0_token_end_to_end_wrong_issuer(monkeypatch):
    # Discovered via the valid-token e2e test: issuer IS enforced. Lock it in.
    import authorize, time as _t
    from jose import jwt as _jwt
    priv, jwk_dict = _rs256_fixture()
    _e2e_verify_env(monkeypatch, jwk_dict)
    tok = _jwt.encode({"sub": "auth0|42", "aud": "e2e-aud",
                       "iss": "https://evil.example.com/",
                       "exp": int(_t.time()) + 300},
                      priv, algorithm="RS256", headers={"kid": "e2e-kid"})
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(tok)
    assert e.value.status_code == 401


# ──────────────────────────────────────────────
# verify_auth0_token END-TO-END with real RS256 crypto: a real keypair signs
# real JWTs, the public key is served as a JWKS, and the full unmodified
# verification chain (JWKS -> signing key -> decode) runs against them.
# ──────────────────────────────────────────────
import time as _time
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives import serialization as _ser
from jose import jwk as _jose_jwk, jwt as _jose_jwt


@pytest.fixture(scope="module")
def rs256_keypair():
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()).decode()
    public_pem = key.public_key().public_bytes(
        _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()
    jwk_dict = _jose_jwk.construct(public_pem, "RS256").to_dict()
    jwk_dict.update({"kid": "test-kid", "use": "sig", "alg": "RS256"})
    return private_pem, jwk_dict


def _sign(private_pem, claims):
    return _jose_jwt.encode(claims, private_pem, algorithm="RS256",
                            headers={"kid": "test-kid"})


def _wire_verify_env(monkeypatch, jwk_dict, audience="test-aud"):
    import authorize
    monkeypatch.setenv("AUTH0_DOMAIN", DOMAIN)
    monkeypatch.setattr(authorize, "_jwks_cache", None)
    monkeypatch.setattr(authorize, "_fetch_jwks", lambda d: {"keys": [jwk_dict]})
    monkeypatch.setattr(authorize, "get_secret", lambda name: audience)


def _claims(**over):
    now = int(_time.time())
    base = {"iss": f"https://{DOMAIN}/", "aud": "test-aud",
            "sub": "auth0|real", "iat": now, "exp": now + 300}
    base.update(over)
    return base


def test_verify_rs256_end_to_end_valid(rs256_keypair, monkeypatch):
    import authorize
    private_pem, jwk_dict = rs256_keypair
    _wire_verify_env(monkeypatch, jwk_dict)
    token = _sign(private_pem, _claims())
    decoded = authorize.verify_auth0_token(token)
    assert decoded["sub"] == "auth0|real"
    assert decoded["aud"] == "test-aud"

def test_verify_rs256_expired_is_401(rs256_keypair, monkeypatch):
    import authorize
    private_pem, jwk_dict = rs256_keypair
    _wire_verify_env(monkeypatch, jwk_dict)
    token = _sign(private_pem, _claims(exp=int(_time.time()) - 10))
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(token)
    assert e.value.status_code == 401 and "expired" in e.value.detail.lower()

def test_verify_rs256_wrong_audience_is_401(rs256_keypair, monkeypatch):
    import authorize
    private_pem, jwk_dict = rs256_keypair
    _wire_verify_env(monkeypatch, jwk_dict)  # verifier expects 'test-aud'
    token = _sign(private_pem, _claims(aud="someone-else"))
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(token)
    assert e.value.status_code == 401

def test_verify_rs256_wrong_issuer_is_401(rs256_keypair, monkeypatch):
    import authorize
    private_pem, jwk_dict = rs256_keypair
    _wire_verify_env(monkeypatch, jwk_dict)
    token = _sign(private_pem, _claims(iss="https://evil.example/"))
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(token)
    assert e.value.status_code == 401

def test_verify_rs256_tampered_signature_is_401(rs256_keypair, monkeypatch):
    import authorize
    private_pem, jwk_dict = rs256_keypair
    _wire_verify_env(monkeypatch, jwk_dict)
    token = _sign(private_pem, _claims())
    head, payload, sig = token.rsplit(".", 2)
    tampered = f"{head}.{payload}.{'A' + sig[1:] if sig[0] != 'A' else 'B' + sig[1:]}"
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(tampered)
    assert e.value.status_code == 401

def test_verify_rs256_key_signed_by_stranger_is_401(rs256_keypair, monkeypatch):
    # Signed by a DIFFERENT private key than the JWKS advertises.
    import authorize
    _, jwk_dict = rs256_keypair
    _wire_verify_env(monkeypatch, jwk_dict)
    stranger = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    stranger_pem = stranger.private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()).decode()
    token = _sign(stranger_pem, _claims())
    with pytest.raises(HTTPExceptionType) as e:
        authorize.verify_auth0_token(token)
    assert e.value.status_code == 401


# ──────────────────────────────────────────────
# login_flow: authorization-code exchange + token decode + callback catcher
# ──────────────────────────────────────────────
KC = "http://kc.local:8080"
TOKEN_URL = f"{KC}/realms/Premkey/protocol/openid-connect/token"

@responses.activate
def test_exchange_code_success():
    from login_flow import exchange_code_for_tokens
    responses.add(responses.POST, TOKEN_URL,
                  json={"access_token": "at", "refresh_token": "rt",
                        "token_type": "Bearer"}, status=200)
    out = exchange_code_for_tokens(KC, "Premkey", "app", "http://cb", "the-code",
                                   client_secret="s")
    assert out["access_token"] == "at"
    sent = responses.calls[0].request.body
    assert "grant_type=authorization_code" in sent and "code=the-code" in sent
    assert "client_secret=s" in sent

@responses.activate
def test_exchange_code_oauth_error_is_actionable():
    from login_flow import exchange_code_for_tokens
    responses.add(responses.POST, TOKEN_URL,
                  json={"error": "invalid_grant",
                        "error_description": "Incorrect redirect_uri"}, status=400)
    with pytest.raises(RuntimeError, match="Incorrect redirect_uri"):
        exchange_code_for_tokens(KC, "Premkey", "app", "http://cb", "bad")

@responses.activate
def test_exchange_code_network_error():
    from login_flow import exchange_code_for_tokens
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("refused")
    responses.add_callback(responses.POST, TOKEN_URL, callback=boom)
    with pytest.raises(RuntimeError, match="Could not reach Keycloak"):
        exchange_code_for_tokens(KC, "Premkey", "app", "http://cb", "c")

@responses.activate
def test_exchange_code_no_access_token():
    from login_flow import exchange_code_for_tokens
    responses.add(responses.POST, TOKEN_URL, json={"token_type": "Bearer"}, status=200)
    with pytest.raises(RuntimeError, match="no access_token"):
        exchange_code_for_tokens(KC, "Premkey", "app", "http://cb", "c")

def test_decode_token_segments():
    from login_flow import decode_token_segments
    import base64 as b64, json as j
    def seg(d):
        raw = j.dumps(d).encode()
        return b64.urlsafe_b64encode(raw).decode().rstrip("=")
    token = f"{seg({'alg': 'RS256', 'kid': 'k1'})}.{seg({'sub': 'user|1', 'preferred_username': 'nathan'})}.sig"
    out = decode_token_segments(token)
    assert out["header"]["kid"] == "k1"
    assert out["payload"]["preferred_username"] == "nathan"

def test_decode_token_segments_rejects_malformed():
    from login_flow import decode_token_segments
    with pytest.raises(ValueError, match="well-formed JWT"):
        decode_token_segments("not.a.jwt.token")
    with pytest.raises(ValueError):
        decode_token_segments("onlyonepart")


@responses.activate
def test_process_callback_success():
    from login_flow import process_callback_query
    import base64 as b64, json as j
    def seg(d):
        return b64.urlsafe_b64encode(j.dumps(d).encode()).decode().rstrip("=")
    access = f"{seg({'alg':'RS256'})}.{seg({'preferred_username':'nathan','identity_provider':'auth0'})}.s"
    responses.add(responses.POST, TOKEN_URL,
                  json={"access_token": access, "token_type": "Bearer"}, status=200)
    res = process_callback_query({"code": ["abc"]}, KC, "Premkey", "app",
                                 "http://cb", None)
    assert res["ok"] and res["username"] == "nathan" and res["idp"] == "auth0"

def test_process_callback_idp_error():
    from login_flow import process_callback_query
    res = process_callback_query(
        {"error": ["access_denied"], "error_description": ["User cancelled"]},
        KC, "Premkey", "app", "http://cb", None)
    assert not res["ok"] and "User cancelled" in res["error"]

def test_process_callback_no_code_is_pending():
    from login_flow import process_callback_query
    res = process_callback_query({}, KC, "Premkey", "app", "http://cb", None)
    assert res["ok"] is False and res.get("pending") is True

@responses.activate
def test_process_callback_exchange_failure_reported():
    from login_flow import process_callback_query
    responses.add(responses.POST, TOKEN_URL,
                  json={"error": "invalid_grant",
                        "error_description": "code expired"}, status=400)
    res = process_callback_query({"code": ["stale"]}, KC, "Premkey", "app",
                                 "http://cb", None)
    assert not res["ok"] and "code expired" in res["error"]


# ──────────────────────────────────────────────
# ensure_client_redirect_uri — fixes "Invalid parameter: redirect_uri"
# ──────────────────────────────────────────────
@responses.activate
def test_ensure_redirect_uri_adds_when_missing():
    from login_flow import ensure_client_redirect_uri
    clients_url = f"{KC}/admin/realms/Premkey/clients"
    responses.add(responses.GET, clients_url,
                  json=[{"id": "uuid-1", "clientId": "app",
                         "redirectUris": ["http://localhost:8000/other"]}], status=200)
    responses.add(responses.PUT, f"{KC}/admin/realms/Premkey/clients/uuid-1", status=204)
    ok = ensure_client_redirect_uri(KC, "Premkey", "tok", "app",
                                    "http://localhost:8000/callback")
    assert ok is True
    put = [c for c in responses.calls if c.request.method == "PUT"][0]
    body = json.loads(put.request.body)
    assert "http://localhost:8000/callback" in body["redirectUris"]
    assert "http://localhost:8000/other" in body["redirectUris"]   # preserved

@responses.activate
def test_ensure_redirect_uri_noop_when_uri_and_wildcard_present():
    from login_flow import ensure_client_redirect_uri
    clients_url = f"{KC}/admin/realms/Premkey/clients"
    responses.add(responses.GET, clients_url,
                  json=[{"id": "uuid-1", "clientId": "app",
                         "standardFlowEnabled": True,
                         "redirectUris": ["http://localhost:8000/callback",
                                          "http://localhost:8000/*"]}], status=200)
    ok = ensure_client_redirect_uri(KC, "Premkey", "tok", "app",
                                    "http://localhost:8000/callback")
    assert ok is True
    assert not [c for c in responses.calls if c.request.method == "PUT"]  # no write

@responses.activate
def test_ensure_redirect_uri_adds_wildcard_and_enables_flow():
    from login_flow import ensure_client_redirect_uri
    clients_url = f"{KC}/admin/realms/Premkey/clients"
    responses.add(responses.GET, clients_url,
                  json=[{"id": "uuid-1", "clientId": "app",
                         "standardFlowEnabled": False,
                         "redirectUris": []}], status=200)
    responses.add(responses.PUT, f"{KC}/admin/realms/Premkey/clients/uuid-1", status=204)
    ensure_client_redirect_uri(KC, "Premkey", "tok", "app",
                               "http://localhost:8000/callback")
    body = json.loads([c for c in responses.calls if c.request.method == "PUT"][0].request.body)
    assert "http://localhost:8000/callback" in body["redirectUris"]
    assert "http://localhost:8000/*" in body["redirectUris"]   # wildcard added
    assert body["standardFlowEnabled"] is True                 # flow enabled

@responses.activate
def test_ensure_redirect_uri_client_missing_raises():
    from login_flow import ensure_client_redirect_uri
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[], status=200)
    with pytest.raises(RuntimeError, match="not found"):
        ensure_client_redirect_uri(KC, "Premkey", "tok", "ghost",
                                   "http://localhost:8000/callback")


@responses.activate
def test_diagnose_redirect_uri_not_registered():
    from login_flow import diagnose_redirect_uri
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[{"id": "u1", "clientId": "app", "standardFlowEnabled": True,
                         "redirectUris": ["http://localhost:8000/other"]}], status=200)
    d = diagnose_redirect_uri(KC, "Premkey", "tok", "app",
                              "http://localhost:8000/callback")
    assert d["would_match"] is False and "NOT in the registered" in d["verdict"]

@responses.activate
def test_diagnose_redirect_uri_wildcard_matches():
    from login_flow import diagnose_redirect_uri
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[{"id": "u1", "clientId": "app", "standardFlowEnabled": True,
                         "redirectUris": ["http://localhost:8000/*"]}], status=200)
    d = diagnose_redirect_uri(KC, "Premkey", "tok", "app",
                              "http://localhost:8000/callback")
    assert d["would_match"] is True

@responses.activate
def test_diagnose_redirect_uri_no_client():
    from login_flow import diagnose_redirect_uri
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[], status=200)
    d = diagnose_redirect_uri(KC, "Premkey", "tok", "ghost", "http://x/cb")
    assert "NO client" in d["verdict"]

@responses.activate
def test_diagnose_redirect_uri_flow_disabled():
    from login_flow import diagnose_redirect_uri
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[{"id": "u1", "clientId": "app", "standardFlowEnabled": False,
                         "redirectUris": ["http://localhost:8000/callback"]}], status=200)
    d = diagnose_redirect_uri(KC, "Premkey", "tok", "app",
                              "http://localhost:8000/callback")
    assert "Standard Flow" in d["verdict"]


def test_create_client_forces_rs256_and_auth_method():
    # Regression: the browser-login app MUST be created with RS256 ID-token
    # signing (Keycloak validates via JWKS/RS256) — an HS256 default breaks the
    # broker callback with the generic "Unexpected error" message.
    import responses as rsp
    @rsp.activate
    def run():
        conn = Auth0Connect(DOMAIN, "cid", "sec")
        rsp.add(rsp.POST, f"https://{DOMAIN}/oauth/token",
                json={"access_token": "t", "expires_in": 999}, status=200)
        rsp.add(rsp.GET, f"https://{DOMAIN}/api/v2/clients",
                json=[], status=200)   # not existing -> POST path
        rsp.add(rsp.POST, f"https://{DOMAIN}/api/v2/clients",
                json={"client_id": "new", "client_secret": "s"}, status=201)
        conn.create_client("keycloak-oidc-client",
                           callbacks=["http://kc/broker"])
        post = [c for c in rsp.calls if c.request.method == "POST"
                and c.request.url.endswith("/clients")][0]
        body = json.loads(post.request.body)
        assert body["jwt_configuration"]["alg"] == "RS256"
        assert body["token_endpoint_auth_method"] == "client_secret_post"
    run()


# ──────────────────────────────────────────────
# fetch_client_secret + the app<->Keycloak 401 diagnosis
# ──────────────────────────────────────────────
@responses.activate
def test_fetch_client_secret_success():
    from login_flow import fetch_client_secret
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[{"id": "uuid-1", "clientId": "Hello-World-app"}], status=200)
    responses.add(responses.GET,
                  f"{KC}/admin/realms/Premkey/clients/uuid-1/client-secret",
                  json={"type": "secret", "value": "kc-app-secret"}, status=200)
    assert fetch_client_secret(KC, "Premkey", "tok", "Hello-World-app") == "kc-app-secret"

@responses.activate
def test_fetch_client_secret_missing_client():
    from login_flow import fetch_client_secret
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[], status=200)
    with pytest.raises(RuntimeError, match="not found"):
        fetch_client_secret(KC, "Premkey", "tok", "ghost")

@responses.activate
def test_fetch_client_secret_public_client_explains():
    from login_flow import fetch_client_secret
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[{"id": "u1", "clientId": "app"}], status=200)
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients/u1/client-secret",
                  json={}, status=200)   # no 'value' -> public client
    with pytest.raises(RuntimeError, match="public"):
        fetch_client_secret(KC, "Premkey", "tok", "app")

@responses.activate
def test_exchange_401_names_missing_client_secret():
    # Regression for the real failure: no client_secret sent -> Keycloak 401.
    # The message must point at the app<->Keycloak leg, not Auth0.
    from login_flow import exchange_code_for_tokens
    responses.add(responses.POST, TOKEN_URL,
                  json={"error": "unauthorized_client",
                        "error_description": "Invalid client or Invalid client credentials"},
                  status=401)
    with pytest.raises(RuntimeError) as e:
        exchange_code_for_tokens(KC, "Premkey", "Hello-World-app",
                                 "http://cb", "code", client_secret=None)
    msg = str(e.value)
    assert "NOT Auth0" in msg
    assert "sent no client_secret" in msg
    assert "KEYCLOAK_CLIENT_SECRET" in msg

@responses.activate
def test_exchange_401_names_rejected_secret():
    from login_flow import exchange_code_for_tokens
    responses.add(responses.POST, TOKEN_URL,
                  json={"error": "unauthorized_client",
                        "error_description": "Invalid client credentials"},
                  status=401)
    with pytest.raises(RuntimeError, match="rejected"):
        exchange_code_for_tokens(KC, "Premkey", "app", "http://cb", "code",
                                 client_secret="wrong")


def test_run_callback_catcher_accepts_secret_error():
    # The catcher must accept the fetch-failure reason so the final output can
    # explain WHY no client secret was available (the warning scrolls away).
    import inspect
    from login_flow import run_callback_catcher
    assert "secret_error" in inspect.signature(run_callback_catcher).parameters


@responses.activate
def test_integrate_mapper_failure_is_not_fatal():
    # Mapper provisioning is best-effort: if Keycloak rejects it, the IdP is
    # still registered (the operator can run diagnose_idp --fix-mappers).
    url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances"
    responses.add(responses.POST, url, status=201)
    responses.add(responses.GET, f"{url}/auth0/mappers", status=403)
    integrate_with_keycloak(_auth0_for_kc(), KC_URL, REALM, "kc-tok", "oid", "osec")
    # No exception == success.

@responses.activate
def test_integrate_skips_existing_mappers():
    url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances"
    responses.add(responses.POST, url, status=409)   # IdP already exists
    responses.add(responses.GET, f"{url}/auth0/mappers",
                  json=[{"name": "email"}, {"name": "username"},
                        {"name": "firstName"}, {"name": "lastName"}], status=200)
    integrate_with_keycloak(_auth0_for_kc(), KC_URL, REALM, "kc-tok", "oid", "osec")
    made = [c for c in responses.calls
            if c.request.method == "POST" and c.request.url.endswith("/mappers")]
    assert made == []   # nothing recreated


# ── pagination: _find_by_name must walk ALL pages ───────────────────────────
@responses.activate
def test_find_by_name_walks_multiple_pages():
    # The item is on the SECOND page. A single-page lookup (the old bug) would
    # miss it and a get-or-create would make a duplicate.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    # page 0: 100 filler clients, total says there are more
    page0 = {"clients": [{"name": f"other-{i}", "client_id": f"c{i}"}
                         for i in range(100)],
             "total": 150, "start": 0, "limit": 100}
    # page 1: the one we want
    page1 = {"clients": [{"name": "keycloak-oidc-client", "client_id": "want"}],
             "total": 150, "start": 100, "limit": 100}
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json=page0, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json=page1, status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    hit = a.get_client_by_name("keycloak-oidc-client")
    assert hit is not None and hit["client_id"] == "want"

@responses.activate
def test_find_by_name_returns_none_when_absent_across_pages():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    page0 = {"clients": [{"name": f"other-{i}"} for i in range(100)],
             "total": 150, "start": 0, "limit": 100}
    page1 = {"clients": [{"name": f"more-{i}"} for i in range(50)],
             "total": 150, "start": 100, "limit": 100}
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json=page0, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json=page1, status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    assert a.get_client_by_name("does-not-exist") is None

@responses.activate
def test_find_by_name_stops_after_one_page_when_total_fits():
    # Only one page needed — must NOT make a second request.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/connections",
                  json={"connections": [{"name": "keycloak-google-oauth2",
                                         "id": "con_1"}],
                        "total": 1, "start": 0, "limit": 100}, status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    hit = a.get_connection_by_name("keycloak-google-oauth2")
    assert hit["id"] == "con_1"
    # exactly one GET to /connections (plus the token POST)
    gets = [c for c in responses.calls if c.request.method == "GET"
            and "/connections" in c.request.url]
    assert len(gets) == 1


# ── Keycloak list_groups pagination ─────────────────────────────────────────
@responses.activate
def test_kc_list_groups_walks_all_pages():
    from auth0_talk import KeycloakAdminAPI
    base = "http://kc:8080"
    url = f"{base}/admin/realms/R/groups"
    # page 1: exactly 100 -> must fetch page 2
    responses.add(responses.GET, url,
                  json=[{"name": f"g{i}", "id": str(i)} for i in range(100)],
                  status=200)
    # page 2: 5 more -> stop
    responses.add(responses.GET, url,
                  json=[{"name": f"g{i}", "id": str(i)} for i in range(100, 105)],
                  status=200)
    api = KeycloakAdminAPI(base, "tok", "R")
    groups = api.list_groups()
    assert len(groups) == 105
    assert groups[-1]["name"] == "g104"

@responses.activate
def test_kc_list_groups_single_page_stops():
    from auth0_talk import KeycloakAdminAPI
    base = "http://kc:8080"
    url = f"{base}/admin/realms/R/groups"
    responses.add(responses.GET, url,
                  json=[{"name": "only", "id": "1"}], status=200)
    api = KeycloakAdminAPI(base, "tok", "R")
    groups = api.list_groups()
    assert len(groups) == 1
    # exactly one GET (no needless second page)
    assert len([c for c in responses.calls if c.request.method == "GET"]) == 1


@responses.activate
def test_find_by_name_exactly_one_full_page_terminates():
    # EDGE CASE: total == limit and the page returns exactly `limit` items.
    # A naive pager (which only stops on a short page) would request page 1,
    # get an empty/short response, and could loop or make a needless call. The
    # (start+limit)>=total guard must terminate after the single full page.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    # exactly 100 items, total 100 -> one full page, nothing after it
    full = {"clients": [{"name": f"c-{i}", "client_id": f"id{i}"}
                        for i in range(100)],
            "total": 100, "start": 0, "limit": 100}
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json=full, status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    # look for something NOT present -> must exhaust and return None without hanging
    hit = a.get_client_by_name("does-not-exist")
    assert hit is None
    # exactly ONE GET — the full-page guard prevented a needless second request
    gets = [c for c in responses.calls if c.request.method == "GET"
            and "/clients" in c.request.url]
    assert len(gets) == 1, f"expected 1 GET, made {len(gets)} (pager didn't stop)"


@responses.activate
def test_find_by_name_finds_item_on_exact_page_boundary():
    # The item is the LAST one on a full first page (total==limit==100). Must be
    # found without requesting a second page.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    items = [{"name": f"c-{i}", "client_id": f"id{i}"} for i in range(99)]
    items.append({"name": "target", "client_id": "found"})
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json={"clients": items, "total": 100, "start": 0, "limit": 100},
                  status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    hit = a.get_client_by_name("target")
    assert hit is not None and hit["client_id"] == "found"


@responses.activate
def test_find_by_name_bare_list_fallback():
    # DEFENSIVE PATH: some tenants/tokens may return a bare list instead of the
    # include_totals envelope. The method must still work (treat as one page).
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/connections",
                  json=[{"name": "conn-a", "id": "1"},
                        {"name": "conn-b", "id": "2"}], status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    hit = a.get_connection_by_name("conn-b")
    assert hit is not None and hit["id"] == "2"


@responses.activate
def test_find_by_name_requests_correct_pagination_params():
    # Verify the request actually sends page/per_page/include_totals — if these
    # were dropped, Auth0 would return defaults and pagination would silently
    # not work as intended.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients",
                  json={"clients": [], "total": 0, "start": 0, "limit": 100},
                  status=200)
    a = Auth0Connect(DOMAIN, "cid", "secret")
    a.get_client_by_name("anything")
    get = next(c for c in responses.calls if c.request.method == "GET"
               and "/clients" in c.request.url)
    assert "include_totals=true" in get.request.url
    assert "per_page=" in get.request.url
    assert "page=" in get.request.url
