#!/usr/bin/env python3
"""Tests for the operational diagnostic/fix tools (diagnose_idp, fix_redirect_uri).
These write to Keycloak, so their guard logic is safety-critical and must be
covered — an untested write is what corrupted the IdP in the first place."""
from __future__ import annotations

import pytest
import responses

import diagnose_idp
import fix_redirect_uri

KC = "http://kc.local:8080"
IDP_URL = f"{KC}/admin/realms/Premkey/identity-provider/instances/auth0"


# ── fix_idp_config: the guard that stops re-corrupting the IdP ──────────────
@responses.activate
def test_fix_idp_refuses_wrong_client():
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "config": {"clientId": "IDP-APP",
                                                     "clientSecret": "x"}}, status=200)
    with pytest.raises(RuntimeError, match="REFUSING to write"):
        diagnose_idp.fix_idp_config(KC, "Premkey", "tok", "auth0",
                                    "secret-of-different-app",
                                    expect_client_id="OTHER-APP")
    assert not [c for c in responses.calls if c.request.method == "PUT"]  # no write

@responses.activate
def test_fix_idp_writes_when_client_matches():
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "config": {"clientId": "IDP-APP"}}, status=200)
    responses.add(responses.PUT, IDP_URL, status=204)
    diagnose_idp.fix_idp_config(KC, "Premkey", "tok", "auth0", "new-sec",
                                expect_client_id="IDP-APP")
    import json
    body = json.loads([c for c in responses.calls if c.request.method == "PUT"][0].request.body)
    assert body["config"]["clientSecret"] == "new-sec"
    assert body["config"]["clientAuthMethod"] == "client_secret_post"  # set if missing

@responses.activate
def test_fix_idp_sets_auth_method_but_keeps_existing():
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "config": {"clientId": "A",
                        "clientAuthMethod": "client_secret_basic"}}, status=200)
    responses.add(responses.PUT, IDP_URL, status=204)
    diagnose_idp.fix_idp_config(KC, "Premkey", "tok", "auth0", "s")
    import json
    body = json.loads([c for c in responses.calls if c.request.method == "PUT"][0].request.body)
    assert body["config"]["clientAuthMethod"] == "client_secret_basic"  # not overwritten

@responses.activate
def test_fix_idp_no_expect_check_allows_explicit_set():
    # --set-idp-secret path: no expect_client_id -> writes regardless (explicit intent)
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "config": {"clientId": "anything"}}, status=200)
    responses.add(responses.PUT, IDP_URL, status=204)
    diagnose_idp.fix_idp_config(KC, "Premkey", "tok", "auth0", "explicit-sec")
    assert [c for c in responses.calls if c.request.method == "PUT"]


# ── _get_idp_client_id ──────────────────────────────────────────────────────
@responses.activate
def test_get_idp_client_id():
    responses.add(responses.GET, IDP_URL,
                  json={"config": {"clientId": "the-id"}}, status=200)
    from rotate_secret import _get_idp_client_id
    assert _get_idp_client_id(KC, "Premkey", "tok", "auth0") == "the-id"

@responses.activate
def test_get_idp_client_id_missing_returns_none():
    responses.add(responses.GET, IDP_URL, status=404)
    responses.add(responses.GET,
                  f"{KC}/auth/admin/realms/Premkey/identity-provider/instances/auth0",
                  status=404)
    from rotate_secret import _get_idp_client_id
    assert _get_idp_client_id(KC, "Premkey", "tok", "auth0") is None


# ── check_auth0_secret / check_jwks / check_issuer ──────────────────────────
DOMAIN = "test.auth0.com"

@responses.activate
def test_check_auth0_secret_valid():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t"}, status=200)
    ok, detail = diagnose_idp.check_auth0_secret(DOMAIN, "cid", "sec")
    assert ok is True

@responses.activate
def test_check_auth0_secret_rejected():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"error": "access_denied"}, status=401)
    ok, detail = diagnose_idp.check_auth0_secret(DOMAIN, "cid", "wrong")
    assert ok is False and "401" in detail

@responses.activate
def test_check_jwks_and_issuer():
    responses.add(responses.GET, f"https://{DOMAIN}/.well-known/jwks.json",
                  json={"keys": [{"kid": "k1"}]}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/.well-known/openid-configuration",
                  json={"issuer": f"https://{DOMAIN}/"}, status=200)
    jok, _ = diagnose_idp.check_jwks(DOMAIN)
    iok, issuer = diagnose_idp.check_issuer(DOMAIN)
    assert jok and iok and issuer == f"https://{DOMAIN}/"

@responses.activate
def test_check_auth0_app_flags_m2m():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t"}, status=200)
    responses.add(responses.GET, f"https://{DOMAIN}/api/v2/clients/idp-app",
                  json={"name": "keycloakAuth", "app_type": "non_interactive",
                        "callbacks": [], "grant_types": ["client_credentials"],
                        "jwt_configuration": {"alg": "RS256"},
                        "token_endpoint_auth_method": "client_secret_post"}, status=200)
    out = diagnose_idp.check_auth0_app(DOMAIN, "m2m", "sec", KC, "Premkey", "auth0",
                                       inspect_client_id="idp-app")
    assert out["ok"] and out["app"]["app_type"] == "non_interactive"


# ── fix_redirect_uri.fix_client ─────────────────────────────────────────────
@responses.activate
def test_fix_redirect_client_adds_uri_and_wildcard():
    client = {"id": "u1", "clientId": "app", "redirectUris": ["http://x/old"]}
    responses.add(responses.PUT, f"{KC}/admin/realms/Premkey/clients/u1", status=204)
    uris = fix_redirect_uri.fix_client(KC, "Premkey", "tok", client,
                                       "http://localhost:8000/callback")
    assert "http://localhost:8000/callback" in uris
    assert "http://localhost:8000/*" in uris
    assert "http://x/old" in uris   # preserved
    import json
    body = json.loads(responses.calls[-1].request.body)
    assert body["standardFlowEnabled"] is True

@responses.activate
def test_fix_redirect_login_url_shape():
    url = fix_redirect_uri.login_url(KC, "Premkey", "app", "http://cb")
    assert url.startswith(f"{KC}/realms/Premkey/protocol/openid-connect/auth?")
    assert "kc_idp_hint=auth0" in url and "client_id=app" in url

@responses.activate
def test_list_realms_and_clients():
    responses.add(responses.GET, f"{KC}/admin/realms",
                  json=[{"realm": "master"}, {"realm": "Premkey"}], status=200)
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/clients",
                  json=[{"id": "u1", "clientId": "app"}], status=200)
    assert "Premkey" in fix_redirect_uri.list_realms(KC, "tok")
    assert fix_redirect_uri.list_clients(KC, "Premkey", "tok")[0]["clientId"] == "app"


# ── dump_idp_full + userInfoUrl reporting ───────────────────────────────────
@responses.activate
def test_dump_idp_full_returns_representation():
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "config": {"clientId": "x",
                        "userInfoUrl": "https://d/userinfo"}}, status=200)
    rep = diagnose_idp.dump_idp_full(KC, "Premkey", "tok", "auth0")
    assert rep["config"]["userInfoUrl"] == "https://d/userinfo"

@responses.activate
def test_dump_idp_full_missing_returns_empty():
    responses.add(responses.GET, IDP_URL, status=404)
    responses.add(responses.GET,
                  f"{KC}/auth/admin/realms/Premkey/identity-provider/instances/auth0",
                  status=404)
    assert diagnose_idp.dump_idp_full(KC, "Premkey", "tok", "auth0") == {}

@responses.activate
def test_fix_idp_preserves_existing_userinfo_and_issuer():
    # Regression: repairing the secret must NOT drop other config keys.
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "config": {
                      "clientId": "A", "userInfoUrl": "https://d/userinfo",
                      "issuer": "https://d/", "jwksUrl": "https://d/jwks"}}, status=200)
    responses.add(responses.PUT, IDP_URL, status=204)
    diagnose_idp.fix_idp_config(KC, "Premkey", "tok", "auth0", "new-sec")
    import json
    body = json.loads([c for c in responses.calls if c.request.method == "PUT"][0].request.body)
    assert body["config"]["userInfoUrl"] == "https://d/userinfo"   # preserved
    assert body["config"]["issuer"] == "https://d/"                # preserved
    assert body["config"]["jwksUrl"] == "https://d/jwks"           # preserved
    assert body["config"]["clientSecret"] == "new-sec"             # updated


# ── set_app_id_token_alg (--fix-alg) ────────────────────────────────────────
@responses.activate
def test_set_app_id_token_alg_success():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t"}, status=200)
    responses.add(responses.PATCH, f"https://{DOMAIN}/api/v2/clients/app-1",
                  json={"jwt_configuration": {"alg": "RS256"}}, status=200)
    got = diagnose_idp.set_app_id_token_alg(DOMAIN, "m2m", "sec", "app-1")
    assert got == "RS256"
    body = __import__("json").loads(
        [c for c in responses.calls if c.request.method == "PATCH"][0].request.body)
    assert body["jwt_configuration"]["alg"] == "RS256"

@responses.activate
def test_set_app_id_token_alg_403_names_scope():
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t"}, status=200)
    responses.add(responses.PATCH, f"https://{DOMAIN}/api/v2/clients/app-1",
                  json={}, status=403)
    with pytest.raises(RuntimeError, match="update:clients"):
        diagnose_idp.set_app_id_token_alg(DOMAIN, "m2m", "sec", "app-1")
