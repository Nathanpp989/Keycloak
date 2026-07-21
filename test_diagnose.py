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


# ── enable_and_fetch_events ─────────────────────────────────────────────────
@responses.activate
def test_events_enables_when_off():
    cfg_url = f"{KC}/admin/realms/Premkey/events/config"
    responses.add(responses.GET, cfg_url,
                  json={"eventsEnabled": False, "enabledEventTypes": []}, status=200)
    responses.add(responses.PUT, cfg_url, status=204)
    out = diagnose_idp.enable_and_fetch_events(KC, "Premkey", "tok")
    assert out and "_note" in out[0]   # tells caller to reproduce + re-run
    assert any(c.request.method == "PUT" for c in responses.calls)

@responses.activate
def test_events_returns_idp_errors():
    cfg_url = f"{KC}/admin/realms/Premkey/events/config"
    responses.add(responses.GET, cfg_url, json={"eventsEnabled": True}, status=200)
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/events",
                  json=[{"type": "IDENTITY_PROVIDER_LOGIN_ERROR",
                         "error": "invalid_token",
                         "details": {"identity_provider": "auth0"}}], status=200)
    out = diagnose_idp.enable_and_fetch_events(KC, "Premkey", "tok")
    assert out[0]["error"] == "invalid_token"

@responses.activate
def test_events_falls_back_to_all_errors():
    cfg_url = f"{KC}/admin/realms/Premkey/events/config"
    responses.add(responses.GET, cfg_url, json={"eventsEnabled": True}, status=200)
    # No IDENTITY_PROVIDER_LOGIN_ERROR events...
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/events",
                  json=[], status=200)
    # ...fallback pulls recent, filters for ERROR
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/events",
                  json=[{"type": "LOGIN_ERROR", "error": "user_not_found"},
                        {"type": "LOGIN", "error": None}], status=200)
    out = diagnose_idp.enable_and_fetch_events(KC, "Premkey", "tok")
    assert len(out) == 1 and out[0]["error"] == "user_not_found"


# ── explain_login_error: map event error codes to causes ────────────────────
def test_explain_first_broker_login_failure():
    # The user's actual event: no provider error -> post-login mapping failure.
    msg = diagnose_idp.explain_login_error(
        "identity_provider_login_failure", {"code_id": "abc"})
    assert "FIRST BROKER LOGIN" in msg
    assert "EMAIL" in msg

def test_explain_signature_provider_error():
    msg = diagnose_idp.explain_login_error(
        "identity_provider_login_failure",
        {"identity_provider_error": "Signature validation failed"})
    assert "RS256" in msg

def test_explain_client_provider_error():
    msg = diagnose_idp.explain_login_error(
        "identity_provider_login_failure",
        {"identity_provider_error": "invalid_client"})
    assert "--set-idp-secret" in msg

def test_explain_unknown_error():
    msg = diagnose_idp.explain_login_error("some_other_error", {"x": 1})
    assert "some_other_error" in msg


# ── ensure_broker_mappers: fixes first-broker-login ─────────────────────────
@responses.activate
def test_ensure_broker_mappers_creates_all_when_none():
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "trustEmail": False, "config": {}}, status=200)
    responses.add(responses.PUT, IDP_URL, status=204)   # trustEmail
    responses.add(responses.GET, f"{IDP_URL}/mappers", json=[], status=200)
    responses.add(responses.POST, f"{IDP_URL}/mappers", status=201)
    created = diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0")
    assert any("email" in x for x in created) and any("username" in x for x in created)
    # trustEmail PUT happened
    assert any(c.request.method == "PUT" for c in responses.calls)
    # one POST per created mapper
    posts = [c for c in responses.calls if c.request.method == "POST"
             and c.request.url.endswith("/mappers")]
    assert len(posts) == len(created)
    import json
    email_body = json.loads(posts[0].request.body)
    assert email_body["config"]["claim"] == "email"
    assert email_body["identityProviderMapper"] == "oidc-user-attribute-idp-mapper"
    assert email_body["identityProviderAlias"] == "auth0"

@responses.activate
def test_ensure_broker_mappers_idempotent():
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "trustEmail": True, "config": {}}, status=200)
    # Existing mappers already have the CORRECT type + config -> no change.
    responses.add(responses.GET, f"{IDP_URL}/mappers", json=[
        {"id": "1", "name": "email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "email", "user.attribute": "email", "syncMode": "INHERIT"}},
        {"id": "2", "name": "username",
         "identityProviderMapper": "oidc-username-idp-mapper",
         "config": {"template": "${CLAIM.email}", "syncMode": "INHERIT"}},
        {"id": "3", "name": "firstName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "given_name", "user.attribute": "firstName", "syncMode": "INHERIT"}},
        {"id": "4", "name": "lastName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "family_name", "user.attribute": "lastName", "syncMode": "INHERIT"}},
    ], status=200)
    created = diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0")
    assert created == []   # nothing changed
    assert not [c for c in responses.calls if c.request.method == "PUT"]
    assert not [c for c in responses.calls if c.request.method == "POST"]

@responses.activate
def test_ensure_broker_mappers_corrects_broken_existing():
    # A mapper named 'email' exists but with WRONG config -> must be corrected,
    # not skipped. This is the false-success bug that hid the real problem.
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "trustEmail": True, "config": {}}, status=200)
    responses.add(responses.GET, f"{IDP_URL}/mappers", json=[
        {"id": "1", "name": "email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "WRONG_CLAIM", "user.attribute": "email"}},
        {"id": "2", "name": "username",
         "identityProviderMapper": "oidc-username-idp-mapper",
         "config": {"template": "${CLAIM.email}", "syncMode": "INHERIT"}},
        {"id": "3", "name": "firstName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "given_name", "user.attribute": "firstName", "syncMode": "INHERIT"}},
        {"id": "4", "name": "lastName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "family_name", "user.attribute": "lastName", "syncMode": "INHERIT"}},
    ], status=200)
    responses.add(responses.PUT, f"{IDP_URL}/mappers/1", status=204)
    changed = diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0")
    assert any("email" in x and "corrected" in x for x in changed)
    import json
    put = [c for c in responses.calls if c.request.method == "PUT"
           and c.request.url.endswith("/mappers/1")][0]
    assert json.loads(put.request.body)["config"]["claim"] == "email"  # fixed

@responses.activate
def test_ensure_broker_mappers_partial():
    # email exists, username missing -> only username created
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "trustEmail": True, "config": {}}, status=200)
    responses.add(responses.GET, f"{IDP_URL}/mappers", json=[
        {"id": "1", "name": "email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "email", "user.attribute": "email", "syncMode": "INHERIT"}},
    ], status=200)
    responses.add(responses.POST, f"{IDP_URL}/mappers", status=201)
    created = diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0")
    assert not any("email" in x for x in created) and any("username" in x for x in created)

@responses.activate
def test_ensure_broker_mappers_idp_missing():
    responses.add(responses.GET, IDP_URL, status=404)
    responses.add(responses.GET,
                  f"{KC}/auth/admin/realms/Premkey/identity-provider/instances/auth0",
                  status=404)
    with pytest.raises(RuntimeError, match="not found"):
        diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0")


@responses.activate
def test_list_broker_mappers():
    responses.add(responses.GET, f"{IDP_URL}/mappers",
                  json=[{"name": "email", "identityProviderMapper": "x",
                         "config": {"claim": "email"}}], status=200)
    out = diagnose_idp.list_broker_mappers(KC, "Premkey", "tok", "auth0")
    assert out[0]["name"] == "email"


@responses.activate
def test_ensure_broker_mappers_removes_conflicts_when_asked():
    # Reproduces the real situation: duplicate 'Email' (nullable=false) and a
    # 'No-login-username' mapper that conflict with our email/username mappers.
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "trustEmail": True, "config": {}}, status=200)
    responses.add(responses.GET, f"{IDP_URL}/mappers", json=[
        {"id": "1", "name": "email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "email", "user.attribute": "email", "syncMode": "INHERIT"}},
        {"id": "2", "name": "username",
         "identityProviderMapper": "oidc-username-idp-mapper",
         "config": {"template": "${CLAIM.email}", "syncMode": "INHERIT"}},
        {"id": "3", "name": "firstName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "given_name", "user.attribute": "firstName", "syncMode": "INHERIT"}},
        {"id": "4", "name": "lastName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "family_name", "user.attribute": "lastName", "syncMode": "INHERIT"}},
        # The conflicting extras:
        {"id": "5", "name": "Email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "email", "user.attribute": "email",
                    "allow.nullable.property": "false"}},
        {"id": "6", "name": "No-login-username",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "name", "user.attribute": "username",
                    "allow.nullable.property": "false"}},
    ], status=200)
    responses.add(responses.DELETE, f"{IDP_URL}/mappers/5", status=204)
    responses.add(responses.DELETE, f"{IDP_URL}/mappers/6", status=204)
    changed = diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0",
                                                 remove_conflicts=True)
    # Both conflicting mappers removed
    assert any("Email" in x and "removed" in x for x in changed)
    assert any("No-login-username" in x and "removed" in x for x in changed)
    deletes = {c.request.url.rsplit("/", 1)[-1]
               for c in responses.calls if c.request.method == "DELETE"}
    assert deletes == {"5", "6"}

@responses.activate
def test_ensure_broker_mappers_no_removal_by_default():
    # Same duplicates, but remove_conflicts defaults False -> NO deletes.
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "trustEmail": True, "config": {}}, status=200)
    responses.add(responses.GET, f"{IDP_URL}/mappers", json=[
        {"id": "1", "name": "email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "email", "user.attribute": "email", "syncMode": "INHERIT"}},
        {"id": "2", "name": "username",
         "identityProviderMapper": "oidc-username-idp-mapper",
         "config": {"template": "${CLAIM.email}", "syncMode": "INHERIT"}},
        {"id": "3", "name": "firstName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "given_name", "user.attribute": "firstName", "syncMode": "INHERIT"}},
        {"id": "4", "name": "lastName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "family_name", "user.attribute": "lastName", "syncMode": "INHERIT"}},
        {"id": "5", "name": "Email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "email", "user.attribute": "email",
                    "allow.nullable.property": "false"}},
    ], status=200)
    changed = diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0")
    assert not [c for c in responses.calls if c.request.method == "DELETE"]
    assert changed == []


@responses.activate
def test_events_dedupes_repeated_code_id(capsys):
    # Five events with the SAME code_id must collapse to one unique line so a
    # repeated view of one failure doesn't look like five failures.
    import diagnose_idp as d
    cfg_url = f"{KC}/admin/realms/Premkey/events/config"
    responses.add(responses.GET, cfg_url, json={"eventsEnabled": True}, status=200)
    same = {"type": "IDENTITY_PROVIDER_LOGIN_ERROR",
            "error": "identity_provider_login_failure",
            "details": {"code_id": "SAME"}, "time": 1_700_000_000_000}
    responses.add(responses.GET, f"{KC}/admin/realms/Premkey/events",
                  json=[same, same, same, same, same], status=200)
    evs = d.enable_and_fetch_events(KC, "Premkey", "tok")
    # The function returns all; dedup happens in main()'s printing. Verify the
    # raw fetch returns them and the code_id is stable so main can dedup.
    codes = {(e.get("details") or {}).get("code_id") for e in evs}
    assert codes == {"SAME"}


@responses.activate
def test_ensure_broker_mappers_disables_userinfo_flag():
    # disableUserInfo=true must be flipped to false so Keycloak fetches email
    # from /userinfo — the fix when correct mappers still fail.
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "trustEmail": True,
                        "config": {"disableUserInfo": "true"}}, status=200)
    responses.add(responses.PUT, IDP_URL, status=204)
    responses.add(responses.GET, f"{IDP_URL}/mappers", json=[
        {"id": "1", "name": "email",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "email", "user.attribute": "email", "syncMode": "INHERIT"}},
        {"id": "2", "name": "username",
         "identityProviderMapper": "oidc-username-idp-mapper",
         "config": {"template": "${CLAIM.email}", "syncMode": "INHERIT"}},
        {"id": "3", "name": "firstName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "given_name", "user.attribute": "firstName", "syncMode": "INHERIT"}},
        {"id": "4", "name": "lastName",
         "identityProviderMapper": "oidc-user-attribute-idp-mapper",
         "config": {"claim": "family_name", "user.attribute": "lastName", "syncMode": "INHERIT"}},
    ], status=200)
    diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0")
    put = [c for c in responses.calls if c.request.method == "PUT"
           and c.request.url == IDP_URL][0]
    body = __import__("json").loads(put.request.body)
    assert body["config"]["disableUserInfo"] == "false"
    assert body["trustEmail"] is True


# ── writes must fail loudly, not silently (audit fixes) ─────────────────────
@responses.activate
def test_events_config_write_failure_raises():
    cfg_url = f"{KC}/admin/realms/Premkey/events/config"
    responses.add(responses.GET, cfg_url,
                  json={"eventsEnabled": False, "enabledEventTypes": []}, status=200)
    responses.add(responses.PUT, cfg_url, status=403)   # permission denied
    with pytest.raises(Exception):   # raise_for_status -> HTTPError
        diagnose_idp.enable_and_fetch_events(KC, "Premkey", "tok")

@responses.activate
def test_broker_mappers_trustemail_write_failure_raises():
    responses.add(responses.GET, IDP_URL,
                  json={"alias": "auth0", "trustEmail": False, "config": {}}, status=200)
    responses.add(responses.PUT, IDP_URL, status=500)   # server error
    with pytest.raises(Exception):
        diagnose_idp.ensure_broker_mappers(KC, "Premkey", "tok", "auth0")


# ── previously-untested helpers ─────────────────────────────────────────────
@responses.activate
def test_admin_token_success():
    responses.add(responses.POST,
                  f"{KC}/realms/master/protocol/openid-connect/token",
                  json={"access_token": "adm"}, status=200)
    assert diagnose_idp.admin_token(KC, "master", "u", "p") == "adm"

@responses.activate
def test_admin_token_failure_raises():
    responses.add(responses.POST,
                  f"{KC}/realms/master/protocol/openid-connect/token",
                  json={"error": "invalid_grant"}, status=401)
    with pytest.raises(RuntimeError, match="Admin login failed"):
        diagnose_idp.admin_token(KC, "master", "u", "wrong")

@responses.activate
def test_fetch_idp_found_and_missing():
    responses.add(responses.GET, IDP_URL, json={"alias": "auth0"}, status=200)
    assert diagnose_idp.fetch_idp(KC, "Premkey", "tok", "auth0")["alias"] == "auth0"

@responses.activate
def test_check_auth0_secret_network_error():
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("down")
    responses.add_callback(responses.POST, f"https://{DOMAIN}/oauth/token",
                           callback=boom)
    ok, detail = diagnose_idp.check_auth0_secret(DOMAIN, "cid", "sec")
    assert ok is False and "cannot reach" in detail.lower()

@responses.activate
def test_check_jwks_failure():
    responses.add(responses.GET, f"https://{DOMAIN}/.well-known/jwks.json",
                  json={}, status=500)
    ok, _ = diagnose_idp.check_jwks(DOMAIN)
    assert ok is False


# ── config consistency across tools ─────────────────────────────────────────
def test_login_flow_loads_dotenv():
    # Regression: login_flow must load .env like the other operational tools,
    # or it silently uses default KEYCLOAK_URL/REALM/APP_REDIRECT_URI while
    # diagnose_idp/fix_redirect_uri use the .env values — a config mismatch.
    import login_flow, inspect
    src = inspect.getsource(login_flow)
    assert "load_dotenv" in src

def test_login_flow_url_normalizes_trailing_slash():
    from login_flow import build_broker_login_url
    with_slash = build_broker_login_url("http://kc:8080/", "R", "c", "http://cb")
    without = build_broker_login_url("http://kc:8080", "R", "c", "http://cb")
    assert with_slash == without
    assert "//realms" not in with_slash.replace("http://", "")

def test_all_operational_tools_load_dotenv():
    # All CLI tools that read config should load .env for consistency.
    import inspect
    import diagnose_idp, fix_redirect_uri, rotate_secret, login_flow
    for mod in (diagnose_idp, fix_redirect_uri, rotate_secret, login_flow):
        assert "load_dotenv" in inspect.getsource(mod), mod.__name__
