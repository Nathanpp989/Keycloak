#!/usr/bin/env python3
"""Tests for openbao_connect.py — the OpenBao 'Z-axis' integration.
All three capabilities are exercised against a mocked OpenBao HTTP API via the
`responses` library, so no live `bao server -dev` is needed."""
from __future__ import annotations

import json

import pytest
import responses

import openbao_connect as ob

ADDR = "http://127.0.0.1:8200"
TOK = "root"


# ── shared: enable_auth_method idempotency ──────────────────────────────────
@responses.activate
def test_enable_auth_method_new():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/oidc", status=204)
    assert ob.enable_auth_method("oidc", "oidc", token=TOK, addr=ADDR) is True

@responses.activate
def test_enable_auth_method_already_exists_is_ok():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/oidc",
                  json={"errors": ["path is already in use at oidc/"]}, status=400)
    # Idempotent: a re-run must not raise.
    assert ob.enable_auth_method("oidc", "oidc", token=TOK, addr=ADDR) is True

@responses.activate
def test_enable_auth_method_real_error_raises():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/oidc",
                  json={"errors": ["permission denied"]}, status=403)
    with pytest.raises(ob.OpenBaoError, match="permission denied"):
        ob.enable_auth_method("oidc", "oidc", token=TOK, addr=ADDR)

def test_missing_token_raises():
    with pytest.raises(ob.OpenBaoError, match="No OpenBao token"):
        ob.enable_auth_method("oidc", "oidc", token="", addr=ADDR)


# ── Capability 1: Keycloak -> OpenBao (OIDC) ────────────────────────────────
@responses.activate
def test_configure_keycloak_oidc_writes_config_and_role():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/oidc", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/config", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/role/keycloak", status=204)
    role = ob.configure_keycloak_oidc(
        "http://localhost:8080/", "Premkey", "openbao", "kc-secret",
        openbao_addr=ADDR, openbao_token=TOK)
    # discovery URL is realm base, no trailing slash duplication
    cfg_call = [c for c in responses.calls if c.request.url.endswith("/config")][0]
    cfg = json.loads(cfg_call.request.body)
    assert cfg["oidc_discovery_url"] == "http://localhost:8080/realms/Premkey"
    assert cfg["oidc_client_id"] == "openbao"
    # role maps preferred_username and registers OpenBao callback URIs
    assert role["user_claim"] == "preferred_username"
    assert any("oidc/callback" in u for u in role["allowed_redirect_uris"])

@responses.activate
def test_configure_keycloak_oidc_custom_policies():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/oidc", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/config", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/role/keycloak", status=204)
    role = ob.configure_keycloak_oidc(
        "http://localhost:8080", "Premkey", "openbao", "s",
        policies=["admin", "reader"], openbao_addr=ADDR, openbao_token=TOK)
    assert role["policies"] == ["admin", "reader"]


# ── Capability 2: Auth0 -> OpenBao (JWT) ────────────────────────────────────
@responses.activate
def test_configure_auth0_jwt_writes_issuer_and_role():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/auth0-jwt", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/config", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/role/auth0", status=204)
    role = ob.configure_auth0_jwt(
        "dev-5cgeft7q4xtq80h1.us.auth0.com",
        bound_audiences=["https://api.example.com"],
        openbao_addr=ADDR, openbao_token=TOK)
    cfg_call = [c for c in responses.calls if c.request.url.endswith("/config")][0]
    cfg = json.loads(cfg_call.request.body)
    assert cfg["oidc_discovery_url"] == "https://dev-5cgeft7q4xtq80h1.us.auth0.com/"
    assert cfg["bound_issuer"] == "https://dev-5cgeft7q4xtq80h1.us.auth0.com/"
    assert role["bound_audiences"] == ["https://api.example.com"]
    assert role["role_type"] == "jwt"

@responses.activate
def test_configure_auth0_jwt_without_audience_binds_claims():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/auth0-jwt", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/config", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/role/auth0", status=204)
    role = ob.configure_auth0_jwt("d.auth0.com", openbao_addr=ADDR, openbao_token=TOK)
    assert "bound_audiences" not in role
    assert role["bound_claims"] == {"sub": "*"}

@responses.activate
def test_login_auth0_jwt_returns_token():
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/login",
                  json={"auth": {"client_token": "s.openbao-token"}}, status=200)
    tok = ob.login_auth0_jwt("the.jwt.here", openbao_addr=ADDR)
    assert tok == "s.openbao-token"
    body = json.loads(responses.calls[0].request.body)
    assert body["role"] == "auth0" and body["jwt"] == "the.jwt.here"

@responses.activate
def test_login_auth0_jwt_no_token_raises():
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/login",
                  json={"auth": {}}, status=200)
    with pytest.raises(ob.OpenBaoError, match="no client_token"):
        ob.login_auth0_jwt("j", openbao_addr=ADDR)


# ── Capability 3: OpenBao as secret store (KV v2) ───────────────────────────
@responses.activate
def test_put_and_get_secret():
    responses.add(responses.POST, f"{ADDR}/v1/secret/data/AUTH0_CLIENT_SECRET",
                  json={"data": {"version": 1}}, status=200)
    responses.add(responses.GET, f"{ADDR}/v1/secret/data/AUTH0_CLIENT_SECRET",
                  json={"data": {"data": {"value": "the-secret"}}}, status=200)
    s = ob.OpenBaoSecrets(addr=ADDR, token=TOK)
    s.put_secret("AUTH0_CLIENT_SECRET", "the-secret")
    assert s.get_secret("AUTH0_CLIENT_SECRET") == "the-secret"
    put_body = json.loads([c for c in responses.calls
                           if c.request.method == "POST"][0].request.body)
    assert put_body["data"]["value"] == "the-secret"

@responses.activate
def test_get_secret_missing_value_raises():
    responses.add(responses.GET, f"{ADDR}/v1/secret/data/X",
                  json={"data": {"data": {}}}, status=200)
    s = ob.OpenBaoSecrets(addr=ADDR, token=TOK)
    with pytest.raises(ob.OpenBaoError, match="no 'value' field"):
        s.get_secret("X")

@responses.activate
def test_get_secret_404_raises():
    responses.add(responses.GET, f"{ADDR}/v1/secret/data/nope", status=404)
    s = ob.OpenBaoSecrets(addr=ADDR, token=TOK)
    with pytest.raises(ob.OpenBaoError, match="not found"):
        s.get_secret("nope")


# ── resolve_secret: OpenBao + Key Vault fallback ────────────────────────────
@responses.activate
def test_resolve_secret_prefers_openbao(monkeypatch):
    monkeypatch.setattr(ob, "OPENBAO_TOKEN", "root")
    responses.add(responses.GET, f"{ADDR}/v1/secret/data/S",
                  json={"data": {"data": {"value": "from-openbao"}}}, status=200)
    monkeypatch.setattr(ob, "OPENBAO_ADDR", ADDR)
    assert ob.resolve_secret("S") == "from-openbao"

def test_resolve_secret_falls_back_to_keyvault(monkeypatch):
    # OpenBao not configured -> resolver uses Key Vault.
    monkeypatch.setattr(ob, "OPENBAO_TOKEN", "")
    import sys, types
    fake = types.ModuleType("authorize")
    fake.get_secret = lambda name: f"kv-{name}"
    monkeypatch.setitem(sys.modules, "authorize", fake)
    assert ob.resolve_secret("MY_SECRET") == "kv-MY_SECRET"

def test_resolve_secret_all_sources_fail(monkeypatch):
    monkeypatch.setattr(ob, "OPENBAO_TOKEN", "")
    import sys, types
    fake = types.ModuleType("authorize")
    def boom(name):
        raise RuntimeError("kv down")
    fake.get_secret = boom
    monkeypatch.setitem(sys.modules, "authorize", fake)
    with pytest.raises(ob.OpenBaoError, match="not resolvable"):
        ob.resolve_secret("X")


# ── network error surfaces a clear message ──────────────────────────────────
@responses.activate
def test_network_error_is_actionable():
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("refused")
    responses.add_callback(responses.GET, f"{ADDR}/v1/secret/data/X", callback=boom)
    s = ob.OpenBaoSecrets(addr=ADDR, token=TOK)
    with pytest.raises(ob.OpenBaoError, match="bao server -dev"):
        s.get_secret("X")


# ── scaffold_all wires all three ────────────────────────────────────────────
@responses.activate
def test_scaffold_all():
    for p in ("sys/auth/oidc", "auth/oidc/config", "auth/oidc/role/keycloak",
              "sys/auth/auth0-jwt", "auth/auth0-jwt/config",
              "auth/auth0-jwt/role/auth0"):
        responses.add(responses.POST, f"{ADDR}/v1/{p}", status=204)
    summary = ob.scaffold_all(
        keycloak_url="http://localhost:8080", keycloak_realm="Premkey",
        keycloak_oidc_client_id="openbao", keycloak_oidc_client_secret="s",
        auth0_domain="d.auth0.com", auth0_audience="https://api",
        openbao_addr=ADDR, openbao_token=TOK)
    assert "keycloak_oidc" in summary and "auth0_jwt" in summary
    assert summary["secret_store"]["mount"] == "secret"


# ════════════════════════════════════════════════════════════════════════════
# EDGE CASES & FAILURE MODES
# Each class below mirrors a real bug that bit us during the Keycloak<->Auth0
# integration, applied to OpenBao so we don't relive it.
# ════════════════════════════════════════════════════════════════════════════

# ── Class: opaque error should be made actionable (the "generic broker error"
#    lesson). OpenBao validates the discovery URL by fetching it; an unreachable
#    IdP must produce a CLEAR message, not a raw 400. Verified live in
#    openbao_smoke.py; unit-tested here. ──
@responses.activate
def test_unreachable_discovery_url_gives_clear_error():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/auth0-jwt", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/config",
                  json={"errors": ["error checking oidc discovery URL"]}, status=400)
    with pytest.raises(ob.OpenBaoError) as e:
        ob.configure_auth0_jwt("unreachable.invalid", openbao_addr=ADDR,
                               openbao_token=TOK)
    msg = str(e.value)
    assert "reach the OIDC discovery" in msg
    assert "reachable FROM the OpenBao server" in msg  # names the real cause

# ── Class: trailing-slash / URL normalization (bit us repeatedly with issuers
#    and Keycloak URLs). ──
@responses.activate
def test_keycloak_url_trailing_slash_normalized():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/oidc", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/config", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/role/keycloak", status=204)
    for kc_url in ("http://localhost:8080", "http://localhost:8080/",
                   "http://localhost:8080///"):
        responses.calls.reset()
        ob.configure_keycloak_oidc(kc_url, "Premkey", "id", "sec",
                                   openbao_addr=ADDR, openbao_token=TOK)
        cfg = json.loads([c for c in responses.calls
                          if c.request.url.endswith("/config")][0].request.body)
        # No double slash, exactly one /realms/ segment.
        assert cfg["oidc_discovery_url"] == "http://localhost:8080/realms/Premkey"

@responses.activate
def test_auth0_issuer_always_has_single_trailing_slash():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/auth0-jwt", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/config", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/role/auth0", status=204)
    for domain in ("d.auth0.com", "d.auth0.com/", "  d.auth0.com  "):
        responses.calls.reset()
        ob.configure_auth0_jwt(domain, openbao_addr=ADDR, openbao_token=TOK)
        cfg = json.loads([c for c in responses.calls
                          if c.request.url.endswith("/config")][0].request.body)
        assert cfg["bound_issuer"] == "https://d.auth0.com/"  # exactly one slash

# ── Class: OPENBAO_ADDR itself has a trailing slash -> no double-slash URLs. ──
@responses.activate
def test_addr_trailing_slash_no_double_slash():
    responses.add(responses.GET, f"{ADDR}/v1/secret/data/X",
                  json={"data": {"data": {"value": "v"}}}, status=200)
    s = ob.OpenBaoSecrets(addr=ADDR + "/", token=TOK)  # trailing slash on addr
    assert s.get_secret("X") == "v"
    assert "//v1" not in responses.calls[0].request.url

# ── Class: silent-failure on writes (the false "✓" bug). Every write path must
#    raise on server rejection, not pretend success. ──
@responses.activate
def test_put_secret_403_raises_not_silent():
    responses.add(responses.POST, f"{ADDR}/v1/secret/data/X",
                  json={"errors": ["permission denied"]}, status=403)
    s = ob.OpenBaoSecrets(addr=ADDR, token=TOK)
    with pytest.raises(ob.OpenBaoError, match="permission denied"):
        s.put_secret("X", "v")

@responses.activate
def test_config_write_500_raises():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/oidc", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/config",
                  json={"errors": ["internal error"]}, status=500)
    with pytest.raises(ob.OpenBaoError, match="500"):
        ob.configure_keycloak_oidc("http://kc", "R", "id", "sec",
                                   openbao_addr=ADDR, openbao_token=TOK)

# ── Class: partial failure — mount succeeds but role write fails. Must surface,
#    not leave a half-configured auth method looking healthy. ──
@responses.activate
def test_role_write_failure_surfaces():
    responses.add(responses.POST, f"{ADDR}/v1/sys/auth/oidc", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/config", status=204)
    responses.add(responses.POST, f"{ADDR}/v1/auth/oidc/role/keycloak",
                  json={"errors": ["invalid policy"]}, status=400)
    with pytest.raises(ob.OpenBaoError, match="write OIDC role"):
        ob.configure_keycloak_oidc("http://kc", "R", "id", "sec",
                                   openbao_addr=ADDR, openbao_token=TOK)

# ── Class: empty/whitespace credentials (the "client ID pasted as secret" and
#    shell-mangled-value lessons — catch degenerate inputs early). ──
def test_missing_token_everywhere():
    # No token via arg, and module default empty -> every entry point errors
    # clearly rather than sending an unauthenticated request.
    import importlib
    saved = ob.OPENBAO_TOKEN
    try:
        ob.OPENBAO_TOKEN = ""
        for call in (
            lambda: ob.OpenBaoSecrets(token="").get_secret("X"),
            lambda: ob.OpenBaoSecrets(token="").put_secret("X", "v"),
            lambda: ob.enable_auth_method("jwt", "m", token=""),
        ):
            with pytest.raises(ob.OpenBaoError, match="No OpenBao token"):
                call()
    finally:
        ob.OPENBAO_TOKEN = saved
        importlib.reload  # noqa: B018 - keep reference; no-op

# ── Class: JSON-shape assumptions (KV v2 nests data.data; a v1-shaped or
#    malformed reply must not silently return None or crash unhelpfully). ──
@responses.activate
def test_kv_v1_shaped_reply_raises_clearly():
    # A KV v1 engine would return {"data": {"value": ...}} (single nesting),
    # not v2's {"data": {"data": {...}}}. Our reader expects v2; a v1 reply
    # must raise a clear 'no value' error, not return garbage.
    responses.add(responses.GET, f"{ADDR}/v1/secret/data/X",
                  json={"data": {"value": "v1-style"}}, status=200)
    s = ob.OpenBaoSecrets(addr=ADDR, token=TOK)
    with pytest.raises(ob.OpenBaoError, match="no 'value' field"):
        s.get_secret("X")

@responses.activate
def test_malformed_json_reply_does_not_crash():
    responses.add(responses.GET, f"{ADDR}/v1/secret/data/X",
                  body="not json at all", status=200)
    s = ob.OpenBaoSecrets(addr=ADDR, token=TOK)
    # _check returns {} for non-JSON; get_secret then reports missing value.
    with pytest.raises(ob.OpenBaoError, match="no 'value' field"):
        s.get_secret("X")

# ── Class: login returns unexpected shapes ──
@responses.activate
def test_login_missing_auth_block():
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/login",
                  json={"warnings": ["something"]}, status=200)  # no 'auth'
    with pytest.raises(ob.OpenBaoError, match="no client_token"):
        ob.login_auth0_jwt("j", openbao_addr=ADDR)

# ── Class: resolver ordering is respected (prefer=keyvault path). ──
def test_resolve_secret_prefer_keyvault(monkeypatch):
    import sys, types
    monkeypatch.setattr(ob, "OPENBAO_TOKEN", "root")
    fake = types.ModuleType("authorize")
    fake.get_secret = lambda name: "from-kv-first"
    monkeypatch.setitem(sys.modules, "authorize", fake)
    # Even though OpenBao is configured, prefer='keyvault' uses KV first.
    assert ob.resolve_secret("S", prefer="keyvault") == "from-kv-first"

# ── Class: idempotency actually holds (the duplicate-mapper lesson). Re-running
#    enable with 'existing mount' variants must all be treated as success. ──
@responses.activate
def test_enable_idempotent_variant_messages():
    for msg in ("path is already in use at m/",
                "existing mount at m/",
                "Path is already in use"):
        responses.calls.reset()
        responses.add(responses.POST, f"{ADDR}/v1/sys/auth/m",
                      json={"errors": [msg]}, status=400)
        assert ob.enable_auth_method("jwt", "m", token=TOK, addr=ADDR) is True


# ── login round-trip mechanics (mocked; live version in openbao_login_smoke.py) ──
@responses.activate
def test_login_auth0_jwt_success_returns_client_token():
    responses.add(responses.POST, f"{ADDR}/v1/auth/custom-mount/login",
                  json={"auth": {"client_token": "s.tok", "policies": ["p"]}},
                  status=200)
    tok = ob.login_auth0_jwt("j.w.t", mount="custom-mount", openbao_addr=ADDR)
    assert tok == "s.tok"

@responses.activate
def test_login_auth0_jwt_rejected_jwt_raises():
    # OpenBao rejects a bad/expired/wrong-aud JWT with 400; must surface clearly.
    responses.add(responses.POST, f"{ADDR}/v1/auth/auth0-jwt/login",
                  json={"errors": ["error validating token: token is expired"]},
                  status=400)
    with pytest.raises(ob.OpenBaoError, match="JWT login failed"):
        ob.login_auth0_jwt("expired.jwt", openbao_addr=ADDR)

def test_login_checklist_mentions_both_flows():
    text = ob.login_checklist(openbao_addr=ADDR)
    assert "Keycloak -> OpenBao" in text
    assert "Auth0 -> OpenBao" in text
    # Includes the concrete callback URL OpenBao expects.
    assert "/oidc/callback" in text


# ════════════════════════════════════════════════════════════════════════════
# PILOT: authorize.get_secret with opt-in OpenBao-first resolution
# ════════════════════════════════════════════════════════════════════════════
def test_openbao_first_names_parsing(monkeypatch):
    import authorize
    monkeypatch.delenv("OPENBAO_SECRETS", raising=False)
    assert authorize._openbao_first_names() == set()
    monkeypatch.setenv("OPENBAO_SECRETS", "AUTH0_AUDIENCE")
    assert authorize._openbao_first_names() == {"AUTH0_AUDIENCE"}
    monkeypatch.setenv("OPENBAO_SECRETS", " A , B ,, C ")
    assert authorize._openbao_first_names() == {"A", "B", "C"}
    monkeypatch.setenv("OPENBAO_SECRETS", "*")
    assert authorize._openbao_first_names() == {"*"}

def test_get_secret_default_does_not_touch_openbao(monkeypatch):
    # Default (no OPENBAO_SECRETS) must NOT consult OpenBao at all — the
    # migration is opt-in and must not change existing behaviour.
    import authorize
    monkeypatch.delenv("OPENBAO_SECRETS", raising=False)
    called = {"n": 0}
    monkeypatch.setattr(authorize, "_try_openbao",
                        lambda n: called.__setitem__("n", called["n"] + 1))
    fake_kv = type("KV", (), {"get_secret": lambda self, n: type(
        "S", (), {"value": "from-kv"})()})()
    monkeypatch.setattr(authorize, "_get_kv_client", lambda: fake_kv)
    assert authorize.get_secret("AUTH0_AUDIENCE") == "from-kv"
    assert called["n"] == 0            # OpenBao never consulted

def test_get_secret_opted_in_uses_openbao(monkeypatch):
    import authorize
    monkeypatch.setenv("OPENBAO_SECRETS", "AUTH0_AUDIENCE")
    monkeypatch.setattr(authorize, "_try_openbao",
                        lambda n: "from-openbao" if n == "AUTH0_AUDIENCE" else None)
    assert authorize.get_secret("AUTH0_AUDIENCE") == "from-openbao"

def test_get_secret_opted_in_falls_back_to_kv_when_openbao_misses(monkeypatch):
    # OpenBao configured but the secret isn't there -> Key Vault still serves it.
    import authorize
    monkeypatch.setenv("OPENBAO_SECRETS", "AUTH0_AUDIENCE")
    monkeypatch.setattr(authorize, "_try_openbao", lambda n: None)
    fake_kv = type("KV", (), {"get_secret": lambda self, n: type(
        "S", (), {"value": "from-kv"})()})()
    monkeypatch.setattr(authorize, "_get_kv_client", lambda: fake_kv)
    assert authorize.get_secret("AUTH0_AUDIENCE") == "from-kv"

def test_get_secret_wildcard_applies_to_all(monkeypatch):
    import authorize
    monkeypatch.setenv("OPENBAO_SECRETS", "*")
    monkeypatch.setattr(authorize, "_try_openbao", lambda n: f"ob-{n}")
    assert authorize.get_secret("ANYTHING") == "ob-ANYTHING"

def test_try_openbao_never_raises(monkeypatch):
    # A broken OpenBao must degrade to None (so KV takes over), never raise —
    # adding a secret store must not add a new single point of failure.
    import authorize
    import openbao_connect
    monkeypatch.setattr(openbao_connect, "OPENBAO_TOKEN", "tok")
    def boom(self, name):
        raise RuntimeError("openbao exploded")
    monkeypatch.setattr(openbao_connect.OpenBaoSecrets, "get_secret", boom)
    assert authorize._try_openbao("X") is None

def test_try_openbao_returns_none_when_unconfigured(monkeypatch):
    import authorize
    import openbao_connect
    monkeypatch.setattr(openbao_connect, "OPENBAO_TOKEN", "")
    assert authorize._try_openbao("X") is None
