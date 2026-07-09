#!/usr/bin/env python3
# test_rotate.py
# Tests for rotate_secret.py — Auth0 secret rotation + Keycloak IdP sync.
# All HTTP mocked; no live services needed.

from __future__ import annotations

import json

import pytest
import responses

from auth0_connect import Auth0Connect
from rotate_secret import update_keycloak_idp_secret, rotate_and_sync

DOMAIN = "test-tenant.us.auth0.com"
KC_URL = "http://localhost:8080"
REALM = "Premkey"


@responses.activate
def test_update_keycloak_idp_secret_read_modify_write():
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    # GET returns existing IdP config
    responses.add(responses.GET, idp_url,
                  json={"alias": "auth0", "providerId": "oidc",
                        "config": {"clientId": "cid", "clientSecret": "old",
                                   "issuer": "https://x/"}},
                  status=200)
    responses.add(responses.PUT, idp_url, status=204)
    update_keycloak_idp_secret(KC_URL, REALM, "kc-tok", "auth0", "new-secret")
    # The PUT must preserve other config and set the new secret
    put_call = [c for c in responses.calls if c.request.method == "PUT"][0]
    body = json.loads(put_call.request.body)
    assert body["config"]["clientSecret"] == "new-secret"
    assert body["config"]["clientId"] == "cid"       # preserved
    assert body["config"]["issuer"] == "https://x/"  # preserved


@responses.activate
def test_update_keycloak_idp_secret_not_found():
    modern = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    legacy = f"{KC_URL}/auth/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, modern, status=404)
    responses.add(responses.GET, legacy, status=404)
    with pytest.raises(RuntimeError, match="not found"):
        update_keycloak_idp_secret(KC_URL, REALM, "kc-tok", "auth0", "new")


@responses.activate
def test_rotate_and_sync_end_to_end():
    # Auth0 token
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    # Rotate returns new secret
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "rotated-xyz"}, status=200)
    # Keycloak IdP GET (read for update) + PUT + GET (read for verify)
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    # responses consumes registered responses in order:
    responses.add(responses.GET, idp_url,                       # read-modify-write read
                  json={"alias": "auth0", "config": {"clientSecret": "old"}}, status=200)
    responses.add(responses.PUT, idp_url, status=204)
    responses.add(responses.GET, idp_url,                       # verification read
                  json={"alias": "auth0", "config": {"clientSecret": "rotated-xyz"}},
                  status=200)

    auth0 = Auth0Connect(DOMAIN, "cid", "old-secret")
    new = rotate_and_sync(auth0, KC_URL, REALM, "kc-tok", update_env=False)
    assert new == "rotated-xyz"
    # Confirm Keycloak got the rotated secret
    put_call = [c for c in responses.calls if c.request.method == "PUT"][0]
    assert json.loads(put_call.request.body)["config"]["clientSecret"] == "rotated-xyz"


@responses.activate
def test_verify_keycloak_idp_secret_match():
    from rotate_secret import verify_keycloak_idp_secret
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url,
                  json={"config": {"clientSecret": "abc"}}, status=200)
    assert verify_keycloak_idp_secret(KC_URL, REALM, "tok", "auth0", "abc") is True

@responses.activate
def test_verify_keycloak_idp_secret_masked_returns_false():
    # Keycloak masks the secret on read -> cannot positively verify -> False
    from rotate_secret import verify_keycloak_idp_secret
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url,
                  json={"config": {"clientSecret": "**********"}}, status=200)
    assert verify_keycloak_idp_secret(KC_URL, REALM, "tok", "auth0", "abc") is False


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


@responses.activate
def test_rotate_and_sync_verify_reuses_discovered_url():
    # E2 efficiency: verify must hit ONLY the URL update discovered (one GET),
    # not re-probe both modern and legacy path variants.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "new-s"}, status=200)
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url,
                  json={"alias": "auth0", "config": {"clientSecret": "old"}}, status=200)
    responses.add(responses.PUT, idp_url, status=204)
    responses.add(responses.GET, idp_url,
                  json={"alias": "auth0", "config": {"clientSecret": "new-s"}}, status=200)

    auth0 = Auth0Connect(DOMAIN, "cid", "old")
    rotate_and_sync(auth0, KC_URL, REALM, "kc-tok", update_env=False)
    legacy_calls = [c for c in responses.calls if "/auth/admin/" in c.request.url]
    assert legacy_calls == []          # never probed the legacy path
    gets = [c for c in responses.calls
            if c.request.method == "GET" and "identity-provider" in c.request.url]
    assert len(gets) == 2              # one read-for-update + one verify, no extras


# ──────────────────────────────────────────────
# .env persistence + R1 failure-recovery + main() — previously untested paths
# ──────────────────────────────────────────────
import os
import tempfile


def _make_env_file(tmpdir, secret="old-secret"):
    path = os.path.join(tmpdir, ".env")
    with open(path, "w") as f:
        f.write(f"AUTH0_CLIENT_SECRET={secret}\n")
    return path


@responses.activate
def test_rotate_and_sync_persists_new_secret_to_env(monkeypatch):
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "fresh-123"}, status=200)
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url,
                  json={"alias": "auth0", "config": {"clientSecret": "old"}}, status=200)
    responses.add(responses.PUT, idp_url, status=204)
    responses.add(responses.GET, idp_url,
                  json={"alias": "auth0", "config": {"clientSecret": "fresh-123"}}, status=200)
    with tempfile.TemporaryDirectory() as td:
        env_path = _make_env_file(td)
        monkeypatch.setenv("DOTENV_PATH", env_path)
        auth0 = Auth0Connect(DOMAIN, "cid", "old-secret")
        rotate_and_sync(auth0, KC_URL, REALM, "kc-tok", update_env=True)
        content = open(env_path).read()
        assert "fresh-123" in content          # new secret persisted
        assert "old-secret" not in content     # old secret replaced


@responses.activate
def test_rotate_keycloak_failure_still_persists_secret(monkeypatch):
    # R1 regression: Keycloak update fails AFTER Auth0 rotation -> the new
    # secret must be captured in .env and the error must explain remediation.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "orphan-risk"}, status=200)
    # Keycloak IdP fetch: 500 on modern path -> update raises immediately
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url, status=500)
    with tempfile.TemporaryDirectory() as td:
        env_path = _make_env_file(td)
        monkeypatch.setenv("DOTENV_PATH", env_path)
        auth0 = Auth0Connect(DOMAIN, "cid", "old-secret")
        with pytest.raises(RuntimeError, match="Keycloak IdP update FAILED"):
            rotate_and_sync(auth0, KC_URL, REALM, "kc-tok", update_env=True)
        content = open(env_path).read()
        assert "orphan-risk" in content        # R1: secret NOT lost


@responses.activate
def test_rotate_failure_without_env_names_dashboard(monkeypatch):
    # R1 variant: update_env=False -> error must point to the Auth0 dashboard.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "s"}, status=200)
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url, status=500)
    auth0 = Auth0Connect(DOMAIN, "cid", "old")
    with pytest.raises(RuntimeError, match="Auth0 dashboard"):
        rotate_and_sync(auth0, KC_URL, REALM, "kc-tok", update_env=False)


@responses.activate
def test_main_end_to_end(monkeypatch):
    # The full CLI flow: env -> KC admin token -> rotate -> KC update -> .env
    import rotate_secret as rs
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "cli-new"}, status=200)
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url,
                  json={"alias": "auth0", "config": {"clientSecret": "old"}}, status=200)
    responses.add(responses.PUT, idp_url, status=204)
    responses.add(responses.GET, idp_url,
                  json={"alias": "auth0", "config": {"clientSecret": "cli-new"}}, status=200)
    with tempfile.TemporaryDirectory() as td:
        env_path = _make_env_file(td)
        for k, v in {"AUTH0_DOMAIN": DOMAIN, "AUTH0_CLIENT_ID": "cid",
                     "AUTH0_CLIENT_SECRET": "old", "KEYCLOAK_URL": KC_URL,
                     "KEYCLOAK_REALM": REALM, "DOTENV_PATH": env_path}.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setattr(rs, "get_keycloak_admin_token", lambda *a, **k: "kc-tok")
        rs.main()  # must complete without raising
        assert "cli-new" in open(env_path).read()


def test_main_missing_env_exits_clearly(monkeypatch):
    import rotate_secret as rs
    for k in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(SystemExit, match="Missing required environment variables"):
        rs.main()


@responses.activate
def test_rotate_failure_env_write_error_does_not_mask_remediation(monkeypatch):
    # S2 regression: if writing .env ALSO fails, the operator must still get
    # the remediation error (pointing to the dashboard), not a raw IOError.
    responses.add(responses.POST, f"https://{DOMAIN}/oauth/token",
                  json={"access_token": "t", "expires_in": 999}, status=200)
    responses.add(responses.POST,
                  f"https://{DOMAIN}/api/v2/clients/cid/rotate-secret",
                  json={"client_id": "cid", "client_secret": "s"}, status=200)
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url, status=500)
    import rotate_secret as rs
    def boom(_):
        raise PermissionError(".env is read-only")
    monkeypatch.setattr(rs, "_persist_secret_to_env", boom)
    auth0 = Auth0Connect(DOMAIN, "cid", "old")
    with pytest.raises(RuntimeError, match="Auth0 dashboard"):
        rs.rotate_and_sync(auth0, KC_URL, REALM, "kc-tok", update_env=True)
