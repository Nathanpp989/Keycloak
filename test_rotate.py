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
    # Keycloak IdP GET + PUT
    idp_url = f"{KC_URL}/admin/realms/{REALM}/identity-provider/instances/auth0"
    responses.add(responses.GET, idp_url,
                  json={"alias": "auth0", "config": {"clientSecret": "old"}}, status=200)
    responses.add(responses.PUT, idp_url, status=204)

    auth0 = Auth0Connect(DOMAIN, "cid", "old-secret")
    new = rotate_and_sync(auth0, KC_URL, REALM, "kc-tok", update_env=False)
    assert new == "rotated-xyz"
    # Confirm Keycloak got the rotated secret
    put_call = [c for c in responses.calls if c.request.method == "PUT"][0]
    assert json.loads(put_call.request.body)["config"]["clientSecret"] == "rotated-xyz"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
