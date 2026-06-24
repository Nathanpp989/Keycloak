# login_flow.py
# Helpers + a documented manual procedure for testing the real browser login
# flow (Keycloak -> Auth0 -> back to Keycloak -> your app).
#
# A genuine browser flow needs a running Keycloak, a configured Auth0 IdP, and a
# human (or Selenium) clicking through consent screens — it cannot run headless
# in CI. So this module provides:
#   1. build_broker_login_url(): constructs the Keycloak-brokered Auth0 login URL
#      (this IS unit-testable and is covered in auth0_test.py).
#   2. A printed step-by-step manual checklist when run directly.

from __future__ import annotations

import os
from urllib.parse import urlencode


def build_broker_login_url(
    keycloak_url: str,
    realm: str,
    client_id: str,
    redirect_uri: str,
    idp_alias: str = "auth0",
    scope: str = "openid profile email",
) -> str:
    """
    Build the Keycloak authorization URL that initiates login, hinting Keycloak
    to broker straight to the Auth0 identity provider via kc_idp_hint.

    Visiting this URL in a browser should redirect: Keycloak -> Auth0 login ->
    (user authenticates) -> back to Keycloak -> back to redirect_uri with a code.
    """
    base = keycloak_url.rstrip("/")
    params = {
        "client_id":     client_id,
        "response_type": "code",
        "scope":         scope,
        "redirect_uri":  redirect_uri,
        "kc_idp_hint":   idp_alias,   # tells Keycloak to use the Auth0 IdP directly
    }
    return f"{base}/realms/{realm}/protocol/openid-connect/auth?{urlencode(params)}"


def main() -> None:
    keycloak_url = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    realm        = os.environ.get("KEYCLOAK_REALM", "Premkey")
    client_id    = os.environ.get("KEYCLOAK_CLIENT_ID", "Hello-World-app")
    redirect_uri = os.environ.get("APP_REDIRECT_URI", "http://localhost:8000/protected")

    url = build_broker_login_url(keycloak_url, realm, client_id, redirect_uri)

    print("=" * 70)
    print("MANUAL BROWSER LOGIN FLOW TEST")
    print("=" * 70)
    print("\nPrereqs:")
    print("  - Keycloak running at", keycloak_url)
    print(f"  - Realm '{realm}' exists with the Auth0 IdP registered (run auth0_connect.py)")
    print("  - A client (e.g. 'Hello-World-app') with redirect URI:", redirect_uri)
    print("\nSteps:")
    print("  1. Open this URL in a browser:\n")
    print("     " + url + "\n")
    print("  2. Keycloak should redirect you straight to the Auth0 login page.")
    print("  3. Log in with an Auth0 user (or a social provider you configured).")
    print("  4. Auth0 redirects back to Keycloak, which redirects to:")
    print("     " + redirect_uri)
    print("  5. You should arrive authenticated (a 'code' param on the redirect).")
    print("\nIf step 2 shows the Keycloak login form instead of Auth0, the")
    print("kc_idp_hint/alias is wrong or the IdP isn't registered.")
    print("=" * 70)


if __name__ == "__main__":
    main()
