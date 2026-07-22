#!/usr/bin/env python3
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

import base64
import json
import logging
import os
from urllib.parse import urlencode

# Load .env so this tool reads the same KEYCLOAK_URL / REALM / APP_REDIRECT_URI
# as diagnose_idp.py, fix_redirect_uri.py, and rotate_secret.py. Without this,
# running login_flow.py would silently use built-in defaults while the other
# tools used your .env values — a confusing config mismatch.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import requests

logger = logging.getLogger(__name__)


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


def exchange_code_for_tokens(
    keycloak_url: str,
    realm: str,
    client_id: str,
    redirect_uri: str,
    code: str,
    client_secret: str | None = None,
    timeout: int = 10,
) -> dict:
    """
    Exchange an authorization code (from the browser redirect) for tokens at
    Keycloak's token endpoint. Returns the parsed token response dict on success.

    Raises RuntimeError with a clear, actionable message on the common failure
    modes so a human debugging the live flow knows what to fix, rather than
    getting a raw stack trace:
      - network failure reaching Keycloak
      - Keycloak returning an OAuth error (invalid_grant, redirect mismatch, ...)
      - a non-JSON or tokenless response
    """
    base = keycloak_url.rstrip("/")
    token_url = f"{base}/realms/{realm}/protocol/openid-connect/token"
    data = {
        "grant_type":   "authorization_code",
        "code":         code,
        "client_id":    client_id,
        "redirect_uri": redirect_uri,
    }
    if client_secret:
        data["client_secret"] = client_secret
    try:
        resp = requests.post(token_url, data=data, timeout=timeout)
    except requests.RequestException as exc:
        raise RuntimeError(f"Could not reach Keycloak token endpoint at "
                           f"{token_url}: {exc}") from exc
    if resp.status_code != 200:
        # Surface Keycloak's own OAuth error so the cause is obvious.
        detail = resp.text
        try:
            body = resp.json()
            detail = body.get("error_description") or body.get("error") or detail
        except ValueError:
            pass
        if resp.status_code == 401 and "client" in str(detail).lower():
            raise RuntimeError(
                f"Token exchange failed (401): {detail}. This is the "
                f"app<->Keycloak leg, NOT Auth0: the '{client_id}' client is "
                "confidential and the request "
                + ("sent no client_secret." if not client_secret
                   else "sent a client_secret Keycloak rejected.")
                + " Get the value from Keycloak admin -> Clients -> "
                f"{client_id} -> Credentials -> Client secret, and set "
                "KEYCLOAK_CLIENT_SECRET (single-quoted).")
        raise RuntimeError(
            f"Token exchange failed ({resp.status_code}): {detail}. "
            "Common causes: redirect_uri mismatch, wrong client_secret, or an "
            "expired/reused code."
        )
    try:
        body = resp.json()
    except ValueError as exc:
        raise RuntimeError("Keycloak token endpoint returned non-JSON") from exc
    if "access_token" not in body:
        raise RuntimeError(f"Token response had no access_token: {body}")
    return body


def decode_token_segments(token: str) -> dict:
    """
    Decode a JWT's header and payload WITHOUT verifying the signature — purely
    for diagnostics when eyeballing what Keycloak returned. Never use this for
    trust decisions (verify_auth0_token does real verification). Returns
    {"header": {...}, "payload": {...}}.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a well-formed JWT (expected 3 dot-separated parts)")

    def _seg(seg: str) -> dict:
        # Restore base64url padding before decoding.
        padded = seg + "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))

    return {"header": _seg(parts[0]), "payload": _seg(parts[1])}


def process_callback_query(query: dict, keycloak_url: str, realm: str,
                           client_id: str, redirect_uri: str,
                           client_secret: str | None) -> dict:
    """
    Given the parsed query dict from the browser redirect, drive the token
    exchange and return a result dict: {"ok": bool, ...}. Pure logic (no HTTP
    server), so it is unit-testable. `query` values are lists, as produced by
    urllib.parse.parse_qs.
    """
    if "error" in query:
        msg = query.get("error_description", query["error"])[0]
        return {"ok": False, "error": f"IdP returned error: {msg}"}
    code = query.get("code", [None])[0]
    if not code:
        return {"ok": False, "pending": True, "error": "no authorization code yet"}
    try:
        tokens = exchange_code_for_tokens(
            keycloak_url, realm, client_id, redirect_uri, code,
            client_secret=client_secret)
        claims = decode_token_segments(tokens["access_token"])["payload"]
        return {
            "ok": True,
            "username": claims.get("preferred_username") or claims.get("sub", "?"),
            "idp": claims.get("identity_provider", "(not present)"),
        }
    except (RuntimeError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


def run_callback_catcher(keycloak_url: str, realm: str, client_id: str,
                         redirect_uri: str, client_secret: str | None,
                         port: int, secret_error: str | None = None) -> int:
    """
    Start a one-shot local HTTP server on `port` to catch the browser redirect,
    exchange the authorization code for tokens, and print a diagnostic summary.
    Returns a process exit code (0 = a valid token round-trip completed).
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    outcome: dict = {}

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            query = parse_qs(urlparse(self.path).query)
            res = process_callback_query(query, keycloak_url, realm, client_id,
                                         redirect_uri, client_secret)
            if res.get("pending"):
                self._reply("Waiting for the OAuth redirect (no 'code' yet).")
                return
            if res["ok"]:
                self._reply(f"Success! Authenticated as {res['username']}. "
                            f"Broker IdP claim: {res['idp']}. Close this tab.")
            else:
                self._reply(f"Login failed: {res['error']}")
            outcome.update(res)

        def _reply(self, text: str):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(text.encode("utf-8"))

    server = HTTPServer(("127.0.0.1", port), _Handler)
    print(f"\nListening for the redirect on http://127.0.0.1:{port} ...")
    print("Complete the login in your browser; this will report the result.\n")
    while not outcome:
        server.handle_request()
    if outcome["ok"]:
        print(f"✓ Round trip OK — user={outcome['username']}, idp={outcome['idp']}")
        return 0
    print(f"✗ Login flow failed — {outcome.get('error')}")
    if secret_error:
        print(f"  NOTE: no client secret was available. Auto-fetch failed with: "
              f"{secret_error}")
    return 1


def diagnose_redirect_uri(keycloak_url: str, realm: str, admin_token: str,
                          client_id: str, redirect_uri: str,
                          timeout: int = 10) -> dict:
    """
    Diagnose a Keycloak "Invalid parameter: redirect_uri" error by reporting
    exactly what the client has registered versus what's being requested, and
    whether Keycloak's matching rules would accept it. Returns a dict with the
    findings and a human-readable 'verdict'. Requires a realm-admin token.
    """
    base = keycloak_url.rstrip("/")
    headers = {"authorization": f"Bearer {admin_token}"}
    info: dict = {"requested": redirect_uri, "client_id": client_id}
    for prefix in ("/admin/realms", "/auth/admin/realms"):
        try:
            resp = requests.get(f"{base}{prefix}/{realm}/clients", headers=headers,
                                params={"clientId": client_id}, timeout=timeout)
        except requests.RequestException as exc:
            info["verdict"] = f"cannot reach Keycloak: {exc}"
            return info
        if resp.status_code == 404 and prefix == "/admin/realms":
            continue
        if not resp.ok:
            info["verdict"] = f"client lookup failed ({resp.status_code}): {resp.text}"
            return info
        clients = resp.json()
        if not clients:
            info["verdict"] = (f"NO client with clientId '{client_id}' exists in "
                               f"realm '{realm}'. Check the exact clientId "
                               "(case-sensitive) or create the client.")
            return info
        client = clients[0]
        registered = client.get("redirectUris") or []
        info["registered"] = registered
        info["standard_flow_enabled"] = client.get("standardFlowEnabled")
        # Apply Keycloak's matching: exact match, or a '*' wildcard suffix match.
        def _matches(pattern: str, uri: str) -> bool:
            if pattern == uri:
                return True
            if pattern.endswith("*"):
                return uri.startswith(pattern[:-1])
            return False
        info["would_match"] = any(_matches(p, redirect_uri) for p in registered)
        if not registered:
            info["verdict"] = ("client has NO redirect URIs registered — every "
                               "redirect is rejected. Add one (ensure_client_redirect_uri).")
        elif not info["would_match"]:
            info["verdict"] = ("requested redirect_uri is NOT in the registered "
                               "list and matches no wildcard. Exact-match rules "
                               "apply: check http/https, localhost vs 127.0.0.1, "
                               "port, and trailing slash.")
        elif client.get("standardFlowEnabled") is False:
            info["verdict"] = ("redirect_uri is fine, but Standard Flow "
                               "(authorization code) is DISABLED on this client — "
                               "enable it.")
        else:
            info["verdict"] = ("redirect_uri should be accepted. If the error "
                               "persists, confirm you're hitting this same realm "
                               "and clientId.")
        return info
    info["verdict"] = f"realm '{realm}' not found at {base}"
    return info


def ensure_client_redirect_uri(keycloak_url: str, realm: str, admin_token: str,
                               client_id: str, redirect_uri: str,
                               timeout: int = 10) -> bool:
    """
    Make sure `redirect_uri` is in the Keycloak client's Valid Redirect URIs.
    This is the fix for Keycloak's "Invalid parameter: redirect_uri" error,
    which occurs when the auth request's redirect_uri isn't registered on the
    client. Returns True if the URI is present (added or already there).

    Requires a realm-admin token (get_keycloak_admin_token). No-op-safe to call
    repeatedly — it reads the client, adds the URI only if missing, and writes back.
    """
    base = keycloak_url.rstrip("/")
    headers = {"authorization": f"Bearer {admin_token}",
               "content-type": "application/json"}
    for prefix in ("/admin/realms", "/auth/admin/realms"):
        list_url = f"{base}{prefix}/{realm}/clients"
        try:
            resp = requests.get(list_url, headers=headers,
                                params={"clientId": client_id}, timeout=timeout)
        except requests.RequestException as exc:
            raise RuntimeError(f"Could not reach Keycloak at {list_url}: {exc}") from exc
        if resp.status_code == 404 and prefix == "/admin/realms":
            continue
        resp.raise_for_status()
        clients = resp.json()
        if not clients:
            raise RuntimeError(
                f"Keycloak client '{client_id}' not found in realm '{realm}'. "
                "Create it (or run your setup) before registering a redirect URI.")
        client = clients[0]
        uris = client.get("redirectUris") or []
        changed = False
        if redirect_uri not in uris:
            uris.append(redirect_uri)
            changed = True
        # Also register a wildcard on the same origin so trailing-slash / path
        # variations don't re-trigger the error during local testing.
        from urllib.parse import urlparse
        p = urlparse(redirect_uri)
        wildcard = f"{p.scheme}://{p.netloc}/*"
        if wildcard not in uris:
            uris.append(wildcard)
            changed = True
        # Standard (authorization-code) flow must be enabled for a browser login.
        updates = {"redirectUris": uris}
        if client.get("standardFlowEnabled") is False:
            updates["standardFlowEnabled"] = True
            changed = True
        if not changed:
            logger.info("Redirect URI + wildcard already registered on '%s'", client_id)
            return True
        upd_url = f"{base}{prefix}/{realm}/clients/{client['id']}"
        put = requests.put(upd_url, headers=headers,
                           json={**client, **updates}, timeout=timeout)
        put.raise_for_status()
        logger.info("Updated client '%s': redirect URIs %s, standard flow on",
                    client_id, uris)
        return True
    raise RuntimeError(f"Keycloak realm '{realm}' not found at {base}")


def fetch_client_secret(keycloak_url: str, realm: str, admin_token: str,
                        client_id: str, timeout: int = 10) -> str:
    """
    Look up a Keycloak client's secret via the admin API.

    The app's client (e.g. Hello-World-app) is confidential, so the
    authorization-code exchange must send client_secret. Without it Keycloak
    answers 401 "Invalid client or Invalid client credentials" — which looks
    like an Auth0 problem but is purely the app<->Keycloak leg.
    """
    base = keycloak_url.rstrip("/")
    headers = {"authorization": f"Bearer {admin_token}"}
    for prefix in ("/admin/realms", "/auth/admin/realms"):
        try:
            r = requests.get(f"{base}{prefix}/{realm}/clients", headers=headers,
                             params={"clientId": client_id}, timeout=timeout)
        except requests.RequestException as exc:
            raise RuntimeError(f"Could not reach Keycloak at {base}: {exc}") from exc
        if r.status_code == 404 and prefix == "/admin/realms":
            continue
        r.raise_for_status()
        clients = r.json()
        if not clients:
            raise RuntimeError(
                f"Keycloak client '{client_id}' not found in realm '{realm}'")
        uuid = clients[0]["id"]
        sr = requests.get(f"{base}{prefix}/{realm}/clients/{uuid}/client-secret",
                          headers=headers, timeout=timeout)
        sr.raise_for_status()
        value = sr.json().get("value")
        if not value:
            raise RuntimeError(
                f"Client '{client_id}' has no secret — it may be a public "
                "client. Either enable client authentication on it, or run the "
                "flow without a secret.")
        return value
    raise RuntimeError(f"Realm '{realm}' not found at {base}")


def main() -> None:
    keycloak_url = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    realm        = os.environ.get("KEYCLOAK_REALM", "Premkey")
    client_id    = os.environ.get("KEYCLOAK_CLIENT_ID", "Hello-World-app")
    # The redirect target must (a) be registered on the Keycloak client's Valid
    # Redirect URIs and (b) actually receive the ?code=. The callback catcher
    # (LOGIN_FLOW_CATCH=1) listens on this path, so default to it rather than
    # /protected, which expects a Bearer token and cannot handle a redirect code.
    redirect_uri = os.environ.get("APP_REDIRECT_URI",
                                  "http://localhost:8000/callback")

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

    # Optional automated verification: if APP_REDIRECT_URI points at localhost
    # and LOGIN_FLOW_CATCH=1, catch the redirect and verify the token exchange.
    if os.environ.get("LOGIN_FLOW_CATCH") == "1":
        from urllib.parse import urlparse
        parsed = urlparse(redirect_uri)
        port = parsed.port or 8000
        secret = os.environ.get("KEYCLOAK_CLIENT_SECRET")
        secret_error = None
        if not secret:
            # Not in the environment — fetch it from Keycloak so the exchange
            # doesn't fail with "Invalid client or Invalid client credentials".
            try:
                from fix_redirect_uri import get_admin_token
                admin_tok = get_admin_token(
                    keycloak_url.rstrip("/"),
                    os.environ.get("KEYCLOAK_ADMIN_REALM", "master"),
                    os.environ.get("KEYCLOAK_ADMIN_USER", "admin"),
                    os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"))
                secret = fetch_client_secret(keycloak_url, realm, admin_tok,
                                             client_id)
                print(f"\n(fetched client secret for '{client_id}' from Keycloak)")
            except Exception as exc:  # noqa: BLE001
                secret_error = str(exc)
                print("\n" + "!" * 70)
                print("NO CLIENT SECRET — the token exchange will almost "
                      "certainly fail.")
                print(f"  Auto-fetch failed: {secret_error}")
                print("  Fix either way:")
                print("    a) supply admin creds so it can be fetched:")
                print("       KEYCLOAK_ADMIN_USER='..' KEYCLOAK_ADMIN_PASSWORD='..' \\")
                print("       LOGIN_FLOW_CATCH=1 python login_flow.py")
                print("    b) or copy it from Keycloak admin -> realm "
                      f"'{realm}' -> Clients -> {client_id}")
                print("       -> Credentials -> Client secret, then:")
                print("       KEYCLOAK_CLIENT_SECRET='...' LOGIN_FLOW_CATCH=1 "
                      "python login_flow.py")
                print("!" * 70)
        raise SystemExit(run_callback_catcher(
            keycloak_url, realm, client_id, redirect_uri, secret, port,
            secret_error=secret_error))
    print("=" * 70)


if __name__ == "__main__":
    main()
