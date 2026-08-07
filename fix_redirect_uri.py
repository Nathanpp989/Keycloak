#!/usr/bin/env python3
"""
fix_redirect_uri.py — diagnose AND fix Keycloak's "Invalid parameter: redirect_uri".

Run it directly; it needs no arguments:

    ./venv/bin/python fix_redirect_uri.py

It reads config from the environment / .env (with sensible defaults), then:
  1. lists every realm it can see, so a wrong-realm mistake is obvious
  2. lists the clients in the target realm (so a wrong clientId is obvious)
  3. prints exactly what redirect URIs the client has registered
  4. adds the needed redirect URI + origin wildcard, enables Standard Flow
  5. re-reads the client and confirms the fix landed
  6. prints the login URL to try

Every step prints what it found, so if it can't fix the problem you still learn
the cause. Nothing here is destructive: existing redirect URIs are preserved.

Environment (all optional, defaults shown):
    KEYCLOAK_URL            http://localhost:8080
    KEYCLOAK_REALM          Premkey
    KEYCLOAK_CLIENT_ID      Hello-World-app
    APP_REDIRECT_URI        http://localhost:8000/callback
    KEYCLOAK_ADMIN_USER     admin
    KEYCLOAK_ADMIN_PASSWORD admin
    KEYCLOAK_ADMIN_REALM    master
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlencode, urlparse

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _cfg() -> dict:
    return {
        "url":          os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/"),
        "realm":        os.environ.get("KEYCLOAK_REALM", "Premkey"),
        "client_id":    os.environ.get("KEYCLOAK_CLIENT_ID", "Hello-World-app"),
        "redirect_uri": os.environ.get("APP_REDIRECT_URI", "http://localhost:8000/callback"),
        "admin_user":   os.environ.get("KEYCLOAK_ADMIN_USER", "admin"),
        "admin_pass":   os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
        "admin_realm":  os.environ.get("KEYCLOAK_ADMIN_REALM", "master"),
    }


def get_admin_token(url: str, admin_realm: str, user: str, password: str,
                    timeout: int = 10) -> str:
    """Password-grant an admin token from the admin realm (usually 'master')."""
    token_url = f"{url}/realms/{admin_realm}/protocol/openid-connect/token"
    try:
        resp = requests.post(token_url, timeout=timeout, data={
            "grant_type": "password", "client_id": "admin-cli",
            "username": user, "password": password,
        })
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Cannot reach Keycloak at {url} ({exc}). Is it running?") from exc
    if resp.status_code != 200:
        raise RuntimeError(
            f"Admin login failed ({resp.status_code}): {resp.text[:200]}. "
            f"Check KEYCLOAK_ADMIN_USER / KEYCLOAK_ADMIN_PASSWORD "
            f"(tried user '{user}' in realm '{admin_realm}').")
    return resp.json()["access_token"]


def list_realms(url: str, token: str, timeout: int = 10) -> list[str]:
    resp = requests.get(f"{url}/admin/realms",
                        headers={"authorization": f"Bearer {token}"}, timeout=timeout)
    if not resp.ok:
        return []
    return [r.get("realm", "?") for r in resp.json()]


def list_clients(url: str, realm: str, token: str, timeout: int = 10) -> list[dict]:
    resp = requests.get(f"{url}/admin/realms/{realm}/clients",
                        headers={"authorization": f"Bearer {token}"}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def fix_client(url: str, realm: str, token: str, client: dict,
               redirect_uri: str, timeout: int = 10) -> list[str]:
    """Add the redirect URI + origin wildcard and enable Standard Flow."""
    parsed = urlparse(redirect_uri)
    wildcard = f"{parsed.scheme}://{parsed.netloc}/*"
    uris = list(client.get("redirectUris") or [])
    for wanted in (redirect_uri, wildcard):
        if wanted not in uris:
            uris.append(wanted)
    payload = {**client, "redirectUris": uris, "standardFlowEnabled": True}
    origins = list(client.get("webOrigins") or [])
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in origins:
        origins.append(origin)
    payload["webOrigins"] = origins
    resp = requests.put(f"{url}/admin/realms/{realm}/clients/{client['id']}",
                        headers={"authorization": f"Bearer {token}",
                                 "content-type": "application/json"},
                        json=payload, timeout=timeout)
    resp.raise_for_status()
    return uris


def login_url(url: str, realm: str, client_id: str, redirect_uri: str) -> str:
    params = {"client_id": client_id, "response_type": "code",
              "scope": "openid profile email", "redirect_uri": redirect_uri,
              "kc_idp_hint": "auth0"}
    return f"{url}/realms/{realm}/protocol/openid-connect/auth?{urlencode(params)}"


def main() -> int:
    c = _cfg()
    print("=" * 72)
    print("KEYCLOAK redirect_uri DIAGNOSTIC + FIX")
    print("=" * 72)
    print(f"Keycloak     : {c['url']}")
    print(f"Realm        : {c['realm']}")
    print(f"Client ID    : {c['client_id']}")
    print(f"Redirect URI : {c['redirect_uri']}")
    print("-" * 72)

    try:
        token = get_admin_token(c["url"], c["admin_realm"], c["admin_user"],
                                c["admin_pass"])
    except RuntimeError as exc:
        print(f"\n✗ {exc}")
        return 1
    print("✓ Admin token acquired")

    realms = list_realms(c["url"], token)
    if realms:
        print(f"  Realms visible: {', '.join(realms)}")
        if c["realm"] not in realms:
            print(f"\n✗ Realm '{c['realm']}' DOES NOT EXIST.")
            print(f"  This is the problem. Pick one of: {', '.join(realms)}")
            print("  Set KEYCLOAK_REALM to the right one, or create the realm.")
            return 1

    try:
        clients = list_clients(c["url"], c["realm"], token)
    except requests.HTTPError as exc:
        print(f"\n✗ Could not list clients in realm '{c['realm']}': {exc}")
        return 1

    names = [cl.get("clientId", "?") for cl in clients]
    print(f"  Clients in '{c['realm']}': {', '.join(names)}")

    match = next((cl for cl in clients if cl.get("clientId") == c["client_id"]), None)
    if match is None:
        print(f"\n✗ Client '{c['client_id']}' DOES NOT EXIST in realm '{c['realm']}'.")
        print("  THIS is why the login URL fails — Keycloak can't match a")
        print("  redirect_uri for a client it doesn't have.")
        print("  Either set KEYCLOAK_CLIENT_ID to one of the above, or start the")
        print("  app once (its startup now creates the client automatically).")
        return 1

    print(f"\n✓ Found client '{c['client_id']}' (uuid={match['id']})")
    current = match.get("redirectUris") or []
    print(f"  Currently registered redirect URIs: {current or '(NONE — this is the bug)'}")
    print(f"  Standard flow enabled: {match.get('standardFlowEnabled')}")

    print("\n→ Applying fix ...")
    try:
        fix_client(c["url"], c["realm"], token, match, c["redirect_uri"])
    except requests.HTTPError as exc:
        print(f"✗ Update failed: {exc}")
        return 1

    verify = next((cl for cl in list_clients(c["url"], c["realm"], token)
                   if cl.get("clientId") == c["client_id"]), None)
    now = (verify or {}).get("redirectUris") or []
    ok = c["redirect_uri"] in now or any(
        u.endswith("*") and c["redirect_uri"].startswith(u[:-1]) for u in now)
    print(f"  Redirect URIs now: {now}")
    print(f"  Standard flow now: {(verify or {}).get('standardFlowEnabled')}")

    if not ok:
        print("\n✗ The redirect URI still isn't registered after the update.")
        print("  Fix it by hand: Admin console → realm "
              f"'{c['realm']}' → Clients → {c['client_id']} → Valid redirect URIs.")
        return 1

    print("\n" + "=" * 72)
    print("✓ FIXED — open this URL in your browser:\n")
    print("   " + login_url(c["url"], c["realm"], c["client_id"], c["redirect_uri"]))
    print("\n(Run with LOGIN_FLOW_CATCH=1 python login_flow.py to auto-verify the")
    print(" full token round trip.)")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
