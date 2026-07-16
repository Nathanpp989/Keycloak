#!/usr/bin/env python3
"""
diagnose_idp.py — diagnose Keycloak's "Unexpected error when authenticating
with identity provider", which happens AFTER Auth0 redirects back to Keycloak.

At that point Keycloak is doing three things, any of which can fail:
  1. exchanging the auth code at Auth0's /oauth/token  (needs a MATCHING secret)
  2. validating the returned token's signature via JWKS
  3. reading the user's claims (needs an email/username)

Run it:
    ./venv/bin/python diagnose_idp.py            # diagnose only
    ./venv/bin/python diagnose_idp.py --fix-secret   # also re-push .env's
                                                     # AUTH0_CLIENT_SECRET to
                                                     # Keycloak's IdP config

Keycloak MASKS the stored client secret on read, so no tool can compare it
directly. What this does instead: proves the secret in your .env works against
Auth0, then (with --fix-secret) pushes that same known-good secret into
Keycloak's IdP — which deterministically fixes a mismatch.
"""

from __future__ import annotations

import os
import sys

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from rotate_secret import update_keycloak_idp_secret, _candidate_idp_urls


def _cfg() -> dict:
    return {
        "kc_url":       os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/"),
        "realm":        os.environ.get("KEYCLOAK_REALM", "Premkey"),
        "alias":        os.environ.get("AUTH0_IDP_ALIAS", "auth0"),
        "domain":       os.environ.get("AUTH0_DOMAIN", ""),
        "client_id":    os.environ.get("AUTH0_CLIENT_ID", ""),
        "client_secret": os.environ.get("AUTH0_CLIENT_SECRET", ""),
        "admin_user":   os.environ.get("KEYCLOAK_ADMIN_USER", "admin"),
        "admin_pass":   os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
        "admin_realm":  os.environ.get("KEYCLOAK_ADMIN_REALM", "master"),
    }


def admin_token(url: str, admin_realm: str, user: str, pw: str) -> str:
    r = requests.post(
        f"{url}/realms/{admin_realm}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": user, "password": pw}, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"Admin login failed ({r.status_code}): {r.text[:150]}")
    return r.json()["access_token"]


def fetch_idp(kc_url: str, realm: str, token: str, alias: str) -> dict | None:
    for url in _candidate_idp_urls(kc_url, realm, alias):
        r = requests.get(url, headers={"authorization": f"Bearer {token}"}, timeout=10)
        if r.status_code == 404:
            continue
        r.raise_for_status()
        return r.json()
    return None


def check_auth0_secret(domain: str, client_id: str, client_secret: str) -> tuple[bool, str]:
    """Prove the .env secret is valid by asking Auth0 for a token."""
    try:
        r = requests.post(f"https://{domain}/oauth/token", timeout=10, json={
            "grant_type": "client_credentials", "client_id": client_id,
            "client_secret": client_secret, "audience": f"https://{domain}/api/v2/",
        })
    except requests.RequestException as exc:
        return False, f"cannot reach Auth0: {exc}"
    if r.status_code == 200:
        return True, "valid"
    return False, f"{r.status_code}: {r.text[:160]}"


def check_jwks(domain: str) -> tuple[bool, str]:
    try:
        r = requests.get(f"https://{domain}/.well-known/jwks.json", timeout=10)
        if r.ok and r.json().get("keys"):
            return True, f"{len(r.json()['keys'])} key(s)"
        return False, f"status {r.status_code}"
    except requests.RequestException as exc:
        return False, str(exc)


def check_issuer(domain: str) -> tuple[bool, str]:
    """Auth0's real issuer, from its OIDC discovery document."""
    try:
        r = requests.get(f"https://{domain}/.well-known/openid-configuration",
                         timeout=10)
        if r.ok:
            return True, r.json().get("issuer", "?")
        return False, f"status {r.status_code}"
    except requests.RequestException as exc:
        return False, str(exc)


def main() -> int:
    c = _cfg()
    fix = "--fix-secret" in sys.argv

    print("=" * 72)
    print("KEYCLOAK <-> AUTH0 IDENTITY-PROVIDER DIAGNOSTIC")
    print("=" * 72)
    if not c["domain"] or not c["client_id"] or not c["client_secret"]:
        print("✗ AUTH0_DOMAIN / AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET missing "
              "from your environment or .env.")
        return 1
    print(f"Keycloak : {c['kc_url']}  realm={c['realm']}  idp alias={c['alias']}")
    print(f"Auth0    : {c['domain']}  client_id={c['client_id'][:8]}...")
    print("-" * 72)

    # 1. Is the .env secret actually valid at Auth0?
    ok, detail = check_auth0_secret(c["domain"], c["client_id"], c["client_secret"])
    print(f"[1] .env AUTH0_CLIENT_SECRET works at Auth0 : {'YES' if ok else 'NO'} ({detail})")
    if not ok:
        print("    → Your .env secret is WRONG/STALE. Rotate again or copy the")
        print("      current secret from the Auth0 dashboard into .env.")
        return 1

    # 2. Auth0's JWKS + issuer (used by Keycloak to validate the token).
    jok, jdetail = check_jwks(c["domain"])
    print(f"[2] Auth0 JWKS reachable                    : {'YES' if jok else 'NO'} ({jdetail})")
    iok, issuer = check_issuer(c["domain"])
    print(f"[3] Auth0 real issuer                       : {issuer}")

    # 3. Keycloak's IdP config.
    try:
        token = admin_token(c["kc_url"], c["admin_realm"], c["admin_user"], c["admin_pass"])
    except RuntimeError as exc:
        print(f"\n✗ {exc}")
        return 1
    idp = fetch_idp(c["kc_url"], c["realm"], token, c["alias"])
    if idp is None:
        print(f"\n✗ No IdP with alias '{c['alias']}' in realm '{c['realm']}'.")
        print("  Run auth0_connect.py to register it.")
        return 1
    conf = idp.get("config", {})
    print(f"[4] Keycloak IdP '{c['alias']}' found            : YES (enabled={idp.get('enabled')})")
    print(f"    clientId          : {conf.get('clientId')}")
    print(f"    clientSecret      : {conf.get('clientSecret')}  (Keycloak masks this)")
    print(f"    tokenUrl          : {conf.get('tokenUrl')}")
    print(f"    jwksUrl           : {conf.get('jwksUrl')}")
    print(f"    issuer            : {conf.get('issuer')}")
    print(f"    validateSignature : {conf.get('validateSignature')}")
    print(f"    useJwksUrl        : {conf.get('useJwksUrl')}")

    problems = []
    if conf.get("clientId") != c["client_id"]:
        problems.append(f"IdP clientId ({conf.get('clientId')}) != AUTH0_CLIENT_ID "
                        f"({c['client_id']}) — Keycloak is using a different Auth0 app.")
    if iok and conf.get("issuer") and conf["issuer"] != issuer:
        problems.append(f"IdP issuer ({conf['issuer']}) != Auth0's real issuer "
                        f"({issuer}) — signature/claim validation will fail.")
    if conf.get("tokenUrl") != f"https://{c['domain']}/oauth/token":
        problems.append(f"IdP tokenUrl looks wrong: {conf.get('tokenUrl')}")

    print("-" * 72)
    if problems:
        print("PROBLEMS FOUND:")
        for p in problems:
            print("  ✗ " + p)
    else:
        print("Config looks consistent. The most likely remaining cause is a")
        print("CLIENT SECRET MISMATCH between Keycloak's IdP and Auth0 (Keycloak")
        print("masks it, so it can't be compared — only re-pushed).")

    print("\nREQUIRED IN AUTH0 → Applications → your app → Settings:")
    print("  Allowed Callback URLs must include:")
    print(f"    {c['kc_url']}/realms/{c['realm']}/broker/{c['alias']}/endpoint")

    if fix:
        print("\n→ Re-pushing .env's (verified-good) secret to Keycloak's IdP ...")
        try:
            used = update_keycloak_idp_secret(c["kc_url"], c["realm"], token,
                                              c["alias"], c["client_secret"])
            print(f"✓ Secret re-pushed via {used}")
            print("  Retry the browser login now.")
        except Exception as exc:  # noqa: BLE001
            print(f"✗ Re-push failed: {exc}")
            return 1
    else:
        print("\nRe-run with --fix-secret to push .env's verified secret into")
        print("Keycloak's IdP (fixes a mismatch deterministically).")

    print("\nALSO: the real exception is in the KEYCLOAK SERVER LOG at the moment")
    print("of failure — look for 'org.keycloak.broker.oidc'. Paste that line.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
