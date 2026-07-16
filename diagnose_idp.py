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

from rotate_secret import _candidate_idp_urls


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


def check_auth0_app(domain: str, client_id: str, client_secret: str,
                    kc_url: str, realm: str, alias: str) -> dict:
    """
    Read the Auth0 APPLICATION's own settings via the Management API. This is
    where the two classic causes of the generic broker error live:
      - jwt_configuration.alg == HS256  (Keycloak validates via JWKS/RS256 -> fails)
      - callbacks missing the Keycloak broker endpoint
    Needs the 'read:clients' scope on your M2M app.
    """
    out: dict = {"ok": False}
    try:
        tok = requests.post(f"https://{domain}/oauth/token", timeout=10, json={
            "grant_type": "client_credentials", "client_id": client_id,
            "client_secret": client_secret, "audience": f"https://{domain}/api/v2/",
        })
        if tok.status_code != 200:
            out["error"] = f"token: {tok.status_code}"
            return out
        access = tok.json()["access_token"]
        r = requests.get(f"https://{domain}/api/v2/clients/{client_id}",
                         headers={"authorization": f"Bearer {access}"},
                         params={"fields": "name,app_type,callbacks,grant_types,"
                                           "jwt_configuration,token_endpoint_auth_method"},
                         timeout=10)
    except requests.RequestException as exc:
        out["error"] = str(exc)
        return out
    if r.status_code == 403:
        out["error"] = ("403 — grant the 'read:clients' scope to your M2M app "
                        "to enable this check")
        return out
    if not r.ok:
        out["error"] = f"{r.status_code}: {r.text[:120]}"
        return out
    app = r.json()
    out["ok"] = True
    out["app"] = app
    alg = (app.get("jwt_configuration") or {}).get("alg")
    out["alg"] = alg
    out["callbacks"] = app.get("callbacks") or []
    out["grant_types"] = app.get("grant_types") or []
    out["auth_method"] = app.get("token_endpoint_auth_method")
    broker = f"{kc_url}/realms/{realm}/broker/{alias}/endpoint"
    out["broker_url"] = broker
    out["callback_ok"] = broker in out["callbacks"]
    return out


def fix_idp_config(kc_url: str, realm: str, token: str, alias: str,
                   new_secret: str, auth_method: str = "client_secret_post") -> str:
    """
    Repair the Keycloak IdP: push the known-good client secret AND ensure
    clientAuthMethod is set (a missing clientAuthMethod breaks the code->token
    exchange). Read-modify-write so other config is preserved.
    """
    headers = {"authorization": f"Bearer {token}",
               "content-type": "application/json"}
    for url in _candidate_idp_urls(kc_url, realm, alias):
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 404:
            continue
        r.raise_for_status()
        rep = r.json()
        conf = dict(rep.get("config") or {})
        conf["clientSecret"] = new_secret
        if not conf.get("clientAuthMethod"):
            conf["clientAuthMethod"] = auth_method
        put = requests.put(url, headers=headers, json={**rep, "config": conf},
                           timeout=10)
        put.raise_for_status()
        return url
    raise RuntimeError(f"IdP '{alias}' not found in realm '{realm}'")


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
    print(f"    clientAuthMethod  : {conf.get('clientAuthMethod') or '(NOT SET — likely bug)'}")
    print(f"    validateSignature : {conf.get('validateSignature')}")
    print(f"    useJwksUrl        : {conf.get('useJwksUrl')}")

    problems = []
    if not conf.get("clientAuthMethod"):
        problems.append("IdP has NO clientAuthMethod — Keycloak doesn't know how to "
                        "authenticate at Auth0's token endpoint. This alone causes "
                        "the generic broker error. Fix with --fix-secret.")
    if conf.get("clientId") != c["client_id"]:
        problems.append(f"IdP clientId ({conf.get('clientId')}) != AUTH0_CLIENT_ID "
                        f"({c['client_id']}) — Keycloak is using a different Auth0 app.")
    if iok and conf.get("issuer") and conf["issuer"] != issuer:
        problems.append(f"IdP issuer ({conf['issuer']}) != Auth0's real issuer "
                        f"({issuer}) — signature/claim validation will fail.")
    if conf.get("tokenUrl") != f"https://{c['domain']}/oauth/token":
        problems.append(f"IdP tokenUrl looks wrong: {conf.get('tokenUrl')}")

    # 5. The Auth0 application's own settings — where HS256/callback bugs live.
    print("-" * 72)
    app_info = check_auth0_app(c["domain"], c["client_id"], c["client_secret"],
                               c["kc_url"], c["realm"], c["alias"])
    if not app_info["ok"]:
        print(f"[5] Auth0 app settings: could not read ({app_info.get('error')})")
    else:
        print(f"[5] Auth0 app '{app_info['app'].get('name')}' "
              f"(type={app_info['app'].get('app_type')})")
        print(f"    ID token algorithm      : {app_info['alg']}")
        print(f"    token_endpoint_auth     : {app_info['auth_method']}")
        print(f"    grant_types             : {app_info['grant_types']}")
        print(f"    callbacks               : {app_info['callbacks']}")
        if app_info["alg"] == "HS256":
            problems.append(
                "Auth0 signs ID tokens with HS256, but Keycloak validates via "
                "JWKS (RS256). THIS BREAKS THE LOGIN. Fix in Auth0: Applications "
                "-> your app -> Settings -> Advanced -> OAuth -> "
                "'JsonWebToken Signature Algorithm' -> RS256.")
        if not app_info["callback_ok"]:
            problems.append(
                f"Auth0 'Allowed Callback URLs' is missing "
                f"{app_info['broker_url']} — add it in the Auth0 dashboard.")
        if "authorization_code" not in app_info["grant_types"]:
            problems.append("Auth0 app does not allow the authorization_code "
                            "grant — enable it in the app's Advanced settings.")
        if (app_info["auth_method"] and conf.get("clientAuthMethod")
                and app_info["auth_method"] != conf.get("clientAuthMethod")):
            problems.append(
                f"Auth0 expects client auth '{app_info['auth_method']}' but "
                f"Keycloak IdP uses '{conf.get('clientAuthMethod')}' — mismatch.")

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
        print("\n→ Repairing Keycloak IdP (secret + clientAuthMethod) ...")
        try:
            used = fix_idp_config(c["kc_url"], c["realm"], token, c["alias"],
                                  c["client_secret"])
            print(f"✓ IdP updated via {used}")
            print("  Retry the browser login now.")
        except Exception as exc:  # noqa: BLE001
            print(f"✗ Repair failed: {exc}")
            return 1
    else:
        print("\nRe-run with --fix-secret to push .env's verified secret AND set")
        print("clientAuthMethod on Keycloak's IdP.")

    print("\nALSO: the real exception is in the KEYCLOAK SERVER LOG at the moment")
    print("of failure — look for 'org.keycloak.broker.oidc'. Paste that line.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
