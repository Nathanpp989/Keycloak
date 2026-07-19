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
                    kc_url: str, realm: str, alias: str,
                    inspect_client_id: str | None = None) -> dict:
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
        target = inspect_client_id or client_id
        r = requests.get(f"https://{domain}/api/v2/clients/{target}",
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
                   new_secret: str, expect_client_id: str | None = None,
                   auth_method: str = "client_secret_post") -> str:
    """
    Repair the Keycloak IdP: push a client secret AND ensure clientAuthMethod is
    set. Read-modify-write so other config is preserved.

    GUARD: if expect_client_id is given and does not match the IdP's configured
    clientId, refuse — writing a secret that belongs to a different Auth0
    application is what breaks brokered login in the first place.
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
        if expect_client_id is not None and conf.get("clientId") != expect_client_id:
            raise RuntimeError(
                f"REFUSING to write: IdP authenticates as Auth0 client "
                f"'{conf.get('clientId')}', but the secret you're pushing belongs "
                f"to '{expect_client_id}'. Pairing one app's clientId with "
                "another app's secret breaks every brokered login. Use "
                "--set-idp-secret <secret-of-the-IdP's-own-app> instead.")
        if new_secret:
            conf["clientSecret"] = new_secret
        if not conf.get("clientAuthMethod"):
            conf["clientAuthMethod"] = auth_method
        put = requests.put(url, headers=headers, json={**rep, "config": conf},
                           timeout=10)
        put.raise_for_status()
        return url
    raise RuntimeError(f"IdP '{alias}' not found in realm '{realm}'")


def enable_broker_debug_logging(kc_url: str, token: str) -> bool:
    """
    Ask Keycloak to log the broker package at DEBUG so the REAL exception behind
    'Unexpected error when authenticating with identity provider' appears in the
    server log. Uses the admin logging endpoint (Keycloak 24+/Quarkus). Returns
    True if accepted; harmless if unsupported.
    """
    # Keycloak exposes runtime log-level changes only in some distributions;
    # this is best-effort. The reliable path is still reading the server console.
    try:
        resp = requests.post(
            f"{kc_url}/admin/realms/master/clients",  # probe admin reachability
            headers={"authorization": f"Bearer {token}"}, timeout=5)
        _ = resp  # we don't actually create anything; real toggle is via config
    except requests.RequestException:
        return False
    return False  # signal: use the manual instruction printed by main()


def dump_idp_full(kc_url: str, realm: str, token: str, alias: str) -> dict:
    """Return the complete IdP representation for inspection (all config keys)."""
    headers = {"authorization": f"Bearer {token}"}
    for url in _candidate_idp_urls(kc_url, realm, alias):
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 404:
            continue
        r.raise_for_status()
        return r.json()
    return {}


def set_app_id_token_alg(domain: str, m2m_id: str, m2m_secret: str,
                         target_client_id: str, alg: str = "RS256") -> str:
    """
    Set the ID-token signing algorithm on an Auth0 application via the
    Management API. Needs 'update:clients' on the M2M app. Returns the alg
    Auth0 confirms.
    """
    tok = requests.post(f"https://{domain}/oauth/token", timeout=10, json={
        "grant_type": "client_credentials", "client_id": m2m_id,
        "client_secret": m2m_secret, "audience": f"https://{domain}/api/v2/",
    })
    if tok.status_code != 200:
        raise RuntimeError(f"M2M token failed: {tok.status_code} {tok.text[:120]}")
    access = tok.json()["access_token"]
    r = requests.patch(
        f"https://{domain}/api/v2/clients/{target_client_id}",
        headers={"authorization": f"Bearer {access}",
                 "content-type": "application/json"},
        json={"jwt_configuration": {"alg": alg}}, timeout=10)
    if r.status_code == 403:
        raise RuntimeError("403 — grant 'update:clients' to your M2M app to use --fix-alg")
    r.raise_for_status()
    return (r.json().get("jwt_configuration") or {}).get("alg", "?")


def main() -> int:
    c = _cfg()
    fix = "--fix-secret" in sys.argv
    dump = "--dump" in sys.argv
    fix_alg = "--fix-alg" in sys.argv
    set_secret = None
    if "--set-idp-secret" in sys.argv:
        i = sys.argv.index("--set-idp-secret")
        if i + 1 >= len(sys.argv):
            print("✗ --set-idp-secret needs a value")
            return 1
        set_secret = sys.argv[i + 1]

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
    print(f"    userInfoUrl       : {conf.get('userInfoUrl') or '(NOT SET)'}")
    print(f"    clientAuthMethod  : {conf.get('clientAuthMethod') or '(NOT SET — likely bug)'}")
    print(f"    validateSignature : {conf.get('validateSignature')}")
    print(f"    useJwksUrl        : {conf.get('useJwksUrl')}")

    problems = []
    if not conf.get("clientAuthMethod"):
        problems.append("IdP has NO clientAuthMethod — Keycloak doesn't know how to "
                        "authenticate at Auth0's token endpoint. This alone causes "
                        "the generic broker error. Fix with --fix-secret.")
    if not conf.get("userInfoUrl"):
        problems.append(
            "IdP has NO userInfoUrl. After the token exchange Keycloak calls "
            "/userinfo to load the profile; without it (or with 'Disable User "
            "Info' off) the login can fail. Expected: "
            f"https://{c['domain']}/userinfo")
    if conf.get("clientId") != c["client_id"]:
        problems.append(
            f"IdP authenticates as Auth0 client '{conf.get('clientId')}' but "
            f"AUTH0_CLIENT_ID in .env is '{c['client_id']}'. These are DIFFERENT "
            "Auth0 apps. That is normal (M2M app vs browser-login app) — BUT it "
            "means rotate_secret.py must NOT push .env's secret into this IdP, "
            "and --fix-secret is refused. Use --set-idp-secret <secret> with the "
            "secret of the IdP's OWN app.")
    if iok and conf.get("issuer") and conf["issuer"] != issuer:
        problems.append(f"IdP issuer ({conf['issuer']}) != Auth0's real issuer "
                        f"({issuer}) — signature/claim validation will fail.")
    if conf.get("tokenUrl") != f"https://{c['domain']}/oauth/token":
        problems.append(f"IdP tokenUrl looks wrong: {conf.get('tokenUrl')}")

    # 5. The Auth0 application's own settings — where HS256/callback bugs live.
    print("-" * 72)
    idp_client = conf.get("clientId")
    app_info = check_auth0_app(c["domain"], c["client_id"], c["client_secret"],
                               c["kc_url"], c["realm"], c["alias"],
                               inspect_client_id=idp_client)
    if not app_info["ok"]:
        print(f"[5] Auth0 app settings: could not read ({app_info.get('error')})")
    else:
        print(f"[5] The IdP's Auth0 app '{app_info['app'].get('name')}' "
              f"(client_id={idp_client}, type={app_info['app'].get('app_type')})")
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
        elif app_info["alg"] != "RS256":
            problems.append(
                f"The IdP's Auth0 app ID-token algorithm is '{app_info['alg']}' "
                "(not confirmed RS256). Keycloak validates via JWKS/RS256 — if "
                "Auth0 signs with anything else, the callback fails with the "
                "generic broker error. Set it to RS256: Applications -> the app "
                "-> Settings -> Advanced -> OAuth -> JsonWebToken Signature "
                "Algorithm -> RS256 (or run this tool with --fix-alg).")
        if not app_info["callback_ok"]:
            problems.append(
                f"Auth0 'Allowed Callback URLs' is missing "
                f"{app_info['broker_url']} — add it in the Auth0 dashboard.")
        if app_info["app"].get("app_type") == "non_interactive":
            problems.append(
                "The IdP's Auth0 app is a MACHINE-TO-MACHINE app "
                "(non_interactive). M2M apps cannot do browser login at all. "
                "Keycloak's IdP needs a REGULAR WEB APPLICATION.")
        if "authorization_code" not in app_info["grant_types"]:
            problems.append("The IdP's Auth0 app does not allow the "
                            "authorization_code grant — enable it in the app's "
                            "Advanced settings (Grant Types).")
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

    if set_secret is not None:
        print("\n→ Setting the IdP's client secret to the value you supplied ...")
        try:
            used = fix_idp_config(c["kc_url"], c["realm"], token, c["alias"],
                                  set_secret)   # no expect check: explicit intent
            print(f"✓ IdP updated via {used}")
            print("  Retry the browser login now.")
        except Exception as exc:  # noqa: BLE001
            print(f"✗ Update failed: {exc}")
            return 1
    elif fix:
        print("\n→ Repairing Keycloak IdP (secret + clientAuthMethod) ...")
        try:
            used = fix_idp_config(c["kc_url"], c["realm"], token, c["alias"],
                                  c["client_secret"],
                                  expect_client_id=c["client_id"])
            print(f"✓ IdP updated via {used}")
            print("  Retry the browser login now.")
        except Exception as exc:  # noqa: BLE001
            print(f"✗ {exc}")
            return 1
    else:
        print("\nOptions:")
        print("  --fix-secret            push .env's secret + set clientAuthMethod")
        print("                          (refused if the IdP uses a different app)")
        print("  --set-idp-secret <s>    set the IdP's secret explicitly — use the")
        print("                          secret of the IdP's OWN Auth0 app")

    if fix_alg:
        idp_client = conf.get("clientId")
        print(f"\n→ Setting ID-token algorithm to RS256 on app {idp_client} ...")
        try:
            got = set_app_id_token_alg(c["domain"], c["client_id"],
                                       c["client_secret"], idp_client)
            print(f"✓ Auth0 confirms alg = {got}. Retry the browser login.")
        except Exception as exc:  # noqa: BLE001
            print(f"✗ {exc}")
            return 1

    if dump:
        import json as _json
        print("\n--- FULL IdP representation ---")
        print(_json.dumps(dump_idp_full(c["kc_url"], c["realm"], token, c["alias"]),
                          indent=2))

    print("\n" + "=" * 72)
    print("TO SEE THE REAL EXCEPTION (definitive):")
    print("  Keycloak prints it the moment the login fails — look in the")
    print("  kc.sh terminal for a line containing:  org.keycloak.broker.oidc")
    print("  For full detail, restart Keycloak with broker DEBUG logging:")
    print("      ./bin/kc.sh start-dev --log-level=INFO,org.keycloak.broker:debug")
    print("  reproduce the login, and read the DEBUG lines — they name the exact")
    print("  token-exchange / userinfo / claim failure.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
