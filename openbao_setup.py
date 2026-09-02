#!/usr/bin/env python3
# openbao_setup.py
# The executable mechanism for running OpenBao together with your LIVE Keycloak
# and Auth0. Unlike openbao_smoke.py (self-contained, stubbed IdPs), this talks
# to your real IdPs and configures the real integrations, checking every
# precondition first and diagnosing failures the way diagnose_idp.py does.
#
# It reads config from the environment / .env (same vars as the rest of the
# project), so a filled-in .env is all you need.
#
# Subcommands:
#   check      - verify preconditions only (no writes): OpenBao up, Keycloak &
#                Auth0 reachable FROM OpenBao, credentials valid.
#   keycloak   - configure Keycloak -> OpenBao (OIDC auth), then print how to log in.
#   auth0      - configure Auth0 -> OpenBao (JWT auth), then verify with a real
#                Auth0 client-credentials token if M2M creds are present.
#   all        - check, then configure both, then print the login checklist.
#   checklist  - print the manual step-by-step (no writes).
#
# Usage:
#   python openbao_setup.py check
#   python openbao_setup.py all
#   OPENBAO_TOKEN=root python openbao_setup.py auth0
#
# Nothing here is destructive beyond creating/updating OpenBao auth mounts and
# roles (all idempotent). It never writes to Keycloak or Auth0.

from __future__ import annotations

import os
import sys

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import openbao_connect as ob


# ── small helpers ───────────────────────────────────────────────────────────
def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _ok(msg: str):
    print(f"  \u2713 {msg}")


def _bad(msg: str):
    print(f"  \u2717 {msg}")


def _reachable_from_here(url: str, timeout: int = 6) -> tuple[bool, str]:
    """Can WE reach this discovery URL? A proxy for 'can OpenBao reach it' when
    OpenBao and this script run on the same host/network.

    We don't just check the status — we confirm the response is a valid OIDC
    discovery document with a jwks_uri, because OpenBao parses it and will
    reject a 200 that isn't real discovery JSON. A bare 200 that isn't discovery
    would otherwise give a false green here while OpenBao's write fails."""
    try:
        r = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        return False, f"{url} unreachable: {exc}"
    if r.status_code >= 400:
        return False, f"{url} -> {r.status_code}"
    try:
        doc = r.json()
    except ValueError:
        return False, (f"{url} -> {r.status_code} but body is not JSON "
                       "(not a valid OIDC discovery document)")
    if "jwks_uri" not in doc or "issuer" not in doc:
        return False, (f"{url} -> {r.status_code} but missing issuer/jwks_uri "
                       "(OpenBao will reject this as invalid discovery)")
    return True, f"{url} -> {r.status_code}, valid discovery (issuer present)"


# ── configuration gathered from env ─────────────────────────────────────────
class Cfg:
    def __init__(self):
        self.bao_addr = _env("OPENBAO_ADDR", "http://127.0.0.1:8200").rstrip("/")
        self.bao_token = _env("OPENBAO_TOKEN")
        # Keycloak
        self.kc_url = _env("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
        self.kc_realm = _env("KEYCLOAK_REALM", "Premkey")
        self.kc_ob_client = _env("OPENBAO_KC_CLIENT_ID", "openbao")
        self.kc_ob_secret = _env("OPENBAO_KC_CLIENT_SECRET")
        # Auth0
        self.a0_domain = _env("AUTH0_DOMAIN").strip().rstrip("/")
        self.a0_audience = _env("AUTH0_AUDIENCE")
        self.a0_m2m_id = _env("AUTH0_CLIENT_ID")
        self.a0_m2m_secret = _env("AUTH0_CLIENT_SECRET")

    @property
    def kc_discovery(self) -> str:
        return f"{self.kc_url}/realms/{self.kc_realm}/.well-known/openid-configuration"

    @property
    def a0_discovery(self) -> str:
        return f"https://{self.a0_domain}/.well-known/openid-configuration"


# ── check: preconditions only, no writes ────────────────────────────────────
def cmd_check(c: Cfg) -> int:
    print("Preconditions (no changes will be made):")
    problems = 0

    # OpenBao reachable + token valid
    try:
        requests.get(f"{c.bao_addr}/v1/sys/health", timeout=5)
        _ok(f"OpenBao reachable at {c.bao_addr}")
    except requests.RequestException as exc:
        _bad(f"OpenBao unreachable at {c.bao_addr}: {exc}")
        _bad("  start it: bao server -dev -dev-root-token-id=root")
        return 1  # nothing else matters
    if not c.bao_token:
        _bad("OPENBAO_TOKEN not set (use the dev root token, e.g. root)")
        problems += 1
    else:
        tr = requests.get(f"{c.bao_addr}/v1/auth/token/lookup-self",
                          headers={"X-Vault-Token": c.bao_token}, timeout=5)
        if tr.status_code == 200:
            _ok("OpenBao token valid")
        else:
            _bad(f"OpenBao token rejected ({tr.status_code})")
            problems += 1

    # Keycloak discovery reachable (OpenBao will need this for capability 1)
    ok, detail = _reachable_from_here(c.kc_discovery)
    (_ok if ok else _bad)(f"Keycloak discovery: {detail}")
    if not ok:
        _bad("  OpenBao configures OIDC by FETCHING this URL — it must be "
             "reachable from the OpenBao host, not just yours.")
        problems += 1

    # Auth0 discovery reachable (capability 2)
    if c.a0_domain:
        ok, detail = _reachable_from_here(c.a0_discovery)
        (_ok if ok else _bad)(f"Auth0 discovery: {detail}")
        if not ok:
            problems += 1
    else:
        print("  - AUTH0_DOMAIN not set; skipping Auth0 checks")

    # Auth0 M2M creds (optional, needed only to verify a real token)
    if c.a0_domain and c.a0_m2m_id and c.a0_m2m_secret:
        try:
            from diagnose_idp import check_auth0_secret
            ok, detail = check_auth0_secret(c.a0_domain, c.a0_m2m_id,
                                            c.a0_m2m_secret)
            (_ok if ok else _bad)(f"Auth0 M2M credentials: {detail}")
            if not ok:
                problems += 1
        except Exception as exc:  # noqa: BLE001
            _bad(f"Auth0 M2M credential check errored: {exc}")
            problems += 1
    else:
        print("  - Auth0 M2M creds absent; token verification will be skipped")

    print()
    if problems:
        print(f"{problems} precondition(s) need attention before setup.")
        return 1
    print("All preconditions satisfied.")
    return 0


# ── keycloak: configure Keycloak -> OpenBao ─────────────────────────────────
def cmd_keycloak(c: Cfg) -> int:
    if not c.bao_token:
        _bad("OPENBAO_TOKEN required")
        return 1
    if not c.kc_ob_secret:
        _bad("OPENBAO_KC_CLIENT_SECRET not set — this is the secret of the "
             "Keycloak client OpenBao logs in AS (Clients -> "
             f"{c.kc_ob_client} -> Credentials).")
        return 1
    ok, detail = _reachable_from_here(c.kc_discovery)
    if not ok:
        _bad(f"Keycloak discovery not reachable: {detail}")
        _bad("Configure step will fail because OpenBao fetches it. Fix first.")
        return 1
    print(f"Configuring Keycloak->OpenBao (mount '{ob.OIDC_MOUNT_KEYCLOAK}')...")
    try:
        ob.configure_keycloak_oidc(
            c.kc_url, c.kc_realm, c.kc_ob_client, c.kc_ob_secret,
            openbao_addr=c.bao_addr, openbao_token=c.bao_token)
    except ob.OpenBaoError as exc:
        _bad(str(exc))
        return 1
    _ok("OIDC auth configured.")
    cb = f"{c.bao_addr}/ui/vault/auth/{ob.OIDC_MOUNT_KEYCLOAK}/oidc/callback"
    print("\nNEXT (needs a human + browser):")
    print(f"  1. In Keycloak, client '{c.kc_ob_client}' Valid Redirect URIs "
          "must include:")
    print(f"        {cb}")
    print("        http://localhost:8250/oidc/callback")
    print(f"  2. Log in:  bao login -method=oidc -path={ob.OIDC_MOUNT_KEYCLOAK}")
    print("     A browser opens; complete the Keycloak login.")
    return 0


# ── auth0: configure Auth0 -> OpenBao, verify with a real token if possible ──
def cmd_auth0(c: Cfg) -> int:
    if not c.bao_token:
        _bad("OPENBAO_TOKEN required")
        return 1
    if not c.a0_domain:
        _bad("AUTH0_DOMAIN required")
        return 1
    ok, detail = _reachable_from_here(c.a0_discovery)
    if not ok:
        _bad(f"Auth0 discovery not reachable: {detail}")
        return 1
    print(f"Configuring Auth0->OpenBao (mount '{ob.JWT_MOUNT_AUTH0}')...")
    try:
        ob.configure_auth0_jwt(
            c.a0_domain,
            bound_audiences=[c.a0_audience] if c.a0_audience else None,
            openbao_addr=c.bao_addr, openbao_token=c.bao_token)
    except ob.OpenBaoError as exc:
        _bad(str(exc))
        return 1
    _ok("JWT auth configured.")

    # If we have M2M creds + an audience, fetch a REAL token and log in with it.
    if c.a0_m2m_id and c.a0_m2m_secret and c.a0_audience:
        print("\nVerifying with a real Auth0 client-credentials token...")
        try:
            tr = requests.post(f"https://{c.a0_domain}/oauth/token", timeout=10,
                               data={"grant_type": "client_credentials",
                                     "client_id": c.a0_m2m_id,
                                     "client_secret": c.a0_m2m_secret,
                                     "audience": c.a0_audience})
            if tr.status_code != 200:
                _bad(f"could not get Auth0 token ({tr.status_code}): "
                     f"{tr.text[:150]}")
                return 1
            jwt = tr.json()["access_token"]
            obt = ob.login_auth0_jwt(jwt, openbao_addr=c.bao_addr)
            _ok(f"real Auth0 JWT exchanged for OpenBao token: {obt[:16]}...")
            print("  *** Auth0->OpenBao verified END TO END with a live token ***")
        except ob.OpenBaoError as exc:
            _bad(f"login with real token failed: {exc}")
            _bad("  usually: bound_audiences != token aud, or issuer mismatch.")
            return 1
        except Exception as exc:  # noqa: BLE001
            _bad(f"verification errored: {exc}")
            return 1
    else:
        print("\n  (AUTH0_CLIENT_ID/SECRET/AUDIENCE not all set — skipping the "
              "live-token verification. Config is in place; provide M2M creds "
              "to confirm end to end.)")
    return 0


def cmd_all(c: Cfg) -> int:
    rc = cmd_check(c)
    if rc != 0:
        print("\nFix the preconditions above, then re-run.")
        return rc
    print("\n" + "=" * 60)
    rc_kc = cmd_keycloak(c)
    print("\n" + "=" * 60)
    rc_a0 = cmd_auth0(c)
    return 0 if (rc_kc == 0 and rc_a0 == 0) else 1


def cmd_checklist(c: Cfg) -> int:
    print(ob.login_checklist(openbao_addr=c.bao_addr))
    return 0


def cmd_approle(c: Cfg) -> int:
    """Provision AppRole so the APP can read secrets without a root token, and
    print the role_id + secret_id to put in the app's environment."""
    if not c.bao_token:
        _bad("OPENBAO_TOKEN required (the generated root token — read it with: "
             "docker compose exec openbao cat /openbao/data/bao-init.json)")
        return 1
    role = _env("OPENBAO_APPROLE_NAME", "auth-broker")
    print(f"Provisioning AppRole role '{role}' at {c.bao_addr} ...")
    try:
        creds = ob.configure_approle(role, addr=c.bao_addr,
                                     token=c.bao_token)
    except ob.OpenBaoError as exc:
        _bad(str(exc))
        return 1
    _ok(f"AppRole '{role}' provisioned (policy '{creds['policy']}')")
    print("\nPut these in the app's environment (.env or compose), then restart"
          " the app:\n")
    print(f"  OPENBAO_ROLE_ID={creds['role_id']}")
    print(f"  OPENBAO_SECRET_ID={creds['secret_id']}")
    print("\nAlso set OPENBAO_SECRETS to the names the app should read from "
          "OpenBao first (comma-separated, or '*' for all), e.g.:")
    print("  OPENBAO_SECRETS=AUTH0_CLIENT_SECRET,AUTH0_CLIENT_ID,AUTH0_AUDIENCE")
    print("\nThe app then logs in with the role_id/secret_id (no root token) and "
          "reads those secrets from OpenBao, falling back to Key Vault.")
    return 0


_COMMANDS = {
    "check": cmd_check,
    "keycloak": cmd_keycloak,
    "auth0": cmd_auth0,
    "approle": cmd_approle,
    "all": cmd_all,
    "checklist": cmd_checklist,
}


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    cmd = argv[0] if argv else "check"
    if cmd in ("-h", "--help", "help"):
        print("Usage: python openbao_setup.py "
              "[check|keycloak|auth0|approle|all|checklist]")
        print(__doc__ or "")
        return 0
    fn = _COMMANDS.get(cmd)
    if not fn:
        print(f"Unknown command '{cmd}'. "
              "Try: check | keycloak | auth0 | all | checklist")
        return 2
    print("=" * 60)
    print(f"OPENBAO SETUP — {cmd}")
    print("=" * 60)
    return fn(Cfg())


if __name__ == "__main__":
    raise SystemExit(main())
