#!/usr/bin/env python3
# integration_test_live.py
# LIVE integration test: runs the app's real Keycloak setup against a REAL
# Keycloak, then exercises the real auth loop over HTTP. This is the test that
# catches the class of bug the mocked suite cannot — the realm-never-created and
# user-not-fully-set-up bugs both passed hundreds of mocked tests and only broke
# against a real Keycloak.
#
# It is deliberately NOT a pytest test: it needs a real Keycloak reachable at
# KEYCLOAK_URL, so it runs as its own CI job (see .github/workflows/ci.yml,
# job 'live-integration') rather than in the unit-test run.
#
# Exit code 0 = all checks passed; non-zero = a real failure.
#
# Required env (CI sets these; locally, point at your own Keycloak):
#   KEYCLOAK_URL            e.g. http://localhost:8080
#   KEYCLOAK_REALM          e.g. Premkey
#   KEYCLOAK_ADMIN_USER     e.g. admin
#   KEYCLOAK_ADMIN_PASSWORD e.g. admin
#   DEFAULT_USER_PASSWORD   the password the app sets on the default 'user'

from __future__ import annotations

import os
import sys
import threading
import time

import requests


PORT = int(os.environ.get("INTEGRATION_APP_PORT", "8099"))
BASE = f"http://127.0.0.1:{PORT}"
DEFAULT_USER = os.environ.get("INTEGRATION_KC_USER", "user")
DEFAULT_PASS = os.environ.get("DEFAULT_USER_PASSWORD", "testpass123")


class Checks:
    def __init__(self):
        self.failed: list[str] = []

    def check(self, name: str, cond: bool, detail: str = ""):
        mark = "\u2713" if cond else "\u2717"
        print(f"  {mark} {name}" + (f" — {detail}" if detail else ""))
        if not cond:
            self.failed.append(name + (f": {detail}" if detail else ""))


def _wait_for_keycloak(url: str, timeout: int = 180) -> bool:
    """Poll the master realm until Keycloak answers or we give up."""
    deadline = time.time() + timeout
    probe = url.rstrip("/") + "/realms/master"
    while time.time() < deadline:
        try:
            if requests.get(probe, timeout=5).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(3)
    return False


def _start_app() -> threading.Thread:
    """Launch the FastAPI app (real lifespan → real Keycloak setup) in-process."""
    import uvicorn
    import main

    def serve():
        uvicorn.run(main.app, host="127.0.0.1", port=PORT, log_level="warning")

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t


def _wait_for_app(timeout: int = 90) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(BASE + "/", timeout=3).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


def main_run() -> int:
    print("=" * 68)
    print("LIVE KEYCLOAK INTEGRATION TEST")
    print("=" * 68)
    kc_url = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    print(f"Keycloak: {kc_url}")
    print(f"App:      {BASE}")

    c = Checks()

    # 1. Keycloak must be reachable before we start the app.
    print("\n[1] Keycloak reachability")
    if not _wait_for_keycloak(kc_url):
        print(f"  \u2717 Keycloak never became ready at {kc_url}")
        return 1
    print("  \u2713 Keycloak is up")

    # 2. Start the app — this runs the REAL setup_keycloak (_ensure_realm,
    #    client creation, default-user finalization) against real Keycloak.
    print("\n[2] App startup (runs real Keycloak provisioning)")
    _start_app()
    if not _wait_for_app():
        print("  \u2717 App did not become ready — startup/provisioning failed")
        print("      (this is exactly the failure the realm/user bugs caused)")
        return 1
    print("  \u2713 App started — realm, client, and default user provisioned")

    # 3. The real auth loop over HTTP.
    print("\n[3] Auth loop")
    # 3a. token with valid credentials
    try:
        r = requests.post(BASE + "/token",
                          data={"username": DEFAULT_USER, "password": DEFAULT_PASS},
                          timeout=15)
        c.check("POST /token (valid creds) -> 200", r.status_code == 200,
                f"got {r.status_code}: {r.text[:120]}" if r.status_code != 200 else "")
        token = r.json().get("access_token") if r.status_code == 200 else None
    except requests.RequestException as exc:
        c.check("POST /token", False, str(exc))
        token = None

    # 3b. token with bad credentials must be rejected
    try:
        rb = requests.post(BASE + "/token",
                          data={"username": DEFAULT_USER, "password": "wrong-pw"},
                          timeout=15)
        c.check("POST /token (bad creds) -> 401", rb.status_code == 401,
                f"got {rb.status_code}")
    except requests.RequestException as exc:
        c.check("POST /token (bad creds)", False, str(exc))

    # 3c. protected with token
    if token:
        try:
            p = requests.get(BASE + "/protected",
                            headers={"Authorization": f"Bearer {token}"}, timeout=15)
            c.check("GET /protected (with token) -> 200", p.status_code == 200,
                    f"got {p.status_code}")
        except requests.RequestException as exc:
            c.check("GET /protected (with token)", False, str(exc))

        # 3d. introspection
        try:
            o = requests.post(BASE + "/oidc-token",
                             headers={"Authorization": f"Bearer {token}"}, timeout=15)
            c.check("POST /oidc-token (introspect) -> 200", o.status_code == 200,
                    f"got {o.status_code}")
        except requests.RequestException as exc:
            c.check("POST /oidc-token", False, str(exc))

    # 3e. protected without token must be rejected (security assertion)
    try:
        a = requests.get(BASE + "/protected", timeout=15)
        c.check("GET /protected (anonymous) -> 401", a.status_code == 401,
                f"got {a.status_code}")
    except requests.RequestException as exc:
        c.check("GET /protected (anonymous)", False, str(exc))

    # 4. Idempotency: running setup again against the now-provisioned Keycloak
    #    must not crash (restarts hit this constantly).
    print("\n[4] Setup idempotency")
    try:
        import main
        main._setup_keycloak_with_retry()
        c.check("second setup run is idempotent", True)
    except Exception as exc:  # noqa: BLE001
        c.check("second setup run is idempotent", False, str(exc))

    # 5. Groups pagination: list_groups must return ALL groups, walking pages.
    #    Verified live against real Keycloak — creates >100 groups (crossing the
    #    page boundary that a single-request implementation could truncate) and
    #    confirms every one comes back. This exercises the auth0_talk.list_groups
    #    pagination fix against a real server, not a mock of the response shape.
    print("\n[5] Groups pagination (list_groups walks all pages)")
    try:
        import requests as _rq
        from auth0_talk import KeycloakAdminAPI
        realm = os.environ.get("KEYCLOAK_REALM", "Premkey")
        admin_user = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
        admin_pass = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
        tok = _rq.post(
            kc_url.rstrip("/") + "/realms/master/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": "admin-cli",
                  "username": admin_user, "password": admin_pass},
            timeout=15).json().get("access_token")
        if not tok:
            c.check("obtained admin token for groups test", False, "no token")
        else:
            hdr = {"Authorization": f"Bearer {tok}",
                   "Content-Type": "application/json"}
            base = kc_url.rstrip("/") + f"/admin/realms/{realm}/groups"
            # Create 120 groups (crosses the 100/page boundary). Idempotent-ish:
            # a 409 on re-run is fine.
            made = 0
            for i in range(120):
                r = _rq.post(base, headers=hdr,
                             json={"name": f"pgtest-{i:04d}"}, timeout=10)
                if r.status_code in (201, 409):
                    made += 1
            api = KeycloakAdminAPI(kc_url.rstrip("/"), tok, realm)
            all_groups = api.list_groups()
            pgtest = [g for g in all_groups if g.get("name", "").startswith("pgtest-")]
            c.check("list_groups returns all >100 groups (paginated)",
                    len(pgtest) >= 120,
                    f"expected >=120 pgtest groups, got {len(pgtest)}")
    except Exception as exc:  # noqa: BLE001
        c.check("groups pagination", False, str(exc))

    # 6. Role provisioning: setup_keycloak must create the admin role and grant
    #    it to the admin user, so the authorization layer is usable. Verified
    #    live because the python-keycloak role method names can't be confirmed by
    #    mocks.
    print("\n[6] Admin role provisioning")
    try:
        import requests as _rq2
        realm = os.environ.get("KEYCLOAK_REALM", "Premkey")
        admin_role = os.environ.get("ADMIN_ROLE", "tenant-admin")
        admin_username = os.environ.get("ADMIN_USERNAME", "admin-user")
        admin_user = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
        admin_pass = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
        tok = _rq2.post(
            kc_url.rstrip("/") + "/realms/master/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": "admin-cli",
                  "username": admin_user, "password": admin_pass},
            timeout=15).json().get("access_token")
        hdr = {"Authorization": f"Bearer {tok}"}
        base = kc_url.rstrip("/") + f"/admin/realms/{realm}"
        roles = _rq2.get(base + "/roles", headers=hdr, timeout=10).json()
        c.check(f"realm role '{admin_role}' provisioned",
                any(r.get("name") == admin_role for r in roles),
                "role not found in realm")
        users = _rq2.get(base + f"/users?username={admin_username}",
                         headers=hdr, timeout=10).json()
        if users:
            uid = users[0]["id"]
            urs = _rq2.get(base + f"/users/{uid}/role-mappings/realm",
                           headers=hdr, timeout=10).json()
            c.check(f"admin user has '{admin_role}' role",
                    any(r.get("name") == admin_role for r in urs),
                    "admin user missing the role")
        else:
            c.check("admin user provisioned", False, "admin user not found")
    except Exception as exc:  # noqa: BLE001
        c.check("role provisioning", False, str(exc))

    print("-" * 68)
    if c.failed:
        print(f"\u2717 {len(c.failed)} check(s) FAILED:")
        for f in c.failed:
            print("   - " + f)
        return 1
    print("ALL LIVE INTEGRATION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main_run())
