#!/usr/bin/env python3
# e2e_smoke.py — run the REAL app end-to-end against a built-in mock IdP.
#
# Verifies, in one command, that the whole stack boots and serves:
#   lifespan (RSA keys -> Keycloak setup w/ retry -> OIDC client -> UserManager)
#   POST /token   (Keycloak password-grant path)
#   GET  /protected (Keycloak introspection path)
#   GET  /users/lookup (protected, cross-system)
#   401 for unauthenticated protected access
#
# No real Keycloak/Auth0 needed. Usage:  python e2e_smoke.py
# Exit code 0 = all checks passed.

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

MOCK_PORT, APP_PORT = 8779, 8123


class _MockIdP(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path
        if "/authentication/flows" in p:
            self._send(200, [{"alias": "Hello-World-flow"}])
        elif "/users" in p and "username=user" in p:
            self._send(200, [{"id": "u-1", "username": "user"}])
        elif "/users" in p and "email=" in p:
            self._send(200, [{"id": "u-9", "email": "nathan@x.com", "username": "nathan"}])
        elif "/clients/" in p and p.endswith("/client-secret"):
            self._send(200, {"type": "secret", "value": "kc-live-secret"})
        elif "/clients" in p and "clientId=" in p:
            self._send(200, [{"id": "client-uuid-1", "clientId": "Hello-World-app"}])
        else:
            self._send(200, [])

    def do_POST(self):
        p = self.path
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if p.endswith("/token/introspect"):
            self._send(200, {"active": True, "preferred_username": "nathan"})
        elif p.endswith("/protocol/openid-connect/token"):
            self._send(200, {"access_token": "live-tok", "expires_in": 300,
                             "refresh_token": "r", "token_type": "Bearer"})
        elif p == "/oauth/token":
            self._send(200, {"access_token": "a0-tok", "expires_in": 3600})
        else:
            self._send(200, {})


def main() -> int:
    # Route the app's https calls to the local http mock.
    import requests
    _orig = requests.sessions.Session.request

    def _patched(self, method, url, **kw):
        return _orig(self, method,
                     url.replace(f"https://127.0.0.1:{MOCK_PORT}",
                                 f"http://127.0.0.1:{MOCK_PORT}"), **kw)

    requests.sessions.Session.request = _patched

    os.environ.update({
        "KEY_DIR": "/tmp/e2e_smoke_keys",
        "KEYCLOAK_URL": f"http://127.0.0.1:{MOCK_PORT}",
        "KEYCLOAK_REALM": "Premkey",
        "AUTH0_DOMAIN": f"127.0.0.1:{MOCK_PORT}",
        "AUTH0_CLIENT_ID": "cid",
        "AUTH0_CLIENT_SECRET": "sec",
        "AUTH0_AUDIENCE": "aud",
        "KEYCLOAK_STARTUP_RETRIES": "3",
        "KEYCLOAK_STARTUP_BACKOFF": "1",
    })

    srv = HTTPServer(("127.0.0.1", MOCK_PORT), _MockIdP)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    import main as app_module
    import uvicorn
    config = uvicorn.Config(app_module.app, host="127.0.0.1", port=APP_PORT,
                            log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()

    deadline = time.time() + 15
    base = f"http://127.0.0.1:{APP_PORT}"
    while time.time() < deadline:
        try:
            if requests.get(f"{base}/", timeout=1).status_code == 200:
                break
        except requests.RequestException:
            time.sleep(0.3)
    else:
        print("FAIL: app did not become ready")
        return 1

    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" — {detail}" if detail else ""))

    r = requests.get(f"{base}/")
    check("GET / serves", r.status_code == 200 and r.json().get("message") == "Hello, World!")

    r = requests.post(f"{base}/token", data={"username": "user", "password": "pw"})
    check("POST /token (Keycloak grant path)",
          r.status_code == 200 and r.json().get("access_token") == "live-tok")

    r = requests.get(f"{base}/protected", headers={"Authorization": "Bearer live-tok"})
    check("GET /protected (introspection path)",
          r.status_code == 200 and "nathan" in r.json().get("message", ""))

    r = requests.get(f"{base}/users/lookup",
                     params={"username": "nathan", "email": "nathan@x.com"},
                     headers={"Authorization": "Bearer live-tok"})
    check("GET /users/lookup (cross-system)", r.status_code == 200
          and r.json().get("system") in ("keycloak", "both", "auth0", "neither"))

    r = requests.get(f"{base}/users/lookup",
                     params={"username": "n", "email": "e@x.com"})
    check("unauthenticated lookup blocked", r.status_code == 401)

    ok = all(checks)
    print("\n" + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
