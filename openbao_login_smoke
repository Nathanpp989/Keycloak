#!/usr/bin/env python3
# openbao_login_smoke.py
# LIVE verification of the OpenBao *login* round trips — the piece that
# test_openbao.py (mocks) and openbao_smoke.py (config/secret only) don't cover.
#
# It proves the JWT login path END TO END against a real `bao server -dev`:
#   1. generates an RSA keypair (stands in for Auth0's signing key),
#   2. serves a local OIDC discovery doc + JWKS (stands in for Auth0's endpoints),
#   3. configures OpenBao's JWT auth method against that issuer,
#   4. mints a real RS256 JWT — signed exactly the way Auth0 signs,
#   5. calls openbao_connect.login_auth0_jwt() and asserts a usable OpenBao
#      token comes back with the expected policy.
#
# The ONLY difference from your production Auth0 path is where the signing key
# comes from. The signature verification, discovery fetch, role binding, and
# token exchange are identical — so a pass here means the mechanics are sound
# and any real-Auth0 failure is config/reachability, not code.
#
# Usage:
#     bao server -dev -dev-root-token-id=root      # terminal 1
#     OPENBAO_ADDR=http://127.0.0.1:8200 OPENBAO_TOKEN=root \
#         python openbao_login_smoke.py
#
# Requires: pyjwt, cryptography  (pip install pyjwt cryptography)

from __future__ import annotations

import base64
import http.server
import json
import os
import threading
import time
import uuid

import requests

try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    pyjwt = None

import openbao_connect as ob


def _make_jwt(priv: bytes, iss: str, sub: str, aud: str, exp_seconds: int,
              iat_offset: int = 0) -> str:
    """Mint an RS256 JWT exactly as Auth0 would sign one, for the smoke checks.

    exp = now + exp_seconds (negative exp_seconds => already-expired token).
    iat = now + iat_offset  (backdate the issued-at for the expired case so the
    token is coherently 'issued in the past and since expired', not the
    nonsensical iat=now/exp<now)."""
    now = int(time.time())
    return pyjwt.encode(
        {"iss": iss + "/", "sub": sub, "aud": aud,
         "iat": now + iat_offset, "exp": now + exp_seconds},
        priv, algorithm="RS256", headers={"kid": "smoke-key-1"})

# The issuer stub binds a free port at runtime (see _start_issuer_stub).


def _b64u(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_key_and_jwks() -> tuple[bytes, dict]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "kid": "smoke-key-1",
                      "alg": "RS256", "n": _b64u(nums.n), "e": _b64u(nums.e)}]}
    return priv, jwks


def _start_issuer_stub(jwks: dict) -> tuple[http.server.HTTPServer, str]:
    """
    Start the local issuer stub on a FREE port (port 0 = OS picks one) and
    return (server, issuer_url). Binding a fixed port would raise a bare
    'Address already in use' if the port were taken — e.g. running this twice
    concurrently — which tells the operator nothing useful.
    """
    issuer_holder = {}

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            iss = issuer_holder["issuer"]
            if "openid-configuration" in self.path:
                body = json.dumps({
                    "issuer": iss + "/",
                    "jwks_uri": iss + "/jwks",
                    "authorization_endpoint": iss + "/authorize",
                    "token_endpoint": iss + "/token",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }).encode()
            elif self.path.endswith("/jwks"):
                body = json.dumps(jwks).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    try:
        srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    except OSError as exc:
        raise RuntimeError(
            f"could not start the local issuer stub: {exc}") from exc
    issuer = f"http://127.0.0.1:{srv.server_address[1]}"
    issuer_holder["issuer"] = issuer
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)
    return srv, issuer


def run() -> int:
    addr = os.environ.get("OPENBAO_ADDR", "http://127.0.0.1:8200").rstrip("/")
    token = os.environ.get("OPENBAO_TOKEN", "")
    print("=" * 68)
    print("OPENBAO LOGIN ROUND-TRIP SMOKE (JWT path, live)")
    print("=" * 68)

    if pyjwt is None:
        print("✗ needs pyjwt + cryptography: pip install pyjwt cryptography")
        return 1
    if not token:
        print("✗ set OPENBAO_TOKEN (dev root token, e.g. root)")
        return 1
    try:
        requests.get(f"{addr}/v1/sys/health", timeout=5)
    except requests.RequestException as exc:
        print(f"✗ OpenBao unreachable at {addr}: {exc}\n"
              "  start it: bao server -dev -dev-root-token-id=root")
        return 1

    sfx = uuid.uuid4().hex[:8]
    mount = f"login-smoke-{sfx}"
    h = {"X-Vault-Token": token}
    priv, jwks = _make_key_and_jwks()
    stub, _ISSUER = _start_issuer_stub(jwks)
    failures = []

    try:
        # Configure JWT auth against the local issuer stub.
        # Every SETUP step is checked: an unchecked setup failure would surface
        # later as a confusing "login failed"/"policy missing" and send you
        # debugging the login code when the real problem was here.
        def _must(resp, what: str):
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"SETUP step failed — {what} ({resp.status_code}): "
                    f"{resp.text[:150]}. This is a harness/permissions problem, "
                    "NOT a failure of the login code under test.")
            return resp

        _must(requests.post(f"{addr}/v1/sys/auth/{mount}", headers=h,
                            json={"type": "jwt"}, timeout=5),
              f"enable jwt auth at {mount}")
        r = requests.post(f"{addr}/v1/auth/{mount}/config", headers=h,
                          json={"oidc_discovery_url": _ISSUER + "/",
                                "bound_issuer": _ISSUER + "/"}, timeout=5)
        if r.status_code >= 400:
            print(f"✗ JWT config failed: {r.status_code} {r.text[:150]}")
            return 1
        _must(requests.put(f"{addr}/v1/sys/policies/acl/login-smoke", headers=h,
                           json={"policy":
                                 'path "secret/*" { capabilities=["read"] }'},
                           timeout=5), "write login-smoke policy")
        _must(requests.post(f"{addr}/v1/auth/{mount}/role/auth0", headers=h,
                            json={"role_type": "jwt", "user_claim": "sub",
                                  "bound_issuer": _ISSUER + "/",
                                  "bound_audiences": ["https://smoke.api"],
                                  "policies": ["login-smoke"], "token_ttl": "1h"},
                            timeout=5), "write jwt role")

        # Mint a real RS256 JWT, exactly as Auth0 would sign one.
        good = _make_jwt(priv, _ISSUER, "auth0|smoke-user",
                         "https://smoke.api", 3600)

        # ── Check 1: the real login code exchanges the JWT for an OpenBao token ──
        try:
            obt = ob.login_auth0_jwt(good, mount=mount, openbao_addr=addr)
            assert obt, "no token returned"
            who = requests.get(f"{addr}/v1/auth/token/lookup-self",
                               headers={"X-Vault-Token": obt}, timeout=5).json()
            pols = who["data"]["policies"]
            assert "login-smoke" in pols, f"policy missing: {pols}"
            print("✓ [1] JWT login round trip: token issued with correct policy")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"jwt login: {exc}")
            print(f"✗ [1] JWT login: {exc}")

        # ── Check 2: an expired JWT is REJECTED (negative case) ──
        try:
            # exp in the past (expired), iat backdated so it's coherent.
            expired = _make_jwt(priv, _ISSUER, "u", "https://smoke.api",
                                -3600, iat_offset=-7200)
            try:
                ob.login_auth0_jwt(expired, mount=mount, openbao_addr=addr)
                failures.append("expired JWT was accepted (should reject)")
                print("✗ [2] expired JWT wrongly accepted")
            except ob.OpenBaoError:
                print("✓ [2] expired JWT correctly rejected")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"expired-jwt check: {exc}")
            print(f"✗ [2] expired-jwt check errored: {exc}")

        # ── Check 3: wrong audience is REJECTED (bound_audiences enforced) ──
        try:
            wrong_aud = _make_jwt(priv, _ISSUER, "u", "https://WRONG", 3600)
            try:
                ob.login_auth0_jwt(wrong_aud, mount=mount, openbao_addr=addr)
                failures.append("wrong-audience JWT accepted (should reject)")
                print("✗ [3] wrong-audience JWT wrongly accepted")
            except ob.OpenBaoError:
                print("✓ [3] wrong-audience JWT correctly rejected")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"wrong-aud check: {exc}")
            print(f"✗ [3] wrong-aud check errored: {exc}")

    except RuntimeError as exc:
        # A checked SETUP step failed (see _must). Report it as a harness
        # problem so it is never mistaken for a failure of the code under test.
        print(f"✗ {exc}")
        failures.append(str(exc))
    finally:
        stub.shutdown()
        requests.delete(f"{addr}/v1/sys/auth/{mount}", headers=h, timeout=5)
        requests.delete(f"{addr}/v1/sys/policies/acl/login-smoke", headers=h,
                        timeout=5)
        print("  (cleaned up login-smoke mount/policy)")

    print("-" * 68)
    if failures:
        print(f"✗ {len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print("   - " + f)
        return 1
    print("ALL LOGIN ROUND-TRIP CHECKS PASSED")
    print("\nNOTE: this proves the JWT *mechanics* (signature, discovery, role,")
    print("token exchange) against real OpenBao. Your real Auth0 path differs")
    print("only in the signing key's origin. The Keycloak *browser* login needs")
    print("a human + live Keycloak — see openbao_login_checklist().")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
