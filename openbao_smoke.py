#!/usr/bin/env python3
# openbao_smoke.py
# LIVE smoke test for the OpenBao "Z-axis" flows — run against a real
# `bao server -dev`. Unlike test_openbao.py (which mocks the HTTP API), this
# actually talks to a running OpenBao and exercises the round trips end to end.
#
# Usage:
#     bao server -dev -dev-root-token-id=root      # in another terminal
#     OPENBAO_ADDR=http://127.0.0.1:8200 OPENBAO_TOKEN=root \
#         python openbao_smoke.py
#
# It is SAFE and self-contained: it uses throwaway mounts/roles/secrets under a
# 'smoke-*' prefix and cleans them up afterward. Exit code 0 = all checks passed.
#
# What it proves that mocked tests cannot:
#   - OpenBao actually accepts our config/role payloads (schema is correct)
#   - KV v2 put/get round-trips a real value
#   - enable_auth_method is genuinely idempotent on a real server
#   - the secret store + resolve_secret fallback work against live data

from __future__ import annotations

import os
import sys
import uuid

import requests

import openbao_connect as ob


def _preflight(addr: str, token: str) -> tuple[bool, str]:
    """Confirm OpenBao is reachable and the token works before testing."""
    try:
        r = requests.get(f"{addr}/v1/sys/health", timeout=5)
    except requests.RequestException as exc:
        return False, (f"cannot reach OpenBao at {addr}: {exc}\n"
                       "Start it with: bao server -dev -dev-root-token-id=root")
    if r.status_code not in (200, 429, 473, 501, 503):
        return False, f"unexpected /sys/health status {r.status_code}"
    # Token check: read our own token info.
    tr = requests.get(f"{addr}/v1/auth/token/lookup-self",
                      headers={"X-Vault-Token": token}, timeout=5)
    if tr.status_code == 403:
        return False, ("token rejected (403). Use the dev root token, e.g. "
                       "OPENBAO_TOKEN=root")
    if tr.status_code != 200:
        return False, f"token lookup failed ({tr.status_code})"
    return True, "ok"


def _cleanup(addr: str, token: str, mounts: list[str], kv_paths: list[str]):
    """Best-effort teardown of everything the smoke test created."""
    h = {"X-Vault-Token": token}
    for m in mounts:
        try:
            requests.delete(f"{addr}/v1/sys/auth/{m}", headers=h, timeout=5)
        except requests.RequestException:
            pass
    for p in kv_paths:
        try:
            requests.delete(f"{addr}/v1/secret/metadata/{p}", headers=h, timeout=5)
        except requests.RequestException:
            pass


class _DiscoveryStub:
    """
    A tiny local HTTP server serving a valid OIDC discovery document + JWKS, so
    OpenBao's write-time discovery fetch succeeds without a real external IdP.
    OpenBao runs on 127.0.0.1, so it can reach this on 127.0.0.1 too.
    """
    def __init__(self):
        import http.server
        import threading
        port = 8271
        issuer = f"http://127.0.0.1:{port}"
        self.issuer = issuer

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                import json as _j
                if self.path.endswith("/.well-known/openid-configuration"):
                    body = _j.dumps({
                        "issuer": issuer,
                        "jwks_uri": f"{issuer}/jwks",
                        "authorization_endpoint": f"{issuer}/authorize",
                        "token_endpoint": f"{issuer}/token",
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    }).encode()
                elif self.path.endswith("/jwks"):
                    body = _j.dumps({"keys": []}).encode()
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._srv = http.server.HTTPServer(("127.0.0.1", port), _H)
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._t.start()

    def stop(self):
        try:
            self._srv.shutdown()
        except Exception:  # noqa: BLE001
            pass


def _start_discovery_stub() -> "_DiscoveryStub":
    return _DiscoveryStub()


def run() -> int:
    addr = os.environ.get("OPENBAO_ADDR", "http://127.0.0.1:8200").rstrip("/")
    token = os.environ.get("OPENBAO_TOKEN", "")
    print("=" * 68)
    print("OPENBAO LIVE SMOKE TEST")
    print("=" * 68)
    print(f"Address : {addr}")

    if not token:
        print("✗ OPENBAO_TOKEN not set. Use the dev root token: "
              "OPENBAO_TOKEN=root")
        return 1

    ok, detail = _preflight(addr, token)
    if not ok:
        print(f"✗ preflight: {detail}")
        return 1
    print("✓ preflight: OpenBao reachable and token valid")

    # Unique suffix so repeated runs never collide, even if cleanup was skipped.
    sfx = uuid.uuid4().hex[:8]
    kc_mount = f"smoke-oidc-{sfx}"
    a0_mount = f"smoke-jwt-{sfx}"
    kv_name = f"smoke-secret-{sfx}"
    created_mounts = [kc_mount, a0_mount]
    created_kv = [kv_name]
    failures = []

    # OpenBao validates the OIDC discovery URL by FETCHING it at write time.
    # To prove the config PATH live without depending on a reachable external
    # IdP, stand up a tiny local OIDC discovery stub OpenBao can reach.
    stub = _start_discovery_stub()

    try:
        # ── Check 1: enable_auth_method + idempotency (real server) ──
        try:
            ob.enable_auth_method("jwt", a0_mount, token=token, addr=addr)
            # Second call must NOT raise (idempotency against a live mount).
            ob.enable_auth_method("jwt", a0_mount, token=token, addr=addr)
            print("✓ [1] enable_auth_method is idempotent on a live server")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"enable/idempotency: {exc}")
            print(f"✗ [1] enable_auth_method: {exc}")

        # ── Check 2: JWT config + role accepted by real OpenBao ──
        # Uses the local stub issuer so OpenBao's discovery fetch succeeds.
        try:
            ob.enable_auth_method("jwt", a0_mount, token=token, addr=addr)
            cfg = {"oidc_discovery_url": stub.issuer, "bound_issuer": stub.issuer}
            r = requests.post(f"{addr}/v1/auth/{a0_mount}/config",
                              headers={"X-Vault-Token": token}, json=cfg, timeout=5)
            assert r.status_code < 400, r.text
            role = {"role_type": "jwt", "user_claim": "sub",
                    "bound_issuer": stub.issuer, "policies": ["default"],
                    "bound_audiences": ["https://smoke.api"]}
            rr = requests.post(f"{addr}/v1/auth/{a0_mount}/role/smoke",
                               headers={"X-Vault-Token": token}, json=role, timeout=5)
            assert rr.status_code < 400, rr.text
            rb = requests.get(f"{addr}/v1/auth/{a0_mount}/role/smoke",
                              headers={"X-Vault-Token": token}, timeout=5)
            got = rb.json()["data"]
            assert "https://smoke.api" in got.get("bound_audiences", []), got
            print("✓ [2] JWT config+role accepted against a live discovery URL")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"jwt config (live discovery): {exc}")
            print(f"✗ [2] JWT config: {exc}")

        # ── Check 3: our configure_* surfaces a CLEAR error on unreachable IdP ──
        # This is the real-world failure mode; assert we explain it, not raise 400.
        try:
            ob.configure_auth0_jwt(
                "unreachable-idp.invalid", mount=f"{a0_mount}-x",
                role_name="smoke", openbao_addr=addr, openbao_token=token)
            failures.append("expected an unreachable-IdP error, got success")
            print("✗ [3] unreachable IdP did not raise")
        except ob.OpenBaoError as exc:
            if "reach the OIDC discovery" in str(exc):
                print("✓ [3] unreachable IdP produces a CLEAR, actionable error")
            else:
                failures.append(f"unreachable IdP wrong message: {exc}")
                print(f"✗ [3] unclear error: {exc}")
        finally:
            requests.delete(f"{addr}/v1/sys/auth/{a0_mount}-x",
                            headers={"X-Vault-Token": token}, timeout=5)

        # ── Check 4: KV v2 secret round trip ──
        try:
            store = ob.OpenBaoSecrets(addr=addr, token=token)
            store.put_secret(kv_name, "round-trip-value")
            got = store.get_secret(kv_name)
            assert got == "round-trip-value", got
            print("✓ [4] KV v2 secret put/get round-trips a real value")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"kv round trip: {exc}")
            print(f"✗ [4] KV secret round trip: {exc}")

        # ── Check 5: resolve_secret finds the live OpenBao value ──
        try:
            ob.OPENBAO_ADDR = addr
            ob.OPENBAO_TOKEN = token
            got = ob.resolve_secret(kv_name)
            assert got == "round-trip-value", got
            print("✓ [5] resolve_secret reads the live OpenBao value first")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"resolve_secret: {exc}")
            print(f"✗ [5] resolve_secret: {exc}")

    finally:
        stub.stop()
        _cleanup(addr, token, created_mounts, created_kv)
        print("  (cleaned up smoke mounts/secrets)")

    print("-" * 68)
    if failures:
        print(f"✗ {len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print("   - " + f)
        return 1
    print("ALL OPENBAO SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(run())
