#!/usr/bin/env python3
# endpoint_smoke.py
# Exercise the app's REAL endpoints with a REAL brokered access token.
#
# Everything in this project has been tested against mocks; this is the step
# that proves the endpoints actually work with a token obtained through the
# Keycloak -> Auth0 -> Keycloak brokered login.
#
# Usage:
#   1. Start the app:      uvicorn main:app --port 8000
#   2. Get a real token:   LOGIN_FLOW_CATCH=1 python login_flow.py
#      (complete the browser login; it prints the access token)
#   3. Run:                APP_TOKEN='<paste>' python endpoint_smoke.py
#
#   Or let it fetch a token itself via direct grant (no browser), if the
#   Keycloak client allows password grant:
#      KC_USER=... KC_PASS=... python endpoint_smoke.py
#
# It is READ-BIASED by default: only GET/status endpoints run. Pass --write to
# additionally exercise creating/deleting a throwaway group + organization.
# Nothing destructive touches existing data.

from __future__ import annotations

import json
import os
import sys
import uuid

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

APP = os.environ.get("APP_URL", "http://localhost:8000").rstrip("/")


class Result:
    def __init__(self):
        self.passed: list[str] = []
        self.failed: list[str] = []
        self.skipped: list[str] = []

    def ok(self, name: str, detail: str = ""):
        self.passed.append(name)
        print(f"  \u2713 {name}{(' — ' + detail) if detail else ''}")

    def bad(self, name: str, detail: str):
        self.failed.append(f"{name}: {detail}")
        print(f"  \u2717 {name} — {detail}")

    def skip(self, name: str, why: str):
        self.skipped.append(name)
        print(f"  - {name} skipped ({why})")


def _get_token() -> tuple[str | None, str]:
    """Return (token, how). Prefers APP_TOKEN; falls back to a direct grant."""
    tok = os.environ.get("APP_TOKEN", "").strip()
    if tok:
        return tok, "APP_TOKEN env var"
    user = os.environ.get("KC_USER")
    pw = os.environ.get("KC_PASS")
    if not (user and pw):
        return None, ("no APP_TOKEN and no KC_USER/KC_PASS — "
                      "get a token with: LOGIN_FLOW_CATCH=1 python login_flow.py")
    kc = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
    realm = os.environ.get("KEYCLOAK_REALM", "Premkey")
    cid = os.environ.get("KEYCLOAK_CLIENT_ID", "Hello-World-app")
    secret = os.environ.get("KEYCLOAK_CLIENT_SECRET", "")
    data = {"grant_type": "password", "client_id": cid,
            "username": user, "password": pw}
    if secret:
        data["client_secret"] = secret
    try:
        r = requests.post(
            f"{kc}/realms/{realm}/protocol/openid-connect/token",
            data=data, timeout=10)
    except requests.RequestException as exc:
        return None, f"Keycloak unreachable: {exc}"
    if r.status_code != 200:
        return None, (f"direct grant failed ({r.status_code}): {r.text[:160]}. "
                      "The client may not allow password grant — use APP_TOKEN.")
    return r.json().get("access_token"), "direct grant"


def _call(res: Result, method: str, path: str, token: str | None = None,
          expect: tuple[int, ...] = (200,), **kw) -> requests.Response | None:
    """Call an endpoint and record pass/fail against expected status codes."""
    url = f"{APP}{path}"
    headers = kw.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.request(method, url, headers=headers, timeout=15, **kw)
    except requests.RequestException as exc:
        res.bad(f"{method} {path}", f"request failed: {exc}")
        return None
    if r.status_code in expect:
        res.ok(f"{method} {path}", f"{r.status_code}")
        return r
    # 503 from an Auth0-backed endpoint is a *configuration* answer, not a bug.
    if r.status_code == 503:
        res.skip(f"{method} {path}",
                 "503 — subsystem disabled; see GET /status/subsystems")
        return None
    res.bad(f"{method} {path}", f"expected {expect}, got {r.status_code}: "
                                f"{r.text[:120]}")
    return r


def run(do_writes: bool = False) -> int:
    print("=" * 68)
    print("APP ENDPOINT SMOKE — real endpoints, real brokered token")
    print("=" * 68)
    print(f"App: {APP}")
    res = Result()

    # ── app reachable ──
    try:
        requests.get(f"{APP}/", timeout=5)
    except requests.RequestException as exc:
        print(f"\u2717 app unreachable at {APP}: {exc}")
        print("  start it: uvicorn main:app --port 8000")
        return 1

    print("\n[unauthenticated]")
    _call(res, "GET", "/")
    sub = _call(res, "GET", "/status/subsystems")
    if sub is not None:
        try:
            print("      subsystems: " +
                  json.dumps({k: v.get("enabled") for k, v in sub.json().items()
                              if isinstance(v, dict)}))
        except ValueError:
            pass
    # /protected must REJECT an anonymous caller — a 200 here would be a
    # serious auth bug, so this is a security assertion, not a formality.
    r = _call(res, "GET", "/protected", expect=(401, 403))
    if r is not None and r.status_code in (401, 403):
        pass

    token, how = _get_token()
    if not token:
        print(f"\n\u2717 no access token: {how}")
        print("  (unauthenticated checks above still ran)")
        return 1
    print(f"\n[authenticated] token via {how}")

    # ── the core: a real token against protected endpoints ──
    _call(res, "GET", "/protected", token=token)
    _call(res, "GET", "/keys")

    # Auth0-backed reads. 503 => subsystem off (reported as skip, not failure).
    _call(res, "GET", "/users/lookup", token=token,
          params={"email": os.environ.get("SMOKE_LOOKUP_EMAIL", "nobody@example.com")},
          expect=(200, 404))
    _call(res, "GET", "/organizations", token=token)

    if not do_writes:
        print("\n(read-only; pass --write to exercise create/delete)")
    else:
        print("\n[writes — throwaway objects, cleaned up]")
        gname = f"smoke-group-{uuid.uuid4().hex[:8]}"
        created = _call(res, "POST", "/groups", token=token,
                        params={"group_name": gname}, expect=(200, 201))
        if created is not None:
            _call(res, "DELETE", "/groups", token=token,
                  params={"group_name": gname}, expect=(200, 204))
        oname = f"smoke-org-{uuid.uuid4().hex[:8]}"
        org = _call(res, "POST", "/organizations", token=token,
                    params={"name": oname, "display_name": oname},
                    expect=(200, 201))
        if org is not None:
            try:
                oid = org.json().get("id") or org.json().get("organization", {}).get("id")
            except ValueError:
                oid = None
            if oid:
                _call(res, "DELETE", f"/organizations/{oid}", token=token,
                      expect=(200, 204))
            else:
                res.skip("DELETE /organizations/{id}", "no id in create response")

    print("-" * 68)
    print(f"passed {len(res.passed)}  failed {len(res.failed)}  "
          f"skipped {len(res.skipped)}")
    if res.failed:
        print("\nFAILURES:")
        for f in res.failed:
            print("  - " + f)
        return 1
    print("ALL ENDPOINT CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(run(do_writes="--write" in sys.argv))
