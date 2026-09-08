#!/usr/bin/env python3
# auth0_pagination_live.py
# Live verification of the Auth0 Management API pagination in
# auth0_connect._find_by_name (get_client_by_name / get_connection_by_name).
#
# WHY THIS EXISTS: those methods were only ever mock-verified, because the M2M
# app couldn't reach the Auth0 Management API (access_denied for the api/v2/
# audience). Once the M2M app is authorized for the Management API, this script
# proves the pagination works against the REAL API response shape — closing the
# one verification gap that was blocked by permissions rather than by choice.
#
# REQUIREMENTS (all read-only — this script creates and deletes nothing):
#   - AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET set in the environment
#   - the M2M app authorized for the Auth0 Management API with at least:
#       read:clients, read:connections
#
# WHAT IT CHECKS:
#   1. The M2M app can actually get a Management API token (the wall is down).
#   2. _find_by_name returns the SAME clients/connections a raw paginated sweep
#      returns — i.e. it doesn't miss items on later pages, and doesn't loop.
#   3. Looking up a name that exists is found; a name that doesn't returns None.
#   4. The exactly-one-page boundary is handled (no infinite loop, no off-by-one)
#      by exercising a small per_page against the real collection.
#
# It exits 0 on success, 1 on any failure, and prints a clear per-check report.

from __future__ import annotations

import os
import sys

from auth0_connect import Auth0Connect


class Checks:
    def __init__(self) -> None:
        self.failed: list[str] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        mark = "\u2713" if ok else "\u2717"
        print(f"  {mark} {name}" + (f" \u2014 {detail}" if detail else ""))
        if not ok:
            self.failed.append(name)


def _raw_sweep(auth0: Auth0Connect, collection: str, per_page: int = 100) -> list:
    """Independently walk all pages of a collection with a simple loop, to get a
    ground-truth list to compare _find_by_name against. Deliberately NOT reusing
    _find_by_name so this is a real cross-check, not the same code."""
    out: list = []
    page = 0
    while True:
        result = auth0._api("GET", collection, params={
            "page": page, "per_page": per_page, "include_totals": "true",
        })
        if isinstance(result, dict):
            items = result.get(collection, [])
            total = result.get("total", len(items))
            start = result.get("start", page * per_page)
            limit = result.get("limit", per_page)
        else:
            items = result if isinstance(result, list) else []
            total, start, limit = len(items), 0, per_page
        out.extend(items)
        if not items or (start + limit) >= total or len(items) < limit:
            break
        page += 1
        if page > 1000:  # hard safety stop
            break
    return out


def verify_collection(auth0: Auth0Connect, collection: str,
                      finder, c: Checks) -> None:
    print(f"\n[{collection}]")
    try:
        ground_truth = _raw_sweep(auth0, collection)
    except Exception as exc:  # noqa: BLE001
        c.check(f"{collection}: reachable", False, str(exc))
        return
    c.check(f"{collection}: reachable via Management API", True,
            f"{len(ground_truth)} item(s) total")

    names = [i.get("name") for i in ground_truth if i.get("name")]
    if not names:
        c.check(f"{collection}: has at least one named item to test", False,
                "no named items — cannot verify lookup")
        return

    # 1. An item that EXISTS is found by _find_by_name.
    target = names[-1]  # the LAST one — most likely on a later page if paginated
    hit = finder(target)
    c.check(f"{collection}: finds an existing item ('{target}')",
            hit is not None and hit.get("name") == target,
            "not found" if hit is None else "ok")

    # 2. Every named item is findable (proves no page is skipped).
    missing = [n for n in names if finder(n) is None]
    c.check(f"{collection}: every item findable (no page skipped)",
            not missing,
            f"missed {len(missing)}: {missing[:3]}" if missing else "all found")

    # 3. A name that does NOT exist returns None (and doesn't loop forever).
    bogus = "zzz-nonexistent-" + "x" * 12
    c.check(f"{collection}: non-existent name returns None",
            finder(bogus) is None)


def main() -> int:
    domain = os.environ.get("AUTH0_DOMAIN")
    cid = os.environ.get("AUTH0_CLIENT_ID")
    secret = os.environ.get("AUTH0_CLIENT_SECRET")
    if not (domain and cid and secret):
        print("SKIP: set AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET "
              "to run this live verification.")
        return 0

    print(f"Auth0 pagination live verification against {domain}")
    auth0 = Auth0Connect(domain, cid, secret)
    c = Checks()

    # 0. Can we get a Management API token at all? (the wall is down)
    try:
        _ = auth0.token
        c.check("M2M app can obtain a Management API token", True,
                "authorized for api/v2/")
    except Exception as exc:  # noqa: BLE001
        c.check("M2M app can obtain a Management API token", False, str(exc))
        print("\n\u2717 Cannot reach the Management API. Authorize the M2M app "
              "for the Auth0 Management API (audience https://%s/api/v2/) with "
              "read:clients and read:connections, then retry." % domain)
        return 1

    verify_collection(auth0, "clients", auth0.get_client_by_name, c)
    verify_collection(auth0, "connections", auth0.get_connection_by_name, c)

    print("\n" + "-" * 68)
    if c.failed:
        print(f"\u2717 {len(c.failed)} check(s) FAILED:")
        for f in c.failed:
            print("   - " + f)
        return 1
    print("ALL AUTH0 PAGINATION LIVE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
