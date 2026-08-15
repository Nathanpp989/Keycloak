#!/usr/bin/env python3
# authz.py
# Role-based authorization for the broker's admin endpoints.
#
# The problem this solves: every admin endpoint currently uses
# require_keycloak_auth, which only checks that the token is VALID — any
# authenticated user can create groups, assign roles, or delete organizations.
# For multi-tenant SaaS that's unacceptable: a customer's ordinary user could
# delete their organization or read across tenants.
#
# This adds AUTHORIZATION on top of authentication: require_role("x") produces a
# FastAPI dependency that (1) validates the token as before, then (2) checks the
# token carries role "x", raising 403 if not. 401 = "who are you?" (bad token);
# 403 = "I know who you are, you're not allowed" (valid token, missing role).
#
# Roles come from Keycloak's token introspection response, which nests them:
#   realm_access.roles:            realm-wide roles (e.g. "tenant-admin")
#   resource_access.<client>.roles: client-scoped roles
# We check both, so a role granted either way satisfies the requirement.

from __future__ import annotations

from typing import Callable, Iterable

from fastapi import Depends, HTTPException


def extract_roles(token_info: dict) -> set[str]:
    """Collect all roles from a Keycloak introspection response.

    Merges realm roles and every client's resource roles into one set. Missing
    or malformed sections are treated as "no roles there" rather than errors —
    a token without the section simply has none of those roles.
    """
    roles: set[str] = set()

    realm = token_info.get("realm_access")
    if isinstance(realm, dict):
        r = realm.get("roles")
        if isinstance(r, list):
            roles.update(str(x) for x in r)

    resource = token_info.get("resource_access")
    if isinstance(resource, dict):
        for client_block in resource.values():
            if isinstance(client_block, dict):
                r = client_block.get("roles")
                if isinstance(r, list):
                    roles.update(str(x) for x in r)

    return roles


def user_has_any_role(token_info: dict, required: Iterable[str]) -> bool:
    """True if the token carries at least one of the required roles."""
    have = extract_roles(token_info)
    return any(r in have for r in required)


# Claims that may carry the user's organization/tenant membership. Keycloak and
# Auth0 both can emit an "organization" claim; we also accept a few common
# alternatives so this works across IdP configurations without code changes.
_ORG_CLAIMS = ("organizations", "organization", "org", "orgs", "tenant", "tenants")


def extract_org_ids(token_info: dict) -> set[str]:
    """Collect the organization/tenant ids the token's subject belongs to.

    Looks across the common claim names and normalizes the several shapes an org
    claim takes in the wild:
      - a list of ids:            ["org_a", "org_b"]
      - a single id string:       "org_a"
      - Auth0-style dict keyed by id: {"org_a": {...}, "org_b": {...}}
      - a list of dicts with id/name: [{"id": "org_a"}, ...]
    Unknown/missing claims yield an empty set (no access), never an error.
    """
    ids: set[str] = set()
    for claim in _ORG_CLAIMS:
        val = token_info.get(claim)
        if val is None:
            continue
        if isinstance(val, str):
            ids.add(val)
        elif isinstance(val, dict):
            # Auth0 organizations claim: keys are the org ids.
            ids.update(str(k) for k in val.keys())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    ids.add(item)
                elif isinstance(item, dict):
                    # dict entries: prefer an explicit id, fall back to name.
                    oid = item.get("id") or item.get("org_id") or item.get("name")
                    if oid is not None:
                        ids.add(str(oid))
    return ids


def user_can_access_org(token_info: dict, org_id: str) -> bool:
    """True if the token's subject belongs to the given organization."""
    return org_id in extract_org_ids(token_info)


def make_require_role(introspect_dependency: Callable) -> Callable:
    """Build the require_role factory, wired to the app's auth dependency.

    Passing the introspection dependency in (rather than importing it) keeps this
    module decoupled from main.py and trivially testable: a test can supply a
    fake dependency that returns any token_info it wants.

    Usage in main.py:
        require_role = make_require_role(require_keycloak_auth)
        @app.post("/groups")
        def create_group(token_info = Depends(require_role("tenant-admin"))):
            ...
    """
    def require_role(*allowed_roles: str) -> Callable:
        if not allowed_roles:
            raise ValueError("require_role needs at least one role")

        def dependency(token_info: dict = Depends(introspect_dependency)) -> dict:
            # token_info is already validated (active, not expired) by the
            # injected dependency. Now the authorization check:
            if not user_has_any_role(token_info, allowed_roles):
                # 403, not 401: the caller IS authenticated, just not permitted.
                # We name the required role(s) so an operator debugging a denied
                # request knows what's missing — but reveal nothing about the
                # token itself.
                raise HTTPException(
                    status_code=403,
                    detail=("Forbidden: requires one of role(s): "
                            + ", ".join(sorted(allowed_roles))),
                )
            return token_info

        return dependency

    return require_role


def enforce_org_access(token_info: dict, org_id: str,
                       superadmin_roles: Iterable[str] = ()) -> None:
    """Raise 403 unless the token's subject may act on the given organization.

    This is the tenant-isolation check: a tenant-admin of org A must not be able
    to modify org B. Call it from any endpoint that takes an org_id, passing the
    validated token_info and the target org.

    A caller holding one of `superadmin_roles` bypasses the scope check — that's
    the platform operator who legitimately manages all tenants. Pass an empty
    set (the default) if you have no such role.

    Kept as a plain function (not a dependency) because the org_id usually comes
    from the path/body of the specific endpoint, which a generic dependency can't
    know — the endpoint calls this after reading its own org_id.
    """
    if superadmin_roles and user_has_any_role(token_info, superadmin_roles):
        return  # platform superadmin: cross-tenant access is intended
    if not user_can_access_org(token_info, org_id):
        raise HTTPException(
            status_code=403,
            detail=("Forbidden: you do not have access to organization "
                    f"'{org_id}'"),
        )


def is_superadmin(token_info: dict, superadmin_roles: Iterable[str]) -> bool:
    """True if the token holds a role that grants cross-tenant (platform) access."""
    return bool(superadmin_roles) and user_has_any_role(token_info, superadmin_roles)


def filter_orgs_to_accessible(token_info: dict, orgs: list,
                              superadmin_roles: Iterable[str] = (),
                              id_key: str = "id",
                              name_key: str = "name") -> list:
    """Filter a list of organization objects to those the caller may see.

    Tenant isolation for READ: a tenant-admin listing organizations should only
    get back their own, not every tenant's. A superadmin gets the full list.

    Each org is matched by its id OR name against the caller's org claim, so this
    works whether the token carries ids or names. Non-dict entries are dropped
    defensively.
    """
    if is_superadmin(token_info, superadmin_roles):
        return orgs
    accessible = extract_org_ids(token_info)
    out = []
    for org in orgs:
        if not isinstance(org, dict):
            continue
        oid = org.get(id_key)
        oname = org.get(name_key)
        if (oid is not None and str(oid) in accessible) or \
           (oname is not None and str(oname) in accessible):
            out.append(org)
    return out
