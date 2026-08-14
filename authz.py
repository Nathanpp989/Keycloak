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
