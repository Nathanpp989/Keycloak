# auth0_talk.py
# Uses the helpers in auth0_connect.py to talk to BOTH APIs:
#   - Keycloak Admin API (manage users in the Keycloak realm)
#   - Auth0 Management API (manage users in Auth0)
#
# Keycloak and Auth0 require DIFFERENT tokens from DIFFERENT issuers:
#   - a fresh Keycloak admin token  -> Keycloak Admin API
#   - the Auth0 M2M token           -> Auth0 Management API
# They are not interchangeable.

from __future__ import annotations

import logging
import os

import requests

from auth0_connect import (
    Auth0Connect,
    get_keycloak_admin_token,
    _require_env,
)

logger = logging.getLogger(__name__)


def _explain_403(resp: requests.Response, needed_scope: str) -> None:
    """Turn an opaque 403 into a clear, actionable message about missing scope."""
    if resp.status_code == 403:
        raise RuntimeError(
            f"403 Forbidden from {resp.url}. The access token is missing the "
            f"'{needed_scope}' scope. Grant it to your application and retry."
        )


def _as_list(payload, wrapper_key: str) -> list:
    """
    Normalise an Auth0 list response. Auth0 endpoints return EITHER a bare list
    OR a paginated object like {"<wrapper_key>": [...], "total": N, ...} when
    include_totals is set. This returns the list either way, preventing a crash
    where iterating a dict would yield its string keys.
    """
    if isinstance(payload, dict):
        return payload.get(wrapper_key, [])
    return payload if isinstance(payload, list) else []


# ──────────────────────────────────────────────
# Keycloak Admin API — user management
# ──────────────────────────────────────────────
class KeycloakAdminAPI:
    def __init__(self, keycloak_url: str, admin_token, realm: str):
        """
        admin_token may be either:
          - a string (a fixed token — simplest, but expires in ~60s), or
          - a zero-arg callable returning a fresh token string (recommended for
            long-running apps, since Keycloak admin tokens expire quickly).
        """
        self.base = keycloak_url.rstrip("/")
        self.realm = realm
        self._token_source = admin_token

    @property
    def headers(self) -> dict:
        # Resolve the token fresh on each access so a long-lived server never
        # uses an expired admin token (Keycloak tokens live ~60s).
        token = self._token_source() if callable(self._token_source) else self._token_source
        return {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}",
        }

    def _users_url(self, user_id: str | None = None) -> str:
        url = f"{self.base}/admin/realms/{self.realm}/users"
        return f"{url}/{user_id}" if user_id else url

    def list_users(self, first: int = 0, max_results: int = 100) -> list:
        """
        List users in the realm. J1 FIX: Keycloak paginates (default 100).
        Pass first/max_results to page through; this returns one page.
        """
        resp = requests.get(
            self._users_url(),
            headers=self.headers,
            params={"first": first, "max": max_results},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    def read_user(self, user_id: str) -> dict:
        resp = requests.get(self._users_url(user_id), headers=self.headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        logger.error("Failed to read Keycloak user: %d %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return {}

    def create_user(self, username: str, email: str, password: str) -> str | None:
        """Create a Keycloak user. Returns the new user's id (from Location header)."""
        payload = {
            "username": username,
            "email":    email,
            "enabled":  True,
            "credentials": [
                {"type": "password", "value": password, "temporary": False}
            ],
        }
        resp = requests.post(self._users_url(), headers=self.headers, json=payload, timeout=10)
        if resp.status_code == 201:
            location = resp.headers.get("Location", "")
            user_id = location.rstrip("/").split("/")[-1] if location else None
            logger.info("Keycloak user '%s' created (id=%s)", username, user_id)
            return user_id
        if resp.status_code == 409:
            logger.info("Keycloak user '%s' already exists", username)
            return None
        logger.error("Failed to create Keycloak user: %d %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return None

    def update_user(self, user_id: str, **fields) -> None:
        """
        Update a Keycloak user. J3 FIX: Keycloak's PUT expects the FULL user
        representation, so we read-modify-write: fetch the existing user, merge
        the changed fields, then PUT the merged object. Sending only the changed
        fields can blank out other attributes.
        """
        current = self.read_user(user_id)
        current.update(fields)
        resp = requests.put(self._users_url(user_id), headers=self.headers, json=current, timeout=10)
        if resp.status_code in (200, 204):
            logger.info("Keycloak user %s updated", user_id)
        else:
            logger.error("Failed to update Keycloak user: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def delete_user(self, user_id: str) -> None:
        resp = requests.delete(self._users_url(user_id), headers=self.headers, timeout=10)
        if resp.status_code == 204:
            logger.info("Keycloak user %s deleted", user_id)
        else:
            logger.error("Failed to delete Keycloak user: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def get_user_groups(self, user_id: str) -> list[dict]:
        """
        Return the groups a Keycloak user belongs to. Each entry is normalised to:
            {"name": str, "path": str, "is_subgroup": bool}
        Keycloak group paths look like "/parent/child"; a path with more than one
        segment means the group is a subgroup.
        """
        url = f"{self.base}/admin/realms/{self.realm}/users/{user_id}/groups"
        resp = requests.get(url, headers=self.headers, timeout=10)
        resp.raise_for_status()
        groups = []
        for g in resp.json():
            path = g.get("path", "/" + g.get("name", ""))
            # "/a" -> 1 segment (top-level); "/a/b" -> 2 segments (subgroup)
            depth = len([seg for seg in path.split("/") if seg])
            groups.append({
                "name": g.get("name", ""),
                "path": path,
                "is_subgroup": depth > 1,
            })
        return groups

    def get_user_roles(self, user_id: str) -> dict[str, list[str]]:
        """
        Return a Keycloak user's effective realm and client role names:
            {"realm": [...], "client": [...]}
        """
        base = f"{self.base}/admin/realms/{self.realm}/users/{user_id}/role-mappings"
        # Realm roles
        realm_resp = requests.get(f"{base}/realm", headers=self.headers, timeout=10)
        realm_resp.raise_for_status()
        realm_roles = [r.get("name", "") for r in realm_resp.json()]
        # Client roles (across all clients) — the composite view lists them
        client_roles: list[str] = []
        all_resp = requests.get(base, headers=self.headers, timeout=10)
        if all_resp.ok:
            data = all_resp.json()
            for client_entry in (data.get("clientMappings") or {}).values():
                client_roles.extend(m.get("name", "") for m in client_entry.get("mappings", []))
        return {"realm": realm_roles, "client": client_roles}

    def get_realm_role(self, role_name: str) -> dict | None:
        """Fetch a realm role's full representation (needed for assignment)."""
        url = f"{self.base}/admin/realms/{self.realm}/roles/{role_name}"
        resp = requests.get(url, headers=self.headers, timeout=10)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def assign_realm_role(self, user_id: str, role_name: str) -> None:
        """
        Assign a realm role to a user. Keycloak's role-mapping API requires the
        FULL role representation (id + name), so we look the role up first.
        Idempotent: assigning an already-assigned role is a no-op for Keycloak.
        """
        role = self.get_realm_role(role_name)
        if role is None:
            raise ValueError(f"Keycloak realm role '{role_name}' not found")
        url = f"{self.base}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm"
        resp = requests.post(url, headers=self.headers, json=[role], timeout=10)
        if resp.status_code in (204, 201):
            logger.info("Assigned realm role '%s' to user %s", role_name, user_id)
        else:
            logger.error("Failed to assign realm role: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def revoke_realm_role(self, user_id: str, role_name: str) -> None:
        """
        Revoke a realm role from a user. Like assignment, needs the full role
        representation. Idempotent: revoking an unassigned role is treated as done.
        """
        role = self.get_realm_role(role_name)
        if role is None:
            raise ValueError(f"Keycloak realm role '{role_name}' not found")
        url = f"{self.base}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm"
        resp = requests.delete(url, headers=self.headers, json=[role], timeout=10)
        if resp.status_code in (204, 404):
            logger.info("Revoked realm role '%s' from user %s", role_name, user_id)
        else:
            logger.error("Failed to revoke realm role: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    # ── group management ───────────────────────────────────────
    def _groups_url(self, group_id: str | None = None) -> str:
        url = f"{self.base}/admin/realms/{self.realm}/groups"
        return f"{url}/{group_id}" if group_id else url

    def list_groups(self) -> list[dict]:
        """Return top-level realm groups (each may contain subGroups)."""
        resp = requests.get(self._groups_url(), headers=self.headers, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def find_group_by_path(self, path: str) -> dict | None:
        """
        Find a group by its full path (e.g. '/finance/billing'), searching the
        nested group tree. Returns the group dict (with 'id') or None.
        """
        wanted = "/" + path.strip("/")

        def walk(groups: list[dict]) -> dict | None:
            for g in groups:
                if g.get("path") == wanted:
                    return g
                found = walk(g.get("subGroups") or [])
                if found:
                    return found
            return None

        return walk(self.list_groups())

    def create_group(self, name: str, parent_id: str | None = None) -> str:
        """
        Create a top-level group, or a subgroup if parent_id is given.
        Returns the new group's id. Idempotent: if the group already exists at
        that location, returns the existing id instead of failing.
        """
        if parent_id:
            url = f"{self._groups_url(parent_id)}/children"
        else:
            url = self._groups_url()
        resp = requests.post(url, headers=self.headers, json={"name": name}, timeout=10)
        if resp.status_code == 201:
            # Keycloak returns the new group's URL in Location
            location = resp.headers.get("Location", "")
            gid = location.rstrip("/").split("/")[-1] if location else None
            # Some Keycloak versions return the representation in the body instead
            if not gid:
                try:
                    gid = resp.json().get("id")
                except ValueError:
                    gid = None
            logger.info("Created Keycloak group '%s' (id=%s)", name, gid)
            return gid or ""
        if resp.status_code == 409:
            logger.info("Keycloak group '%s' already exists; reusing", name)
            # Resolve existing id: build the expected path
            if parent_id:
                parent = requests.get(self._groups_url(parent_id),
                                      headers=self.headers, timeout=10)
                parent.raise_for_status()
                existing = next((s for s in (parent.json().get("subGroups") or [])
                                 if s.get("name") == name), None)
            else:
                existing = next((g for g in self.list_groups() if g.get("name") == name), None)
            return existing.get("id", "") if existing else ""
        logger.error("Failed to create Keycloak group: %d %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return ""

    def add_user_to_group(self, user_id: str, group_id: str) -> None:
        """Add a Keycloak user to a group (idempotent)."""
        url = f"{self._users_url(user_id)}/groups/{group_id}"
        resp = requests.put(url, headers=self.headers, timeout=10)
        if resp.status_code in (201, 204):
            logger.info("Added Keycloak user %s to group %s", user_id, group_id)
        else:
            logger.error("Failed to add user to group: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def remove_user_from_group(self, user_id: str, group_id: str) -> None:
        """Revoke a Keycloak user's membership in a group (idempotent)."""
        url = f"{self._users_url(user_id)}/groups/{group_id}"
        resp = requests.delete(url, headers=self.headers, timeout=10)
        if resp.status_code in (204, 404):
            logger.info("Removed Keycloak user %s from group %s", user_id, group_id)
        else:
            logger.error("Failed to remove user from group: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def update_group(self, group_id: str, **fields) -> None:
        """
        Update a Keycloak group (e.g. rename via name=, or attributes=).
        Keycloak's group PUT replaces the representation, so we read-modify-write
        to avoid dropping other fields.
        """
        get_resp = requests.get(self._groups_url(group_id), headers=self.headers, timeout=10)
        get_resp.raise_for_status()
        current = get_resp.json()
        current.update(fields)
        resp = requests.put(self._groups_url(group_id), headers=self.headers,
                          json=current, timeout=10)
        if resp.status_code in (200, 204):
            logger.info("Updated Keycloak group %s", group_id)
        else:
            logger.error("Failed to update group: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def delete_group(self, group_id: str) -> None:
        """Delete a Keycloak group (and its subgroups). Idempotent on 404."""
        resp = requests.delete(self._groups_url(group_id), headers=self.headers, timeout=10)
        if resp.status_code in (204, 404):
            logger.info("Deleted Keycloak group %s", group_id)
        else:
            logger.error("Failed to delete group: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()


# ──────────────────────────────────────────────
# Auth0 Management API — user management
# Requires create:users / read:users / update:users / delete:users scopes.
# ──────────────────────────────────────────────
class Auth0UsersAPI:
    def __init__(self, auth0: Auth0Connect):
        self.auth0 = auth0
        self.base = f"https://{auth0.domain}/api/v2/users"

    @property
    def headers(self) -> dict:
        return {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {self.auth0.token}",
        }

    def list_users(self, page: int = 0, per_page: int = 50) -> list:
        """List Auth0 users. J1 FIX: Auth0 paginates (default 50). Returns one page."""
        resp = requests.get(
            self.base,
            headers=self.headers,
            params={"page": page, "per_page": per_page},
            timeout=10,
        )
        _explain_403(resp, "read:users")   # J2 FIX: clear message on missing scope
        resp.raise_for_status()
        return _as_list(resp.json(), "users")

    def create_user(self, email: str, password: str,
                    connection: str = "Username-Password-Authentication") -> dict:
        payload = {"email": email, "password": password, "connection": connection}
        resp = requests.post(self.base, headers=self.headers, json=payload, timeout=10)
        _explain_403(resp, "create:users")
        if resp.status_code == 201:
            logger.info("Auth0 user '%s' created", email)
            return resp.json()
        logger.error("Failed to create Auth0 user: %d %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return {}

    def update_user(self, user_id: str, **fields) -> dict:
        resp = requests.patch(f"{self.base}/{user_id}", headers=self.headers, json=fields, timeout=10)
        _explain_403(resp, "update:users")
        if resp.status_code == 200:
            logger.info("Auth0 user %s updated", user_id)
            return resp.json()
        logger.error("Failed to update Auth0 user: %d %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return {}

    def delete_user(self, user_id: str) -> None:
        resp = requests.delete(f"{self.base}/{user_id}", headers=self.headers, timeout=10)
        _explain_403(resp, "delete:users")
        if resp.status_code == 204:
            logger.info("Auth0 user %s deleted", user_id)
        else:
            logger.error("Failed to delete Auth0 user: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def get_user_roles(self, user_id: str) -> list[str]:
        """
        Return the names of Auth0 Authorization Core roles assigned to a user.
        Requires the 'read:roles' scope on the M2M application.
        """
        url = f"{self.base}/{user_id}/roles"
        resp = requests.get(url, headers=self.headers, timeout=10)
        _explain_403(resp, "read:roles")
        resp.raise_for_status()
        return [r.get("name", "") for r in _as_list(resp.json(), "roles")]

    def _roles_base(self) -> str:
        # Roles live under /api/v2/roles; self.base is .../api/v2/users
        return self.base.rsplit("/users", 1)[0] + "/roles"

    def get_role_by_name(self, role_name: str) -> dict | None:
        """
        Find an Auth0 role by name. Assignment needs the role ID, not the name.
        Requires the 'read:roles' scope.
        """
        resp = requests.get(self._roles_base(), headers=self.headers,
                            params={"name_filter": role_name}, timeout=10)
        _explain_403(resp, "read:roles")
        resp.raise_for_status()
        # name_filter is a substring match, so confirm an exact (case-insensitive) hit
        for r in _as_list(resp.json(), "roles"):
            if r.get("name", "").lower() == role_name.lower():
                return r
        return None

    def assign_role(self, user_id: str, role_name: str) -> None:
        """
        Assign an Auth0 role to a user. Requires 'update:users' (and 'read:roles'
        to resolve the role id). Idempotent on Auth0's side.
        """
        role = self.get_role_by_name(role_name)
        if role is None:
            raise ValueError(f"Auth0 role '{role_name}' not found")
        url = f"{self.base}/{user_id}/roles"
        resp = requests.post(url, headers=self.headers,
                            json={"roles": [role["id"]]}, timeout=10)
        _explain_403(resp, "update:users")
        if resp.status_code in (200, 204):
            logger.info("Assigned Auth0 role '%s' to user %s", role_name, user_id)
        else:
            logger.error("Failed to assign Auth0 role: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def revoke_role(self, user_id: str, role_name: str) -> None:
        """Revoke an Auth0 role from a user. Requires 'update:users' + 'read:roles'."""
        role = self.get_role_by_name(role_name)
        if role is None:
            raise ValueError(f"Auth0 role '{role_name}' not found")
        url = f"{self.base}/{user_id}/roles"
        resp = requests.delete(url, headers=self.headers,
                              json={"roles": [role["id"]]}, timeout=10)
        _explain_403(resp, "update:users")
        if resp.status_code in (200, 204):
            logger.info("Revoked Auth0 role '%s' from user %s", role_name, user_id)
        else:
            logger.error("Failed to revoke Auth0 role: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()


# ──────────────────────────────────────────────
# Auth0 Organizations (Management API)
# Requires scopes: read:organizations, create:organizations,
# update:organizations, delete:organizations, read:organization_members,
# create:organization_members, delete:organization_members.
# ──────────────────────────────────────────────
class Auth0OrganizationsAPI:
    def __init__(self, auth0: Auth0Connect):
        self.auth0 = auth0
        self.base = f"https://{auth0.domain}/api/v2/organizations"

    @property
    def headers(self) -> dict:
        return {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {self.auth0.token}",
        }

    def list_organizations(self, page: int = 0, per_page: int = 50) -> list:
        resp = requests.get(self.base, headers=self.headers,
                            params={"page": page, "per_page": per_page}, timeout=10)
        _explain_403(resp, "read:organizations")
        resp.raise_for_status()
        return _as_list(resp.json(), "organizations")

    def get_organization(self, org_id: str) -> dict:
        resp = requests.get(f"{self.base}/{org_id}", headers=self.headers, timeout=10)
        _explain_403(resp, "read:organizations")
        resp.raise_for_status()
        return resp.json()

    def get_organization_by_name(self, name: str) -> dict | None:
        """Look up an organization by its (unique) name via the name endpoint."""
        resp = requests.get(f"{self.base}/name/{name}", headers=self.headers, timeout=10)
        if resp.status_code == 404:
            return None
        _explain_403(resp, "read:organizations")
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def normalize_org_name(name: str) -> str:
        """
        Normalise a name to Auth0's organization-name rules: lowercase, only
        [a-z0-9_-], 3-50 chars, starting with an alphanumeric. Spaces and other
        characters become hyphens. Raises ValueError if the result is still
        invalid (e.g. too short after cleaning).
        """
        import re
        cleaned = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-_")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,49}", cleaned):
            raise ValueError(
                f"'{name}' cannot be converted to a valid Auth0 organization name "
                "(needs 3-50 chars of lowercase letters, digits, '-' or '_', "
                "starting with a letter or digit)."
            )
        return cleaned

    def create_organization(self, name: str, display_name: str | None = None) -> dict:
        """
        Get-or-create an organization. The `name` is normalised to Auth0's
        organization-name rules (lowercase, [a-z0-9_-]); the human-readable label
        is kept as display_name (defaulting to the original input). Names are
        unique in Auth0, so an existing org with the normalised name is reused.
        """
        norm = self.normalize_org_name(name)
        existing = self.get_organization_by_name(norm)
        if existing:
            logger.info("Auth0 organization '%s' already exists; reusing", norm)
            return existing
        payload = {"name": norm, "display_name": display_name or name}
        resp = requests.post(self.base, headers=self.headers, json=payload, timeout=10)
        _explain_403(resp, "create:organizations")
        if resp.status_code in (200, 201):
            logger.info("Created Auth0 organization '%s'", norm)
            return resp.json()
        logger.error("Failed to create organization: %d %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return {}

    def update_organization(self, org_id: str, **fields) -> dict:
        """Update an organization (e.g. display_name, branding, metadata)."""
        resp = requests.patch(f"{self.base}/{org_id}", headers=self.headers,
                             json=fields, timeout=10)
        _explain_403(resp, "update:organizations")
        if resp.status_code == 200:
            logger.info("Updated Auth0 organization %s", org_id)
            return resp.json()
        logger.error("Failed to update organization: %d %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return {}

    def delete_organization(self, org_id: str) -> None:
        """Delete an organization. Idempotent: a 404 is treated as already gone."""
        resp = requests.delete(f"{self.base}/{org_id}", headers=self.headers, timeout=10)
        _explain_403(resp, "delete:organizations")
        if resp.status_code in (204, 404):
            logger.info("Deleted Auth0 organization %s", org_id)
        else:
            logger.error("Failed to delete organization: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    # ── members ────────────────────────────────────────────────
    def list_members(self, org_id: str, page: int = 0, per_page: int = 50) -> list:
        resp = requests.get(f"{self.base}/{org_id}/members", headers=self.headers,
                            params={"page": page, "per_page": per_page}, timeout=10)
        _explain_403(resp, "read:organization_members")
        resp.raise_for_status()
        return _as_list(resp.json(), "members")

    def add_members(self, org_id: str, user_ids: list[str]) -> None:
        """Add one or more users to an organization."""
        resp = requests.post(f"{self.base}/{org_id}/members", headers=self.headers,
                            json={"members": user_ids}, timeout=10)
        _explain_403(resp, "create:organization_members")
        if resp.status_code in (200, 204):
            logger.info("Added %d member(s) to organization %s", len(user_ids), org_id)
        else:
            logger.error("Failed to add members: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()

    def remove_members(self, org_id: str, user_ids: list[str]) -> None:
        """Remove one or more users from an organization. Idempotent."""
        resp = requests.delete(f"{self.base}/{org_id}/members", headers=self.headers,
                             json={"members": user_ids}, timeout=10)
        _explain_403(resp, "delete:organization_members")
        if resp.status_code in (200, 204, 404):
            logger.info("Removed %d member(s) from organization %s", len(user_ids), org_id)
        else:
            logger.error("Failed to remove members: %d %s", resp.status_code, resp.text)
            resp.raise_for_status()


# ──────────────────────────────────────────────
# Auth0 Authorization Extension — groups
# The Authorization Extension is a SEPARATE service with its own base URL and
# its own access token (audience = "urn:auth0-authz-api"), NOT the Management
# API. Configure its URL via AUTH0_AUTHZ_EXTENSION_URL, e.g.
#   https://<tenant>.<region>.webtask.io/adf6e2f2b84784b57522e3b19dfc9201/api
# ──────────────────────────────────────────────
class Auth0AuthzExtensionAPI:
    def __init__(self, auth0: Auth0Connect, extension_url: str):
        self.auth0 = auth0
        self.base = extension_url.rstrip("/")

    def _token(self) -> str:
        """
        Get an access token for the Authorization Extension API. Its audience
        differs from the Management API, so we request it explicitly.
        """
        url = f"https://{self.auth0.domain}/oauth/token"
        payload = {
            "client_id":     self.auth0.client_id,
            "client_secret": self.auth0.client_secret,
            "audience":      "urn:auth0-authz-api",
            "grant_type":    "client_credentials",
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Authz Extension token request failed: {exc}") from exc
        if not resp.ok:
            raise RuntimeError(
                f"Authz Extension token returned {resp.status_code}: {resp.text}"
            )
        token = resp.json().get("access_token")
        if not token:
            raise RuntimeError("Authz Extension token response missing access_token")
        return token

    def get_user_groups(self, user_id: str) -> list[dict]:
        """
        Return the Authorization Extension groups for a user, normalised to:
            {"name": str, "is_subgroup": bool}
        The extension represents nesting via a 'parent' reference / nested array;
        a group that appears nested under another is treated as a subgroup.
        """
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {self._token()}",
        }
        url = f"{self.base}/users/{user_id}/groups"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Authz Extension groups request failed: {exc}") from exc
        if resp.status_code == 403:
            raise RuntimeError(
                "403 from the Auth0 Authorization Extension — the client is not "
                "authorised for the extension API."
            )
        resp.raise_for_status()
        groups = []
        for g in resp.json():
            # The extension marks nesting with a 'parent' field or by nesting.
            groups.append({
                "name": g.get("name", ""),
                "is_subgroup": bool(g.get("parent") or g.get("parentGroupId")),
            })
        return groups

    def _ext_headers(self) -> dict:
        return {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {self._token()}",
        }

    def _ext_request(self, method: str, path: str, **kwargs):
        url = f"{self.base}/{path.lstrip('/')}"
        try:
            resp = requests.request(method, url, headers=self._ext_headers(), timeout=10, **kwargs)
        except requests.RequestException as exc:
            raise RuntimeError(f"Authz Extension {method} {path} failed: {exc}") from exc
        if resp.status_code == 403:
            raise RuntimeError(
                "403 from the Auth0 Authorization Extension — the client is not "
                "authorised for the extension API."
            )
        return resp

    def list_groups(self) -> list[dict]:
        """Return all Authorization Extension groups (raw representations)."""
        resp = self._ext_request("GET", "groups")
        resp.raise_for_status()
        data = resp.json()
        # The extension returns either a list or {"groups": [...]}
        return data.get("groups", data) if isinstance(data, dict) else data

    def find_group_by_name(self, name: str) -> dict | None:
        """Find an extension group by name (case-insensitive). Returns it or None."""
        lname = name.lower()
        return next((g for g in self.list_groups()
                     if g.get("name", "").lower() == lname), None)

    def create_group(self, name: str, description: str = "",
                     parent_group_id: str | None = None) -> dict:
        """
        Create an Authorization Extension group, or a nested group if
        parent_group_id is given. Idempotent on name. Returns the group dict.
        """
        existing = self.find_group_by_name(name)
        if existing:
            logger.info("Authz Extension group '%s' already exists; reusing", name)
            return existing
        resp = self._ext_request("POST", "groups",
                                 json={"name": name, "description": description or name})
        resp.raise_for_status()
        group = resp.json()
        group_id = group.get("_id") or group.get("id")
        # Nest under a parent if requested. The extension nests by POSTing the
        # child id under the parent's /nested endpoint.
        if parent_group_id and group_id:
            nest = self._ext_request("PATCH", f"groups/{parent_group_id}/nested",
                                     json=[group_id])
            nest.raise_for_status()
            logger.info("Nested group '%s' under %s", name, parent_group_id)
        logger.info("Created Authz Extension group '%s' (id=%s)", name, group_id)
        return group

    def add_user_to_group(self, group_id: str, user_id: str) -> None:
        """Add a user to an Authorization Extension group (members endpoint)."""
        resp = self._ext_request("PATCH", f"groups/{group_id}/members", json=[user_id])
        resp.raise_for_status()
        logger.info("Added user %s to Authz Extension group %s", user_id, group_id)

    def remove_user_from_group(self, group_id: str, user_id: str) -> None:
        """Revoke a user's membership in an Authorization Extension group."""
        resp = self._ext_request("DELETE", f"groups/{group_id}/members", json=[user_id])
        if resp.status_code not in (200, 204):
            resp.raise_for_status()
        logger.info("Removed user %s from Authz Extension group %s", user_id, group_id)

    def update_group(self, group_id: str, name: str | None = None,
                     description: str | None = None) -> dict:
        """Update an Authorization Extension group's name/description."""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        resp = self._ext_request("PUT", f"groups/{group_id}", json=body)
        resp.raise_for_status()
        logger.info("Updated Authz Extension group %s", group_id)
        return resp.json() if resp.text else {}

    def delete_group(self, group_id: str) -> None:
        """Delete an Authorization Extension group. Idempotent on 404."""
        resp = self._ext_request("DELETE", f"groups/{group_id}")
        if resp.status_code not in (200, 204, 404):
            resp.raise_for_status()
        logger.info("Deleted Authz Extension group %s", group_id)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    env = _require_env("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET")

    keycloak_url        = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    keycloak_admin_user = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
    keycloak_admin_pass = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
    realm               = os.environ.get("KEYCLOAK_REALM", "Premkey")

    # ---- Keycloak side ----
    # Use a token-getter so KeycloakAdminAPI always has a FRESH admin token.
    # Keycloak admin tokens expire in ~60s; a one-time token would break later
    # calls in this script if it runs longer than that.
    def kc_token_getter() -> str:
        return get_keycloak_admin_token(keycloak_url, keycloak_admin_user, keycloak_admin_pass)

    kc = KeycloakAdminAPI(keycloak_url, kc_token_getter, realm)

    logger.info("Keycloak users in realm '%s' (first page): %d", realm, len(kc.list_users()))
    new_id = kc.create_user("newuser", "newemail@example.com", "ChangeMe123!")
    if new_id:
        kc.update_user(new_id, email="updatedemail@example.com")
        # kc.delete_user(new_id)   # uncomment to remove the user again

    # ---- Auth0 side ----
    auth0 = Auth0Connect(env["AUTH0_DOMAIN"], env["AUTH0_CLIENT_ID"], env["AUTH0_CLIENT_SECRET"])
    a0 = Auth0UsersAPI(auth0)

    logger.info("Auth0 users visible (first page): %d", len(a0.list_users()))
    # Requires create:users / update:users / delete:users scopes:
    # created = a0.create_user("user@example.com", "ChangeMe123!")
    # a0.update_user(created["user_id"], name="Updated Name")
    # a0.delete_user(created["user_id"])

    logger.info("Done.")


if __name__ == "__main__":
    main()
