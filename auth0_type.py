#!/usr/bin/env python3
# auth0_type.py
# Detects which system(s) a username already belongs to (Keycloak vs Auth0),
# derives a username from an email address, and creates a new user in BOTH
# Keycloak and Auth0. Builds on auth0_connect.py and auth0_talk.py.

from __future__ import annotations

import logging
import requests
import os
import re
import secrets
from enum import Enum

from auth0_connect import Auth0Connect, get_keycloak_admin_token, _require_env
from auth0_talk import KeycloakAdminAPI, Auth0UsersAPI, Auth0AuthzExtensionAPI, Auth0OrganizationsAPI

logger = logging.getLogger(__name__)


class UserSystem(str, Enum):
    """Which system(s) a username currently exists in."""
    KEYCLOAK = "keycloak"
    AUTH0    = "auth0"
    BOTH     = "both"
    NEITHER  = "neither"


def derive_username_from_email(email: str) -> str:
    """
    Build a username from the local part of an email (before the '@'),
    sanitised to safe characters, with a short random suffix to avoid
    collisions (since the local part is not globally unique).

    'John.Doe+test@example.com' -> 'john.doe-3f9a2c'
    """
    if "@" not in email:
        raise ValueError(f"Not a valid email address: {email!r}")
    local_part = email.split("@", 1)[0].lower()
    # Keep letters, digits, dot, underscore, hyphen; collapse anything else
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", local_part).strip("-._")
    if not cleaned:
        cleaned = "user"
    suffix = secrets.token_hex(3)  # 6 hex chars
    return f"{cleaned}-{suffix}"


def generate_password(length: int = 16) -> str:
    """Generate a strong random password meeting common complexity rules."""
    # token_urlsafe gives letters+digits+-_ ; ensure it satisfies typical policies
    base = secrets.token_urlsafe(length)
    # Guarantee at least one digit and one uppercase to satisfy strict policies
    return f"A1{base}"


class UserManager:
    """Detects user presence across systems and creates users in both."""

    def __init__(self, keycloak: KeycloakAdminAPI, auth0_users: Auth0UsersAPI,
                 auth0_authz=None, auth0_orgs=None):
        self.keycloak = keycloak
        self.auth0_users = auth0_users
        # Optional Auth0AuthzExtensionAPI; group lookup is skipped if not provided.
        self.auth0_authz = auth0_authz
        # Optional Auth0OrganizationsAPI; org operations require it.
        self.auth0_orgs = auth0_orgs

    # ── id resolution ──────────────────────────────────────────
    def _keycloak_user_id(self, username: str, email: str) -> str | None:
        """Return the Keycloak user id for an email (preferred) or username."""
        for params in ({"email": email, "exact": "true"},
                       {"username": username, "exact": "true"}):
            resp = requests.get(
                self.keycloak._users_url(),
                headers=self.keycloak.headers,
                params=params,
                timeout=10,
            )
            resp.raise_for_status()
            results = resp.json()
            if results:
                return results[0].get("id")
        return None

    def _auth0_user_id(self, email: str) -> str | None:
        """Return the Auth0 user_id for an email, or None if not found."""
        base = f"https://{self.auth0_users.auth0.domain}/api/v2/users-by-email"
        resp = requests.get(
            base, headers=self.auth0_users.headers,
            params={"email": email}, timeout=10,
        )
        if resp.status_code == 403:
            raise RuntimeError(
                "403 from Auth0 users-by-email — the token is missing the "
                "'read:users' scope. Grant it to your M2M app and retry."
            )
        resp.raise_for_status()
        results = resp.json()
        return results[0].get("user_id") if results else None

    # ── detection ──────────────────────────────────────────────
    def _in_keycloak(self, username: str, email: str) -> bool:
        """
        Check whether a user already exists in Keycloak (by email, then username).
        N1 FIX: email is the stable identity; the derived username has a random
        suffix so username-only checks would miss existing accounts.
        """
        return self._keycloak_user_id(username, email) is not None

    def _in_auth0(self, email: str) -> bool:
        return self._auth0_user_id(email) is not None

    def determine_user_system(self, username: str, email: str) -> UserSystem:
        """Detect which system(s) the user already belongs to."""
        in_kc = self._in_keycloak(username, email)
        in_a0 = self._in_auth0(email)
        if in_kc and in_a0:
            return UserSystem.BOTH
        if in_kc:
            return UserSystem.KEYCLOAK
        if in_a0:
            return UserSystem.AUTH0
        return UserSystem.NEITHER

    # ── membership (groups + roles) ────────────────────────────
    def get_membership(self, username: str, email: str) -> dict:
        """
        Collect a user's group membership and roles from BOTH systems and
        correlate them.

        Returns:
        {
          "username": ..., "email": ...,
          "keycloak": {
              "found": bool,
              "groups": [{"name","path","is_subgroup"}],
              "roles":  {"realm": [...], "client": [...]},
          },
          "auth0": {
              "found": bool,
              "groups": [{"name","is_subgroup"}],   # [] if no Authz Extension
              "roles":  [...],
          },
          "correlation": {
              "groups_in_both":      [names present in both systems],
              "groups_keycloak_only":[...],
              "groups_auth0_only":   [...],
              "roles_in_both":       [...],
              "roles_keycloak_only": [...],
              "roles_auth0_only":    [...],
          }
        }
        Group/role correlation is by case-insensitive name match.
        """
        result: dict = {
            "username": username,
            "email": email,
            "keycloak": {"found": False, "groups": [], "roles": {"realm": [], "client": []}},
            "auth0": {"found": False, "groups": [], "roles": []},
            "correlation": {},
        }

        # --- Keycloak side ---
        kc_id = self._keycloak_user_id(username, email)
        if kc_id:
            result["keycloak"]["found"] = True
            result["keycloak"]["groups"] = self.keycloak.get_user_groups(kc_id)
            result["keycloak"]["roles"] = self.keycloak.get_user_roles(kc_id)

        # --- Auth0 side ---
        a0_id = self._auth0_user_id(email)
        if a0_id:
            result["auth0"]["found"] = True
            result["auth0"]["roles"] = self.auth0_users.get_user_roles(a0_id)
            if self.auth0_authz is not None:
                result["auth0"]["groups"] = self.auth0_authz.get_user_groups(a0_id)

        # --- Correlation (case-insensitive name match) ---
        kc_group_names = {g["name"].lower() for g in result["keycloak"]["groups"]}
        a0_group_names = {g["name"].lower() for g in result["auth0"]["groups"]}
        kc_role_names = {r.lower() for r in
                         result["keycloak"]["roles"]["realm"] + result["keycloak"]["roles"]["client"]}
        a0_role_names = {r.lower() for r in result["auth0"]["roles"]}

        result["correlation"] = {
            "groups_in_both":       sorted(kc_group_names & a0_group_names),
            "groups_keycloak_only": sorted(kc_group_names - a0_group_names),
            "groups_auth0_only":    sorted(a0_group_names - kc_group_names),
            "roles_in_both":        sorted(kc_role_names & a0_role_names),
            "roles_keycloak_only":  sorted(kc_role_names - a0_role_names),
            "roles_auth0_only":     sorted(a0_role_names - kc_role_names),
        }
        return result

    # ── group management (cross-system) ────────────────────────
    def create_group(self, name: str, parent_path: str | None = None) -> dict:
        """
        Create a group (or subgroup) in Keycloak, and in the Auth0 Authorization
        Extension if configured. For Keycloak subgroups, parent_path is the
        parent's full path (e.g. '/finance'); the parent must already exist.
        Returns {"keycloak_id": ..., "auth0_group": ...}.
        """
        result: dict = {"keycloak_id": None, "auth0_group": None}

        # Keycloak
        parent_id = None
        if parent_path:
            parent = self.keycloak.find_group_by_path(parent_path)
            if not parent:
                raise ValueError(f"Keycloak parent group '{parent_path}' not found")
            parent_id = parent.get("id")
        result["keycloak_id"] = self.keycloak.create_group(name, parent_id=parent_id)

        # Auth0 Authorization Extension (optional)
        if self.auth0_authz is not None:
            parent_group_id = None
            if parent_path:
                parent_name = parent_path.strip("/").split("/")[-1]
                parent_group = self.auth0_authz.find_group_by_name(parent_name)
                parent_group_id = (parent_group or {}).get("_id") or (parent_group or {}).get("id")
            result["auth0_group"] = self.auth0_authz.create_group(
                name, parent_group_id=parent_group_id
            )
        return result

    def set_group_membership(self, username: str, email: str, group_name: str,
                             add: bool = True) -> dict:
        """
        Add (add=True) or revoke (add=False) a user's membership in a group named
        `group_name`, in whichever systems the user and group exist.
        Returns a per-system summary of what changed.
        """
        summary: dict = {"keycloak": "skipped", "auth0": "skipped"}

        # Keycloak
        kc_uid = self._keycloak_user_id(username, email)
        if kc_uid:
            group = self.keycloak.find_group_by_path("/" + group_name.strip("/"))
            # Fall back: a bare name may be a top-level group
            if not group:
                group = next((g for g in self.keycloak.list_groups()
                              if g.get("name", "").lower() == group_name.lower()), None)
            if group:
                gid = group.get("id")
                if add:
                    self.keycloak.add_user_to_group(kc_uid, gid)
                    summary["keycloak"] = "added"
                else:
                    self.keycloak.remove_user_from_group(kc_uid, gid)
                    summary["keycloak"] = "removed"
            else:
                summary["keycloak"] = "group-not-found"
        else:
            summary["keycloak"] = "user-not-found"

        # Auth0 Authorization Extension
        if self.auth0_authz is not None:
            a0_uid = self._auth0_user_id(email)
            if a0_uid:
                # Flat group names in the extension; match the leaf of any path.
                ext_name = group_name.strip("/").split("/")[-1]
                group = self.auth0_authz.find_group_by_name(ext_name)
                if group:
                    gid = group.get("_id") or group.get("id")
                    if add:
                        self.auth0_authz.add_user_to_group(gid, a0_uid)
                        summary["auth0"] = "added"
                    else:
                        self.auth0_authz.remove_user_from_group(gid, a0_uid)
                        summary["auth0"] = "removed"
                else:
                    summary["auth0"] = "group-not-found"
            else:
                summary["auth0"] = "user-not-found"
        return summary

    def set_role(self, username: str, email: str, role_name: str,
                 assign: bool = True) -> dict:
        """
        Assign (assign=True) or revoke (assign=False) a role named `role_name`
        for a user, in whichever systems the user exists. In Keycloak this maps
        to a realm role; in Auth0 to an Authorization Core role.
        Returns a per-system summary: assigned / revoked / role-not-found /
        user-not-found.
        """
        summary: dict = {"keycloak": "skipped", "auth0": "skipped"}

        # Keycloak (realm role)
        kc_uid = self._keycloak_user_id(username, email)
        if kc_uid:
            try:
                if assign:
                    self.keycloak.assign_realm_role(kc_uid, role_name)
                    summary["keycloak"] = "assigned"
                else:
                    self.keycloak.revoke_realm_role(kc_uid, role_name)
                    summary["keycloak"] = "revoked"
            except ValueError:
                summary["keycloak"] = "role-not-found"
        else:
            summary["keycloak"] = "user-not-found"

        # Auth0 (Authorization Core role)
        a0_uid = self._auth0_user_id(email)
        if a0_uid:
            try:
                if assign:
                    self.auth0_users.assign_role(a0_uid, role_name)
                    summary["auth0"] = "assigned"
                else:
                    self.auth0_users.revoke_role(a0_uid, role_name)
                    summary["auth0"] = "revoked"
            except ValueError:
                summary["auth0"] = "role-not-found"
        else:
            summary["auth0"] = "user-not-found"
        return summary

    # ── account lifecycle (cross-system pairs) ──────────────────
    def _resolve_ids(self, username: str, email: str) -> tuple[str | None, str | None]:
        """Resolve (keycloak_id, auth0_id) for a user; either may be None."""
        return self._keycloak_user_id(username, email), self._auth0_user_id(email)

    def set_user_metadata(self, username: str, email: str, metadata: dict) -> dict:
        """
        Pair 1: write key/values to Keycloak user attributes AND Auth0
        app_metadata. Returns a per-system status summary.
        """
        summary = {"keycloak": "user-not-found", "auth0": "user-not-found"}
        kc_id, a0_id = self._resolve_ids(username, email)
        if kc_id:
            self.keycloak.set_user_attributes(kc_id, metadata)
            summary["keycloak"] = "updated"
        if a0_id:
            self.auth0_users.set_user_metadata(a0_id, app_metadata=metadata)
            summary["auth0"] = "updated"
        return summary

    def set_user_active(self, username: str, email: str, active: bool) -> dict:
        """
        Pair 2: enable/disable the account everywhere. Keycloak uses enabled=X,
        Auth0 uses blocked=not X.
        """
        summary = {"keycloak": "user-not-found", "auth0": "user-not-found"}
        kc_id, a0_id = self._resolve_ids(username, email)
        if kc_id:
            self.keycloak.set_user_enabled(kc_id, active)
            summary["keycloak"] = "enabled" if active else "disabled"
        if a0_id:
            self.auth0_users.set_user_blocked(a0_id, not active)
            summary["auth0"] = "unblocked" if active else "blocked"
        return summary

    def set_email_verified(self, username: str, email: str,
                           verified: bool = True) -> dict:
        """Pair 3a: set the verified flag directly in both systems."""
        summary = {"keycloak": "user-not-found", "auth0": "user-not-found"}
        kc_id, a0_id = self._resolve_ids(username, email)
        if kc_id:
            self.keycloak.set_email_verified(kc_id, verified)
            summary["keycloak"] = "set"
        if a0_id:
            self.auth0_users.set_email_verified(a0_id, verified)
            summary["auth0"] = "set"
        return summary

    def send_verification_email(self, username: str, email: str) -> dict:
        """Pair 3b: trigger each system's own verification email."""
        summary = {"keycloak": "user-not-found", "auth0": "user-not-found"}
        kc_id, a0_id = self._resolve_ids(username, email)
        if kc_id:
            self.keycloak.send_verify_email(kc_id)
            summary["keycloak"] = "sent"
        if a0_id:
            self.auth0_users.send_verification_email(a0_id)
            summary["auth0"] = "sent"
        return summary

    def trigger_password_reset(self, username: str, email: str) -> dict:
        """
        Pair 4: start a password reset in both systems. Keycloak emails the user
        directly (realm SMTP required); Auth0 returns a ticket URL, included in
        the summary so the caller can deliver it.
        """
        summary: dict = {"keycloak": "user-not-found", "auth0": "user-not-found",
                         "auth0_ticket": None}
        kc_id, a0_id = self._resolve_ids(username, email)
        if kc_id:
            self.keycloak.send_reset_password_email(kc_id)
            summary["keycloak"] = "email-sent"
        if a0_id:
            summary["auth0_ticket"] = self.auth0_users.create_password_reset_ticket(a0_id)
            summary["auth0"] = "ticket-created"
        return summary

    def logout_everywhere(self, username: str, email: str) -> dict:
        """
        Pair 5: kill the user's sessions in both systems. Keycloak invalidates
        sessions; Auth0 deletes sessions AND revokes grants/refresh tokens.
        """
        summary = {"keycloak": "user-not-found", "auth0": "user-not-found"}
        kc_id, a0_id = self._resolve_ids(username, email)
        if kc_id:
            self.keycloak.logout_user(kc_id)
            summary["keycloak"] = "logged-out"
        if a0_id:
            self.auth0_users.delete_sessions(a0_id)
            self.auth0_users.revoke_grants(a0_id)
            summary["auth0"] = "sessions-and-grants-revoked"
        return summary

    # ── Auth0 organization membership ──────────────────────────
    def get_user_org_refs(self, email: str) -> list:
        """Return the org ids AND names a user belongs to (for tenant-scoping).

        Resolves email -> Auth0 user id -> organizations, returning both each
        org's id and name so a caller's claim matches regardless of which form
        it carries. Returns [] if orgs are unavailable or the user has none —
        the caller treats an empty result as "no shared tenant".
        """
        if self.auth0_orgs is None:
            return []
        try:
            a0_uid = self._auth0_user_id(email)
        except Exception:  # noqa: BLE001
            return []
        if a0_uid is None:
            return []
        refs: list = []
        for org in self.auth0_orgs.get_user_organizations(a0_uid):
            if isinstance(org, dict):
                if org.get("id"):
                    refs.append(str(org["id"]))
                if org.get("name"):
                    refs.append(str(org["name"]))
        return refs

    def set_organization_membership(self, email: str, org_name: str,
                                    add: bool = True) -> str:
        """
        Add or remove a user (by email) from an Auth0 organization (by name).
        Returns a status string: added / removed / user-not-found /
        org-not-found / no-orgs-api.
        """
        if self.auth0_orgs is None:
            return "no-orgs-api"
        org = self.auth0_orgs.get_organization_by_name(org_name)
        if org is None:
            return "org-not-found"
        a0_uid = self._auth0_user_id(email)
        if a0_uid is None:
            return "user-not-found"
        org_id = org.get("id")
        if add:
            self.auth0_orgs.add_members(org_id, [a0_uid])
            return "added"
        self.auth0_orgs.remove_members(org_id, [a0_uid])
        return "removed"

    # ── group update / delete (cross-system) ───────────────────
    def update_group(self, group_path_or_name: str, new_name: str) -> dict:
        """
        Rename a group in Keycloak (by path or top-level name) and, if the Authz
        Extension is configured, in Auth0. Returns a per-system status.
        """
        summary: dict = {"keycloak": "skipped", "auth0": "skipped"}

        group = self.keycloak.find_group_by_path("/" + group_path_or_name.strip("/"))
        if not group:
            group = next((g for g in self.keycloak.list_groups()
                          if g.get("name", "").lower() == group_path_or_name.lower()), None)
        if group:
            self.keycloak.update_group(group.get("id"), name=new_name)
            summary["keycloak"] = "updated"
        else:
            summary["keycloak"] = "group-not-found"

        if self.auth0_authz is not None:
            # The Authz Extension has flat group names; for a Keycloak subgroup
            # path like 'finance/billing', match the leaf name ('billing').
            ext_name = group_path_or_name.strip("/").split("/")[-1]
            ext_group = self.auth0_authz.find_group_by_name(ext_name)
            if ext_group:
                gid = ext_group.get("_id") or ext_group.get("id")
                self.auth0_authz.update_group(gid, name=new_name)
                summary["auth0"] = "updated"
            else:
                summary["auth0"] = "group-not-found"
        return summary

    def delete_group(self, group_path_or_name: str) -> dict:
        """
        Delete a group in Keycloak (by path or top-level name) and, if configured,
        in the Auth0 Authz Extension. Returns a per-system status.
        """
        summary: dict = {"keycloak": "skipped", "auth0": "skipped"}

        group = self.keycloak.find_group_by_path("/" + group_path_or_name.strip("/"))
        if not group:
            group = next((g for g in self.keycloak.list_groups()
                          if g.get("name", "").lower() == group_path_or_name.lower()), None)
        if group:
            self.keycloak.delete_group(group.get("id"))
            summary["keycloak"] = "deleted"
        else:
            summary["keycloak"] = "group-not-found"

        if self.auth0_authz is not None:
            ext_name = group_path_or_name.strip("/").split("/")[-1]
            ext_group = self.auth0_authz.find_group_by_name(ext_name)
            if ext_group:
                gid = ext_group.get("_id") or ext_group.get("id")
                self.auth0_authz.delete_group(gid)
                summary["auth0"] = "deleted"
            else:
                summary["auth0"] = "group-not-found"
        return summary

    # ── creation ───────────────────────────────────────────────
    def add_user(self, email: str, password: str | None = None,
                 username: str | None = None) -> dict:
        """
        Create a user in BOTH Keycloak and Auth0.
        - username defaults to one derived from the email
        - password defaults to a generated strong password
        Returns a summary dict with what was created and where.
        """
        username = username or derive_username_from_email(email)
        password = password or generate_password()

        existing = self.determine_user_system(username, email)
        logger.info("Pre-check for %s / %s: %s", username, email, existing.value)

        summary: dict = {
            "username": username,
            "email": email,
            "pre_existing": existing.value,
            "keycloak_id": None,
            "auth0_id": None,
        }

        # Keycloak
        if existing in (UserSystem.KEYCLOAK, UserSystem.BOTH):
            logger.info("User already in Keycloak; skipping Keycloak creation")
        else:
            summary["keycloak_id"] = self.keycloak.create_user(username, email, password)

        # Auth0
        if existing in (UserSystem.AUTH0, UserSystem.BOTH):
            logger.info("User already in Auth0; skipping Auth0 creation")
        else:
            created = self.auth0_users.create_user(email, password)
            summary["auth0_id"] = created.get("user_id")

        return summary


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

    # Token-getter so KeycloakAdminAPI always uses a fresh admin token
    # (Keycloak admin tokens expire in ~60s).
    def kc_token_getter() -> str:
        return get_keycloak_admin_token(keycloak_url, keycloak_admin_user, keycloak_admin_pass)

    keycloak = KeycloakAdminAPI(keycloak_url, kc_token_getter, realm)

    auth0 = Auth0Connect(env["AUTH0_DOMAIN"], env["AUTH0_CLIENT_ID"], env["AUTH0_CLIENT_SECRET"])
    auth0_users = Auth0UsersAPI(auth0)

    # Optional: Auth0 Authorization Extension for groups (separate API).
    authz = None
    authz_url = os.environ.get("AUTH0_AUTHZ_EXTENSION_URL")
    if authz_url:
        authz = Auth0AuthzExtensionAPI(auth0, authz_url)

    # Organizations are always available via the Management API.
    orgs = Auth0OrganizationsAPI(auth0)

    manager = UserManager(keycloak, auth0_users, auth0_authz=authz, auth0_orgs=orgs)

    # Example: add a new user from an email address
    target_email = os.environ.get("NEW_USER_EMAIL", "new.person@example.com")
    result = manager.add_user(target_email)

    logger.info("Result: %s", result)
    logger.info(
        "Created username '%s' (Keycloak id=%s, Auth0 id=%s)",
        result["username"], result["keycloak_id"], result["auth0_id"],
    )

    # Show correlated group + role membership across both systems
    membership = manager.get_membership(result["username"], target_email)
    logger.info("Membership: %s", membership)


if __name__ == "__main__":
    main()
