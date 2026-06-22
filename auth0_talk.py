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
        return resp.json()

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
    kc_token = get_keycloak_admin_token(keycloak_url, keycloak_admin_user, keycloak_admin_pass)
    kc = KeycloakAdminAPI(keycloak_url, kc_token, realm)

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
