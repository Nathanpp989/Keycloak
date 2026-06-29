# auth0_type.py
# Detects which system(s) a username already belongs to (Keycloak vs Auth0),
# derives a username from an email address, and creates a new user in BOTH
# Keycloak and Auth0. Builds on auth0_connect.py and auth0_talk.py.

from __future__ import annotations

import logging
import os
import re
import secrets
from enum import Enum

from auth0_connect import Auth0Connect, get_keycloak_admin_token, _require_env
from auth0_talk import KeycloakAdminAPI, Auth0UsersAPI

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

    def __init__(self, keycloak: KeycloakAdminAPI, auth0_users: Auth0UsersAPI):
        self.keycloak = keycloak
        self.auth0_users = auth0_users

    # ── detection ──────────────────────────────────────────────
    def _in_keycloak(self, username: str, email: str) -> bool:
        """
        Check whether a user already exists in Keycloak.

        N1 FIX: match on BOTH username and email. The username passed in is
        derived with a random suffix, so checking username alone would never
        detect an existing account for the same email — leading to duplicate
        Keycloak users on repeated registration. Email is the stable identity.
        """
        import requests
        # Email is the stable key; check it first.
        resp = requests.get(
            self.keycloak._users_url(),
            headers=self.keycloak.headers,
            params={"email": email, "exact": "true"},
            timeout=10,
        )
        resp.raise_for_status()
        if len(resp.json()) > 0:
            return True
        # Fall back to an exact username match (covers username-only accounts).
        resp = requests.get(
            self.keycloak._users_url(),
            headers=self.keycloak.headers,
            params={"username": username, "exact": "true"},
            timeout=10,
        )
        resp.raise_for_status()
        return len(resp.json()) > 0

    def _in_auth0(self, email: str) -> bool:
        # Auth0 lookup by email via the users-by-email endpoint
        import requests
        base = f"https://{self.auth0_users.auth0.domain}/api/v2/users-by-email"
        resp = requests.get(
            base,
            headers=self.auth0_users.headers,
            params={"email": email},
            timeout=10,
        )
        if resp.status_code == 403:
            raise RuntimeError(
                "403 from Auth0 users-by-email — the token is missing the "
                "'read:users' scope. Grant it to your M2M app and retry."
            )
        resp.raise_for_status()
        return len(resp.json()) > 0

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

    manager = UserManager(keycloak, auth0_users)

    # Example: add a new user from an email address
    target_email = os.environ.get("NEW_USER_EMAIL", "new.person@example.com")
    result = manager.add_user(target_email)

    logger.info("Result: %s", result)
    logger.info(
        "Created username '%s' (Keycloak id=%s, Auth0 id=%s)",
        result["username"], result["keycloak_id"], result["auth0_id"],
    )


if __name__ == "__main__":
    main()
