# rotate_secret.py
# Rotates the Auth0 client secret AND updates the Keycloak Auth0 IdP config with
# the new value in one atomic-ish flow, so the broker keeps working after rotation.
#
# Rotating an Auth0 secret invalidates the old one immediately. If you rotate
# without updating Keycloak's stored secret, logins through the Auth0 IdP break.
# This script does both, in the correct order, and updates the local .env too.
#
# Run with:   python rotate_secret.py
# Requires:   the M2M app to have 'update:client_keys' and 'read:clients' scopes.

from __future__ import annotations

import logging
import os

import requests

from auth0_connect import Auth0Connect, get_keycloak_admin_token

try:
    from dotenv import load_dotenv, set_key
    load_dotenv()
    _HAVE_DOTENV = True
except ImportError:
    _HAVE_DOTENV = False

logger = logging.getLogger(__name__)


def update_keycloak_idp_secret(
    keycloak_url: str,
    realm_name: str,
    admin_token: str,
    alias: str,
    new_secret: str,
) -> None:
    """
    Update the clientSecret in an existing Keycloak OIDC identity provider.

    Uses GET (fetch current config) then PUT (write back with new secret), because
    Keycloak's IdP update replaces the whole representation — a partial PUT would
    drop the other config fields.
    """
    base = keycloak_url.rstrip("/")
    last_error = ""
    for prefix in ("/admin/realms", "/auth/admin/realms"):
        url = f"{base}{prefix}/{realm_name}/identity-provider/instances/{alias}"
        headers = {
            "content-type":  "application/json",
            "authorization": f"Bearer {admin_token}",
        }
        try:
            get_resp = requests.get(url, headers=headers, timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Keycloak IdP fetch failed: {exc}") from exc

        if get_resp.status_code == 404:
            last_error = get_resp.text
            if prefix == "/admin/realms":
                continue
            break
        if not get_resp.ok:
            raise RuntimeError(
                f"Keycloak IdP fetch returned {get_resp.status_code}: {get_resp.text}"
            )

        idp = get_resp.json()
        idp.setdefault("config", {})
        idp["config"]["clientSecret"] = new_secret  # merge: keep all other config

        try:
            put_resp = requests.put(url, headers=headers, json=idp, timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Keycloak IdP update failed: {exc}") from exc

        if put_resp.status_code in (200, 204):
            logger.info("Keycloak IdP '%s' secret updated in realm '%s'", alias, realm_name)
            return
        raise RuntimeError(
            f"Keycloak IdP update returned {put_resp.status_code}: {put_resp.text}"
        )

    raise RuntimeError(
        f"Keycloak IdP '{alias}' not found in realm '{realm_name}' at {base}. "
        f"Last error: {last_error}"
    )


def rotate_and_sync(
    auth0: Auth0Connect,
    keycloak_url: str,
    realm_name: str,
    keycloak_admin_token: str,
    idp_alias: str = "auth0",
    update_env: bool = True,
) -> str:
    """
    Rotate the Auth0 client secret, then update the Keycloak IdP (and optionally
    the local .env) with the new value. Returns the new secret.
    """
    new_secret = auth0.rotate_client_secret(auth0.client_id)

    update_keycloak_idp_secret(
        keycloak_url, realm_name, keycloak_admin_token, idp_alias, new_secret
    )

    if update_env and _HAVE_DOTENV:
        env_path = os.environ.get("DOTENV_PATH", ".env")
        if os.path.exists(env_path):
            set_key(env_path, "AUTH0_CLIENT_SECRET", new_secret)
            logger.info("Updated AUTH0_CLIENT_SECRET in %s", env_path)
        else:
            logger.warning("No .env at %s — update AUTH0_CLIENT_SECRET manually.", env_path)
    elif update_env:
        logger.warning("python-dotenv not installed — update AUTH0_CLIENT_SECRET manually.")

    return new_secret


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    domain        = os.environ["AUTH0_DOMAIN"]
    client_id     = os.environ["AUTH0_CLIENT_ID"]
    client_secret = os.environ["AUTH0_CLIENT_SECRET"]

    keycloak_url        = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
    keycloak_admin_user = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
    keycloak_admin_pass = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
    realm_name          = os.environ.get("KEYCLOAK_REALM", "Premkey")

    auth0 = Auth0Connect(domain, client_id, client_secret)
    kc_token = get_keycloak_admin_token(keycloak_url, keycloak_admin_user, keycloak_admin_pass)

    new_secret = rotate_and_sync(auth0, keycloak_url, realm_name, kc_token)
    logger.info("Rotation complete. New secret (first 4 chars): %s...", new_secret[:4])
    logger.info("If running elsewhere, update AUTH0_CLIENT_SECRET in those environments too.")


if __name__ == "__main__":
    main()
