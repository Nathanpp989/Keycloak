"""Sync Auth0 Organizations into Keycloak groups — one-way (Auth0 -> Keycloak).

Auth0 is the source of truth for B2B organizations; this mirrors each org as a
Keycloak group so the broker's existing group-based tenant scoping applies to
them. The mapping is Auth0 Organization -> Keycloak group, with the org's id and
names stored as group attributes so the two stay linked.

Conflict rule: ADOPT. If a Keycloak group with the org's name already exists, it
is linked to the org (attributes set) rather than duplicated or errored — so a
group you created by hand becomes the managed mirror on first sync.

This is deliberately one-way: two systems both editing the same record is a much
harder problem (conflict resolution, loops) and isn't needed to give Auth0 orgs a
home in the broker's authz model.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

GROUP_SOURCE = "auth0-sync"


def _org_attributes(org: dict) -> dict:
    """Keycloak group attributes that link the group to its Auth0 org. Keycloak
    stores attributes as lists of strings."""
    return {
        "auth0_org_id": [str(org.get("id", ""))],
        "auth0_org_name": [str(org.get("name", ""))],
        "auth0_org_display_name": [str(org.get("display_name") or org.get("name", ""))],
        "source": [GROUP_SOURCE],
    }


def _all_organizations(orgs_api, page_size: int = 50) -> list:
    """Fetch every Auth0 org, paging until a short page."""
    out: list = []
    page = 0
    while True:
        batch = orgs_api.list_organizations(page=page, per_page=page_size)
        out.extend(batch)
        if len(batch) < page_size:
            return out
        page += 1


def sync_organizations(orgs_api, admin, *, dry_run: bool = False) -> dict:
    """Mirror all Auth0 orgs into Keycloak groups (one-way, adopt-and-link).

    orgs_api: an Auth0OrganizationsAPI (from auth0_talk).
    admin:    a KeycloakAdmin.
    dry_run:  compute the plan without writing to Keycloak.

    Returns {created:[names], adopted:[names], failed:[names], total:int,
    dry_run:bool}.
    """
    orgs = _all_organizations(orgs_api)
    # Index existing groups by name (id + name is all we need to find/adopt).
    existing = {g.get("name"): g for g in admin.get_groups()}
    summary: dict = {"created": [], "adopted": [], "failed": [],
                     "total": len(orgs), "dry_run": dry_run}
    for org in orgs:
        name = org.get("name") or ""
        if not name:
            logger.warning("skipping Auth0 org with no name: id=%s", org.get("id"))
            continue
        attrs = _org_attributes(org)
        try:
            if name in existing:
                if not dry_run:
                    admin.update_group(existing[name]["id"], {"attributes": attrs})
                summary["adopted"].append(name)
            else:
                if not dry_run:
                    admin.create_group({"name": name, "attributes": attrs})
                summary["created"].append(name)
        except Exception as exc:  # noqa: BLE001 — one bad org shouldn't abort the rest
            logger.error("sync failed for org '%s': %s", name, exc)
            summary["failed"].append(name)
    return summary


def run_sync(*, dry_run: bool = False) -> dict:
    """Build the Auth0 + Keycloak clients from env/broker config and sync.
    Used by the /admin/org-sync endpoint and the live-test script."""
    import os
    from auth0_talk import Auth0Connect, Auth0OrganizationsAPI
    from main import _build_keycloak_admin   # lazy: avoid import cycle

    auth0 = Auth0Connect(os.environ["AUTH0_DOMAIN"],
                         os.environ["AUTH0_CLIENT_ID"],
                         os.environ["AUTH0_CLIENT_SECRET"])
    orgs_api = Auth0OrganizationsAPI(auth0)
    admin = _build_keycloak_admin()
    return sync_organizations(orgs_api, admin, dry_run=dry_run)
