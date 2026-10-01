"""Tests for auth0_org_sync — Auth0 orgs -> Keycloak groups (one-way, adopt-and-link),
exercised with a mocked Auth0OrganizationsAPI and a mocked KeycloakAdmin."""
from unittest.mock import MagicMock

import auth0_org_sync as s


def _orgs_api(orgs):
    api = MagicMock()
    api.list_organizations.return_value = orgs   # <50 -> single page
    return api


def test_creates_new_groups():
    api = _orgs_api([{"id": "org_1", "name": "acme", "display_name": "Acme"}])
    admin = MagicMock(); admin.get_groups.return_value = []
    out = s.sync_organizations(api, admin)
    assert out["created"] == ["acme"] and out["adopted"] == [] and out["total"] == 1
    payload = admin.create_group.call_args[0][0]
    assert payload["name"] == "acme"
    assert payload["attributes"]["auth0_org_id"] == ["org_1"]
    assert payload["attributes"]["source"] == ["auth0-sync"]


def test_adopts_existing_group():
    api = _orgs_api([{"id": "org_2", "name": "globex", "display_name": "Globex"}])
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "kc-grp-9", "name": "globex"}]
    out = s.sync_organizations(api, admin)
    assert out["adopted"] == ["globex"] and out["created"] == []
    admin.create_group.assert_not_called()
    gid, payload = admin.update_group.call_args[0]
    assert gid == "kc-grp-9" and payload["attributes"]["auth0_org_id"] == ["org_2"]


def test_dry_run_writes_nothing():
    api = _orgs_api([{"id": "o", "name": "acme"}])
    admin = MagicMock(); admin.get_groups.return_value = []
    out = s.sync_organizations(api, admin, dry_run=True)
    assert out["created"] == ["acme"] and out["dry_run"] is True
    admin.create_group.assert_not_called()
    admin.update_group.assert_not_called()


def test_one_failure_does_not_abort_the_rest():
    api = _orgs_api([{"id": "1", "name": "good1"},
                     {"id": "2", "name": "bad"},
                     {"id": "3", "name": "good2"}])
    admin = MagicMock(); admin.get_groups.return_value = []

    def create(payload):
        if payload["name"] == "bad":
            raise RuntimeError("keycloak boom")
    admin.create_group.side_effect = create
    out = s.sync_organizations(api, admin)
    assert out["failed"] == ["bad"]
    assert set(out["created"]) == {"good1", "good2"}


def test_paginates_until_short_page():
    api = MagicMock()
    page0 = [{"id": str(i), "name": f"o{i}"} for i in range(50)]
    page1 = [{"id": "50", "name": "o50"}]
    api.list_organizations.side_effect = [page0, page1]
    admin = MagicMock(); admin.get_groups.return_value = []
    out = s.sync_organizations(api, admin)
    assert out["total"] == 51 and api.list_organizations.call_count == 2
