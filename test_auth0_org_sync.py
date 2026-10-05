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


def test_adopts_existing_group_and_preserves_attributes():
    api = _orgs_api([{"id": "org_2", "name": "globex", "display_name": "Globex"}])
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "kc-grp-9", "name": "globex"}]
    # the pre-existing group already has an unrelated attribute
    admin.get_group.return_value = {"id": "kc-grp-9", "name": "globex",
                                    "attributes": {"existing": ["keep-me"]}}
    out = s.sync_organizations(api, admin)
    assert out["adopted"] == ["globex"] and out["created"] == []
    admin.create_group.assert_not_called()
    gid, payload = admin.update_group.call_args[0]
    assert gid == "kc-grp-9"
    # auth0 attrs added AND the pre-existing attr preserved (merge, not replace)
    assert payload["attributes"]["auth0_org_id"] == ["org_2"]
    assert payload["attributes"]["existing"] == ["keep-me"]


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


# ── member sync (org membership -> Keycloak group membership) ─────────────────

def _member_api(orgs, members_by_org):
    api = MagicMock()
    api.list_organizations.return_value = orgs
    api.list_members.side_effect = (
        lambda org_id, page=0, per_page=50:
        members_by_org.get(org_id, []) if page == 0 else [])
    return api


def test_member_sync_adds_matched_user():
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"email": "a@x.com", "user_id": "auth0|1"}]})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = []
    admin.get_users.return_value = [{"id": "kc-u1", "email": "a@x.com"}]
    out = s.sync_org_members(api, admin)
    assert out["added"] == ["a@x.com"]
    admin.group_user_add.assert_called_once_with("kc-u1", "g1")
    admin.get_users.assert_called_with({"email": "a@x.com", "exact": True})


def test_member_sync_already_member():
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"email": "a@x.com"}]})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = [{"id": "kc-u1"}]
    admin.get_users.return_value = [{"id": "kc-u1"}]
    out = s.sync_org_members(api, admin)
    assert out["already_member"] == ["a@x.com"] and out["added"] == []
    admin.group_user_add.assert_not_called()


def test_member_sync_unmatched_user():
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"email": "ghost@x.com"}]})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = []
    admin.get_users.return_value = []          # no Keycloak user at that email
    out = s.sync_org_members(api, admin)
    assert out["unmatched"] == ["ghost@x.com"] and out["added"] == []
    admin.group_user_add.assert_not_called()


def test_member_sync_no_group_for_org():
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"email": "a@x.com"}]})
    admin = MagicMock()
    admin.get_groups.return_value = []          # acme has no group yet
    out = s.sync_org_members(api, admin)
    assert out["no_group"] == ["acme"]
    admin.get_group_members.assert_not_called()


def test_member_sync_dry_run_writes_nothing():
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"email": "a@x.com"}]})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = []
    admin.get_users.return_value = [{"id": "kc-u1"}]
    out = s.sync_org_members(api, admin, dry_run=True)
    assert out["added"] == ["a@x.com"] and out["dry_run"] is True
    admin.group_user_add.assert_not_called()


def test_member_sync_is_add_only():
    # A user in the Keycloak group but NOT in the Auth0 org must NOT be removed.
    api = _member_api([{"id": "org_1", "name": "acme"}], {"org_1": []})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = [{"id": "kc-leftover"}]
    out = s.sync_org_members(api, admin)
    assert out["added"] == []
    admin.group_user_remove.assert_not_called()   # never removes


# ── membership reconciliation (remove_absent) ─────────────────────────────────

def test_reconcile_removes_departed_member():
    # Auth0 org has a@x.com; the KC group has a@x.com AND a departed b@x.com.
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"email": "a@x.com"}]})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = [{"id": "kc-a", "email": "a@x.com"},
                                            {"id": "kc-b", "email": "b@x.com"}]
    admin.get_users.return_value = [{"id": "kc-a"}]      # a@x.com -> kc-a
    out = s.sync_org_members(api, admin, remove_absent=True)
    assert out["removed"] == ["b@x.com"] and out["added"] == []
    admin.group_user_remove.assert_called_once_with("kc-b", "g1")


def test_reconcile_off_removes_nobody():
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"email": "a@x.com"}]})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = [{"id": "kc-a", "email": "a@x.com"},
                                            {"id": "kc-b", "email": "b@x.com"}]
    admin.get_users.return_value = [{"id": "kc-a"}]
    out = s.sync_org_members(api, admin)                 # default: add-only
    assert out["removed"] == []
    admin.group_user_remove.assert_not_called()


def test_reconcile_dry_run_reports_but_does_not_remove():
    api = _member_api([{"id": "org_1", "name": "acme"}], {"org_1": []})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = [{"id": "kc-x", "email": "x@x.com"}]
    out = s.sync_org_members(api, admin, remove_absent=True, dry_run=True)
    assert out["removed"] == ["x@x.com"] and out["dry_run"] is True
    admin.group_user_remove.assert_not_called()


def test_reconcile_keeps_current_member():
    # the only KC member is also the only Auth0 member -> not removed
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"email": "a@x.com"}]})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = [{"id": "kc-a", "email": "a@x.com"}]
    admin.get_users.return_value = [{"id": "kc-a"}]
    out = s.sync_org_members(api, admin, remove_absent=True)
    assert out["removed"] == [] and out["already_member"] == ["a@x.com"]
    admin.group_user_remove.assert_not_called()


# ── edge cases surfaced by coverage ───────────────────────────────────────────

def test_sync_skips_org_with_no_name():
    # an Auth0 org with no name must be skipped, not crash or create a "" group
    api = _orgs_api([{"id": "org_x"}, {"id": "org_1", "name": "acme"}])
    admin = MagicMock(); admin.get_groups.return_value = []
    out = s.sync_organizations(api, admin)
    assert out["created"] == ["acme"]              # only the named one
    # create_group never called with an empty name
    for call in admin.create_group.call_args_list:
        assert call[0][0]["name"] != ""


def test_member_sync_skips_member_with_no_email():
    api = _member_api([{"id": "org_1", "name": "acme"}],
                      {"org_1": [{"user_id": "auth0|noemail"}, {"email": "a@x.com"}]})
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = []
    admin.get_users.return_value = [{"id": "kc-a"}]
    out = s.sync_org_members(api, admin)
    # the emailless member is silently skipped; only a@x.com processed
    assert out["added"] == ["a@x.com"] and out["unmatched"] == []


def test_member_sync_paginates_members():
    # 50 on page 0 forces a page 1 fetch (covers the _all_members loop)
    page0 = [{"email": f"u{i}@x.com"} for i in range(50)]
    page1 = [{"email": "u50@x.com"}]
    api = MagicMock()
    api.list_organizations.return_value = [{"id": "org_1", "name": "acme"}]
    api.list_members.side_effect = lambda org_id, page=0, per_page=50: (
        page0 if page == 0 else page1 if page == 1 else [])
    admin = MagicMock()
    admin.get_groups.return_value = [{"id": "g1", "name": "acme"}]
    admin.get_group_members.return_value = []
    admin.get_users.return_value = []     # all unmatched (we only count the paging)
    out = s.sync_org_members(api, admin)
    assert len(out["unmatched"]) == 51     # 50 + 1 across two pages
    assert api.list_members.call_count == 2


def test_run_sync_wiring(monkeypatch):
    # covers run_sync's client construction + delegation without real I/O
    import auth0_org_sync as mod
    import auth0_talk
    fake_admin = MagicMock(); fake_admin.get_groups.return_value = []
    monkeypatch.setenv("AUTH0_DOMAIN", "d"); monkeypatch.setenv("AUTH0_CLIENT_ID", "i")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "s")
    monkeypatch.setattr(auth0_talk, "Auth0Connect", lambda *a, **k: object())
    fake_orgs = MagicMock(); fake_orgs.list_organizations.return_value = []
    monkeypatch.setattr(auth0_talk, "Auth0OrganizationsAPI", lambda a: fake_orgs)
    import main
    monkeypatch.setattr(main, "_build_keycloak_admin", lambda: fake_admin)
    out = mod.run_sync(dry_run=True)
    assert out["total"] == 0 and out["dry_run"] is True
