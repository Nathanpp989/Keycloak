# Tests for role-based authorization (authz.py) and its enforcement in main.
import contextlib
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import authz
import main


# ── Unit tests for the authz logic ──────────────────────────────────────────
def test_extract_realm_roles():
    ti = {"realm_access": {"roles": ["tenant-admin", "user"]}}
    assert authz.extract_roles(ti) == {"tenant-admin", "user"}

def test_extract_client_roles():
    ti = {"resource_access": {"myclient": {"roles": ["editor"]}}}
    assert authz.extract_roles(ti) == {"editor"}

def test_extract_merges_realm_and_client():
    ti = {"realm_access": {"roles": ["a"]},
          "resource_access": {"c1": {"roles": ["b"]}, "c2": {"roles": ["c"]}}}
    assert authz.extract_roles(ti) == {"a", "b", "c"}

def test_extract_handles_missing_sections():
    assert authz.extract_roles({}) == set()

def test_extract_handles_malformed_sections():
    # None, wrong types -> empty, never raises
    assert authz.extract_roles({"realm_access": None}) == set()
    assert authz.extract_roles({"realm_access": {"roles": "notalist"}}) == set()
    assert authz.extract_roles({"resource_access": "nope"}) == set()

def test_user_has_any_role():
    ti = {"realm_access": {"roles": ["tenant-admin"]}}
    assert authz.user_has_any_role(ti, ["tenant-admin"])
    assert authz.user_has_any_role(ti, ["superadmin", "tenant-admin"])
    assert not authz.user_has_any_role(ti, ["superadmin"])

def test_require_role_needs_at_least_one():
    factory = authz.make_require_role(lambda: {})
    with pytest.raises(ValueError):
        factory()  # no roles given


# ── Integration: enforcement through the real app ───────────────────────────
@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "x")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "x")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "x")
    monkeypatch.setenv("KEY_DIR", "/tmp/authztest")

    @contextlib.asynccontextmanager
    async def _noop(app):
        yield
    monkeypatch.setattr(main.app.router, "lifespan_context", _noop)
    with TestClient(main.app) as c:
        yield c


_HDR = {"Authorization": "Bearer faketoken"}

def _introspect_returning(roles):
    def fake(token):
        return {"active": True, "realm_access": {"roles": roles}, "sub": "u1"}
    return fake


def test_admin_endpoint_denies_without_role(client):
    # Valid token, but no admin role -> 403 on an admin write endpoint.
    with patch.object(main, "_introspect_token", _introspect_returning(["user"])):
        r = client.post("/groups", json={"name": "g"}, headers=_HDR)
    assert r.status_code == 403

def test_admin_endpoint_allows_with_role(client):
    # Valid token WITH admin role -> not 403 (clears auth; may hit body/downstream).
    with patch.object(main, "_introspect_token",
                      _introspect_returning(["user", "tenant-admin"])):
        r = client.post("/groups", json={"name": "g"}, headers=_HDR)
    assert r.status_code != 403

def test_read_endpoint_open_to_any_authenticated_user(client):
    # Read endpoints keep plain authentication — no admin role required.
    with patch.object(main, "_introspect_token", _introspect_returning(["user"])):
        r = client.get("/users/lookup?email=a@b.com", headers=_HDR)
    assert r.status_code != 403

def test_delete_org_denied_without_role(client):
    # The most destructive endpoint must be gated.
    with patch.object(main, "_introspect_token", _introspect_returning(["user"])):
        r = client.delete("/organizations/some-id", headers=_HDR)
    assert r.status_code == 403

def test_403_names_required_role(client):
    # The 403 detail should name the required role to aid debugging.
    with patch.object(main, "_introspect_token", _introspect_returning(["user"])):
        r = client.post("/groups", json={"name": "g"}, headers=_HDR)
    assert "tenant-admin" in r.json().get("detail", "")


# ── Tenant scoping ──────────────────────────────────────────────────────────
def test_extract_org_ids_list():
    assert authz.extract_org_ids({"organizations": ["a", "b"]}) == {"a", "b"}

def test_extract_org_ids_string():
    assert authz.extract_org_ids({"organization": "a"}) == {"a"}

def test_extract_org_ids_auth0_dict():
    # Auth0 organizations claim is a dict keyed by org id
    assert authz.extract_org_ids({"organizations": {"a": {}, "b": {}}}) == {"a", "b"}

def test_extract_org_ids_list_of_dicts():
    assert authz.extract_org_ids({"orgs": [{"id": "a"}, {"name": "b"}]}) == {"a", "b"}

def test_extract_org_ids_missing():
    assert authz.extract_org_ids({}) == set()
    assert authz.extract_org_ids({"organization": None}) == set()

def test_user_can_access_org():
    ti = {"organizations": ["org_a"]}
    assert authz.user_can_access_org(ti, "org_a")
    assert not authz.user_can_access_org(ti, "org_b")

def test_enforce_org_access_denies_cross_tenant():
    from fastapi import HTTPException
    ti = {"organizations": ["org_a"]}
    with pytest.raises(HTTPException) as ei:
        authz.enforce_org_access(ti, "org_b")
    assert ei.value.status_code == 403

def test_enforce_org_access_allows_own_tenant():
    ti = {"organizations": ["org_a"]}
    authz.enforce_org_access(ti, "org_a")  # must not raise

def test_enforce_org_access_superadmin_bypasses():
    ti = {"organizations": ["org_a"], "realm_access": {"roles": ["platform-admin"]}}
    # superadmin can touch an org they don't belong to
    authz.enforce_org_access(ti, "org_z", superadmin_roles=["platform-admin"])

def test_enforce_org_access_non_superadmin_still_scoped():
    from fastapi import HTTPException
    ti = {"organizations": ["org_a"], "realm_access": {"roles": ["tenant-admin"]}}
    # having a non-superadmin role does NOT bypass scoping
    with pytest.raises(HTTPException):
        authz.enforce_org_access(ti, "org_z", superadmin_roles=["platform-admin"])


# ── Tenant scoping through the app ──────────────────────────────────────────
def _introspect_org(orgs, roles=("tenant-admin",)):
    def fake(token):
        return {"active": True, "realm_access": {"roles": list(roles)},
                "organizations": list(orgs)}
    return fake


def test_delete_own_org_allowed(client):
    from unittest.mock import MagicMock
    mgr = MagicMock()
    mgr.auth0_orgs = MagicMock()
    with patch.object(main, "_introspect_token", _introspect_org(["org_a"])), \
         patch.object(main, "user_manager", mgr):
        r = client.delete("/organizations/org_a", headers=_HDR)
    assert r.status_code != 403

def test_delete_other_tenant_org_denied(client):
    from unittest.mock import MagicMock
    mgr = MagicMock()
    mgr.auth0_orgs = MagicMock()
    with patch.object(main, "_introspect_token", _introspect_org(["org_a"])), \
         patch.object(main, "user_manager", mgr):
        r = client.delete("/organizations/org_b", headers=_HDR)
    assert r.status_code == 403
    assert "org_b" in r.json().get("detail", "")

def test_update_other_tenant_org_denied(client):
    from unittest.mock import MagicMock
    mgr = MagicMock()
    mgr.auth0_orgs = MagicMock()
    with patch.object(main, "_introspect_token", _introspect_org(["org_a"])), \
         patch.object(main, "user_manager", mgr):
        r = client.patch("/organizations/org_b", data={"display_name": "X"},
                         headers=_HDR)
    assert r.status_code == 403


# ── Org-list read filtering ─────────────────────────────────────────────────
def test_filter_orgs_to_caller_tenants():
    orgs = [{"id": "a", "name": "A"}, {"id": "b", "name": "B"},
            {"id": "c", "name": "C"}]
    ti = {"organizations": ["a", "c"]}
    result = authz.filter_orgs_to_accessible(ti, orgs)
    assert [o["id"] for o in result] == ["a", "c"]

def test_filter_orgs_matches_by_name_too():
    orgs = [{"id": "id1", "name": "Acme"}, {"id": "id2", "name": "Beta"}]
    ti = {"organizations": ["Acme"]}   # claim carries names, not ids
    result = authz.filter_orgs_to_accessible(ti, orgs)
    assert [o["id"] for o in result] == ["id1"]

def test_filter_orgs_superadmin_sees_all():
    orgs = [{"id": "a"}, {"id": "b"}]
    ti = {"organizations": ["a"], "realm_access": {"roles": ["super"]}}
    result = authz.filter_orgs_to_accessible(ti, orgs, superadmin_roles=["super"])
    assert len(result) == 2

def test_filter_orgs_empty_when_no_membership():
    orgs = [{"id": "a"}, {"id": "b"}]
    result = authz.filter_orgs_to_accessible({}, orgs)
    assert result == []

def test_filter_orgs_drops_non_dict_entries():
    orgs = [{"id": "a"}, "garbage", None, {"id": "b"}]
    ti = {"organizations": ["a", "b"]}
    result = authz.filter_orgs_to_accessible(ti, orgs)
    assert [o["id"] for o in result] == ["a", "b"]

def test_is_superadmin():
    ti = {"realm_access": {"roles": ["platform-admin"]}}
    assert authz.is_superadmin(ti, ["platform-admin"])
    assert not authz.is_superadmin(ti, ["other"])
    assert not authz.is_superadmin(ti, [])   # no superadmin role configured


def test_list_orgs_endpoint_filters_to_tenant(client):
    from unittest.mock import MagicMock
    mgr = MagicMock()
    mgr.auth0_orgs.list_organizations.return_value = [
        {"id": "org_a", "name": "A"}, {"id": "org_b", "name": "B"}]
    with patch.object(main, "_introspect_token", _introspect_org(["org_a"])), \
         patch.object(main, "user_manager", mgr):
        r = client.get("/organizations", headers=_HDR)
    assert r.status_code == 200
    ids = [o["id"] for o in r.json()["organizations"]]
    assert ids == ["org_a"]   # org_b NOT leaked


# ── Shared-org (user lookup) scoping ────────────────────────────────────────
def test_shares_org_true_when_overlap():
    ti = {"organizations": ["org_a", "org_b"]}
    assert authz.shares_org(ti, ["org_b", "org_c"])

def test_shares_org_false_when_disjoint():
    ti = {"organizations": ["org_a"]}
    assert not authz.shares_org(ti, ["org_x", "org_y"])

def test_shares_org_superadmin_always_true():
    ti = {"organizations": [], "realm_access": {"roles": ["super"]}}
    assert authz.shares_org(ti, ["anything"], superadmin_roles=["super"])

def test_enforce_shared_org_denies_disjoint():
    from fastapi import HTTPException
    ti = {"organizations": ["org_a"]}
    with pytest.raises(HTTPException) as ei:
        authz.enforce_shared_org(ti, ["org_z"])
    assert ei.value.status_code == 403

def test_enforce_shared_org_allows_overlap():
    ti = {"organizations": ["org_a"]}
    authz.enforce_shared_org(ti, ["org_a", "org_b"])  # no raise


# ── id-vs-name org matching ─────────────────────────────────────────────────
def test_user_can_access_org_matches_any_ref():
    ti = {"organizations": ["org_id_123"]}
    # token carries the id; we pass both name and id -> matches on id
    assert authz.user_can_access_org(ti, "Acme", "org_id_123")
    # token carries id; only the name passed -> no match
    assert not authz.user_can_access_org(ti, "Acme")

def test_enforce_org_access_multi_ref():
    from fastapi import HTTPException
    ti = {"organizations": ["the_id"]}
    # passing both name and id, token has id -> allowed
    authz.enforce_org_access(ti, "TheName", "the_id")
    # neither matches -> denied
    with pytest.raises(HTTPException):
        authz.enforce_org_access(ti, "OtherName", "other_id")


def test_filter_orgs_handles_none_list():
    # A None org list (degenerate input) must not crash — returns empty, and
    # consistently so for both scoped and superadmin callers.
    ti = {"organizations": ["a"]}
    ti_super = {"realm_access": {"roles": ["super"]}}
    assert authz.filter_orgs_to_accessible(ti, None) == []
    assert authz.filter_orgs_to_accessible(
        ti_super, None, superadmin_roles=["super"]) == []


# ── Scope extraction + enforcement (M2M scope restriction) ──────────────────
def test_extract_scopes_splits_space_delimited():
    assert authz.extract_scopes({"scope": "openid orders:read profile"}) == {
        "openid", "orders:read", "profile"}

def test_extract_scopes_missing_or_malformed():
    assert authz.extract_scopes({}) == set()
    assert authz.extract_scopes({"scope": None}) == set()

def test_extract_audiences_string_and_list():
    assert authz.extract_audiences({"aud": "api"}) == {"api"}
    assert authz.extract_audiences({"aud": ["api", "admin"]}) == {"api", "admin"}
    assert authz.extract_audiences({}) == set()

def test_token_has_scope_requires_all():
    ti = {"scope": "openid orders:read"}
    assert authz.token_has_scope(ti, ["orders:read"])
    assert not authz.token_has_scope(ti, ["orders:read", "orders:write"])

def test_enforce_scope_denies_missing():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        authz.enforce_scope({"scope": "openid"}, "orders:write")
    assert ei.value.status_code == 403
    assert "orders:write" in ei.value.detail

def test_enforce_scope_allows_present():
    authz.enforce_scope({"scope": "openid orders:read"}, "orders:read")  # no raise

def test_enforce_scope_no_requirement_is_noop():
    authz.enforce_scope({"scope": ""})  # no required scopes -> no raise

def test_enforce_scope_multiple_required():
    ti = {"scope": "openid orders:read orders:write"}
    authz.enforce_scope(ti, ["orders:read", "orders:write"])  # no raise
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        authz.enforce_scope(ti, ["orders:read", "orders:delete"])

