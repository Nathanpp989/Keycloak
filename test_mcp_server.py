"""Tests for the MCP server's broker handlers. Skipped if the optional mcp SDK
isn't installed (it's not a broker dependency). The handlers are pure (client in,
dict out), so they're exercised with a mocked httpx client — no live broker."""
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp")          # optional component; skip if SDK absent
import mcp_server as m               # noqa: E402


def _client(status=200, body=None):
    resp = MagicMock(status_code=status, is_success=(200 <= status < 300))
    resp.json.return_value = {} if body is None else body
    c = MagicMock()
    c.get.return_value = resp
    c.post.return_value = resp
    c.delete.return_value = resp
    return c


def test_result_normalizes_json():
    c = _client(200, {"status": "alive"})
    out = m._h_health(c)
    assert out == {"status": 200, "ok": True, "body": {"status": "alive"}}
    c.get.assert_called_once_with("/health/live")


def test_result_handles_non_json():
    resp = MagicMock(status_code=503, is_success=False, text="down")
    resp.json.side_effect = ValueError("not json")
    c = MagicMock(); c.get.return_value = resp
    out = m._h_health(c)
    assert out["ok"] is False and out["body"] == {"text": "down"}


def test_introspect_posts_token():
    c = _client(200, {"active": True})
    out = m._h_introspect(c, "tok123")
    assert out["body"]["active"] is True
    c.post.assert_called_once_with("/token/introspect", data={"token": "tok123"})


def test_create_api_key_passes_fields():
    c = _client(200, {"id": "k1", "api_key": "ak_..."})
    m._h_create_key(c, "svc", "read,write", 3600)
    c.post.assert_called_once_with("/admin/api-keys",
                                   data={"name": "svc", "scopes": "read,write",
                                         "ttl_seconds": 3600})


def test_revoke_and_sessions_build_paths():
    c = _client(200, {"revoked": True})
    m._h_revoke_key(c, "k9")
    c.delete.assert_called_once_with("/admin/api-keys/k9")
    c2 = _client(200, {"sessions": []})
    m._h_sessions(c2, "u7")
    c2.get.assert_called_once_with("/admin/users/u7/sessions")


def test_sync_orgs_sends_dry_run_lowercase():
    c = _client(200, {"created": []})
    m._h_sync_orgs(c, True)
    c.post.assert_called_once_with("/admin/org-sync", data={"dry_run": "true"})
    c2 = _client(200, {"created": ["x"]})
    m._h_sync_orgs(c2, False)
    c2.post.assert_called_once_with("/admin/org-sync", data={"dry_run": "false"})


def test_tools_are_registered():
    # the @server.tool() wrappers exist and are callable
    for name in ("broker_health", "introspect_token", "list_api_keys",
                 "create_api_key", "revoke_api_key", "list_user_sessions",
                 "sync_organizations"):
        assert callable(getattr(m, name))
