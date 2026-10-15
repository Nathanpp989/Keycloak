"""Tests for the MCP server's broker handlers. Skipped if the optional mcp SDK
isn't installed (it's not a broker dependency). The handlers are pure (client in,
dict out), so they're exercised with a mocked httpx client — no live broker."""
from unittest.mock import MagicMock

import httpx
import pytest

pytest.importorskip("mcp")          # optional component; skip if SDK absent
import mcp_server as m               # noqa: E402


class _CM:
    """Minimal context manager returning a preset client, for monkeypatching
    mcp_server._client (which _safe_call uses as `with _client() as c:`)."""
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *a):
        return False


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


# ── resilience: broker unreachable / errors don't raise into the MCP client ──

def test_safe_call_turns_transport_error_into_clean_result(monkeypatch):
    # Broker down: the client's request raises a connect error. The tool must
    # return a readable error dict, not raise.
    c = MagicMock()
    c.get.side_effect = httpx.ConnectError("connection refused")
    monkeypatch.setattr(m, "_client", lambda: _CM(c))
    out = m.broker_health()
    assert out["ok"] is False
    assert out["status"] == 0
    assert "failed" in out["error"]
    assert "ConnectError" in out["error"]
    assert out["broker_url"] == m.BROKER_URL


def test_safe_call_handles_timeout(monkeypatch):
    c = MagicMock()
    c.get.side_effect = httpx.TimeoutException("timed out")
    monkeypatch.setattr(m, "_client", lambda: _CM(c))
    out = m.list_api_keys()
    assert out["ok"] is False and out["status"] == 0
    assert "TimeoutException" in out["error"]


def test_safe_call_handles_unexpected_error(monkeypatch):
    c = MagicMock()
    c.post.side_effect = RuntimeError("boom")
    monkeypatch.setattr(m, "_client", lambda: _CM(c))
    out = m.introspect_token("tok")
    assert out["ok"] is False and out["status"] == 0
    assert "unexpected error" in out["error"] and "RuntimeError" in out["error"]


def test_safe_call_success_path_through_tool(monkeypatch):
    resp = MagicMock(status_code=200, is_success=True)
    resp.json.return_value = {"status": "alive"}
    c = MagicMock(); c.get.return_value = resp
    monkeypatch.setattr(m, "_client", lambda: _CM(c))
    out = m.broker_health()
    assert out == {"status": 200, "ok": True, "body": {"status": "alive"}}


def test_version_present():
    assert isinstance(m.VERSION, str) and m.VERSION


def test_result_hints_on_401_without_token(monkeypatch):
    monkeypatch.setattr(m, "BROKER_TOKEN", "")
    resp = MagicMock(status_code=401, is_success=False)
    resp.json.return_value = {"detail": "unauthorized"}
    out = m._result(resp)
    assert out["ok"] is False and out["status"] == 401
    assert "BROKER_TOKEN" in out.get("hint", "")


def test_result_no_hint_when_token_present(monkeypatch):
    monkeypatch.setattr(m, "BROKER_TOKEN", "admin-bearer")
    resp = MagicMock(status_code=401, is_success=False)
    resp.json.return_value = {"detail": "unauthorized"}
    out = m._result(resp)
    assert "hint" not in out        # a real 401 with a token set isn't the misstep


def test_safe_call_logs_on_transport_error(monkeypatch, caplog):
    c = MagicMock()
    c.get.side_effect = httpx.ConnectError("refused")
    monkeypatch.setattr(m, "_client", lambda: _CM(c))
    with caplog.at_level("WARNING"):
        m.broker_health()
    assert any("broker request failed" in r.message for r in caplog.records)


def test_safe_call_handles_eof_remote_protocol_error(monkeypatch):
    # Broker closed the connection mid-response (EOF / truncated body). httpx
    # raises RemoteProtocolError, which must become a clean envelope, not a crash.
    c = MagicMock()
    c.get.side_effect = httpx.RemoteProtocolError(
        "peer closed connection without sending complete message body (EOF)")
    monkeypatch.setattr(m, "_client", lambda: _CM(c))
    out = m.broker_health()
    assert out["ok"] is False and out["status"] == 0
    assert "RemoteProtocolError" in out["error"]


def test_safe_call_wrong_server_connect_error(monkeypatch):
    # BROKER_URL points at the wrong/old host: the connection is refused. The
    # tool must report it readably (with the URL it tried), not raise.
    c = MagicMock()
    c.get.side_effect = httpx.ConnectError("[Errno 111] Connection refused")
    monkeypatch.setattr(m, "_client", lambda: _CM(c))
    out = m.broker_health()
    assert out["ok"] is False and out["broker_url"] == m.BROKER_URL
    assert "reachable" in out.get("hint", "").lower()


def test_all_tools_return_normalized_result(monkeypatch):
    # Invoke every admin tool once through a mocked client so the thin wrappers
    # are all exercised (coverage) and each returns a clean normalized envelope.
    resp = MagicMock(status_code=200, is_success=True)
    resp.json.return_value = {"ok_body": True}
    c = MagicMock()
    for verb in ("get", "post", "delete"):
        getattr(c, verb).return_value = resp
    monkeypatch.setattr(m, "_client", lambda: _CM(c))
    calls = [
        lambda: m.introspect_token("tok"),
        lambda: m.list_api_keys(),
        lambda: m.create_api_key("svc", "read", 3600),
        lambda: m.revoke_api_key("k1"),
        lambda: m.list_user_sessions("u1"),
        lambda: m.sync_organizations(True),
    ]
    for call in calls:
        out = call()
        assert out["status"] == 200 and out["ok"] is True
