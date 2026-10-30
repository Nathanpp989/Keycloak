"""Broker caller-auth + scope enforcement — verbs_common._authenticate.

The registry caller MODEL (key hashing, scope round-trip, disabled, the
count_enabled_callers rule) is covered end-to-end against the real registry in
the engine integration suite (test_registry_backed_callers). THIS suite guards
the piece that lives in the broker: _authenticate consuming a caller row and
enforcing enabled + per-verb scope, with the bootstrap-key fallback and the
auth-off posture. The registry lookup is stubbed (the bundle ships no registry),
exactly as conftest stubs the engine door.

Authority order under test (verbs_common §P2-3):
  registry caller (enabled + scope) → PREMDISPATCH_API_KEY bootstrap → auth off.
A denial names forbidden (authenticated, missing scope) vs unauthorized
(unknown/invalid/missing key).
"""
import pytest


def _wire_callers(C, monkeypatch, rows, *, count=None):
    """Point verbs_common's registry seams at an in-memory {key: row} map."""
    monkeypatch.setattr(C, "_CALLERS_AVAILABLE", True)
    monkeypatch.setattr(C, "_registry_authenticate_caller",
                        lambda key: rows.get(key))
    n = len(rows) if count is None else count
    monkeypatch.setattr(C, "_registry_count_callers", lambda: n)


def _caller(cid, scopes, *, enabled=True, deterministic_only=False):
    return {"id": cid, "enabled": enabled, "scopes": list(scopes),
            "deterministic_only": deterministic_only}


# ── registry caller: scope granted / denied ──────────────────────────────────

def test_scope_granted_allows(C, monkeypatch):
    _wire_callers(C, monkeypatch, {"k1": _caller("svc-1", ["dispatch", "health"])})
    denied, ident = C._authenticate({"api_key": "k1"}, "dispatch")
    assert denied is None
    assert ident and ident["id"] == "svc-1" and ident["source"] == "registry"


def test_missing_scope_is_forbidden(C, monkeypatch):
    _wire_callers(C, monkeypatch, {"k1": _caller("svc-1", ["dispatch"])})
    denied, ident = C._authenticate({"api_key": "k1"}, "certify_run")
    assert ident is None
    assert denied["ok"] is False and denied["forbidden"] is True
    assert denied["unauthorized"] is True and denied["caller"] == "svc-1"
    assert "certify_run" in denied["error"]


def test_wildcard_scope_allows_any_verb(C, monkeypatch):
    _wire_callers(C, monkeypatch, {"k1": _caller("admin", ["*"])})
    for verb in ("dispatch", "certify_run", "ingest_events", "run_due"):
        denied, ident = C._authenticate({"api_key": "k1"}, verb)
        assert denied is None and ident["id"] == "admin", verb


def test_disabled_caller_is_unauthorized_not_forbidden(C, monkeypatch):
    _wire_callers(C, monkeypatch,
                  {"k1": _caller("svc-1", ["dispatch"], enabled=False)})
    denied, ident = C._authenticate({"api_key": "k1"}, "dispatch")
    assert ident is None
    assert denied["unauthorized"] is True and "disabled" in denied["error"].lower()
    assert not denied.get("forbidden")        # disabled is not a scope outcome


def test_deterministic_only_flag_flows_into_identity(C, monkeypatch):
    _wire_callers(C, monkeypatch,
                  {"k1": _caller("svc-1", ["*"], deterministic_only=True)})
    _, ident = C._authenticate({"api_key": "k1"}, "dispatch")
    assert ident["deterministic_only"] is True


# ── unknown / missing key while governed callers exist ────────────────────────

def test_unknown_key_with_callers_present_is_unauthorized(C, monkeypatch):
    # key not in the map, but the install HAS enabled callers → auth mandatory
    _wire_callers(C, monkeypatch, {"k1": _caller("svc-1", ["*"])}, count=1)
    denied, ident = C._authenticate({"api_key": "nope"}, "dispatch")
    assert ident is None and denied["unauthorized"] is True
    assert not denied.get("forbidden")


def test_missing_key_with_callers_present_is_unauthorized(C, monkeypatch):
    _wire_callers(C, monkeypatch, {}, count=1)   # callers exist, none matched
    denied, ident = C._authenticate({}, "dispatch")
    assert ident is None and denied["unauthorized"] is True


# ── bootstrap env key fallback ────────────────────────────────────────────────

def test_bootstrap_env_key_allows_when_no_registry_caller(C, monkeypatch):
    _wire_callers(C, monkeypatch, {}, count=0)          # no governed callers
    monkeypatch.setattr(C, "API_KEY", "env-secret")
    denied, ident = C._authenticate({"api_key": "env-secret"}, "dispatch")
    assert denied is None and ident["id"] == "bootstrap" and ident["source"] == "env"


def test_wrong_env_key_is_unauthorized(C, monkeypatch):
    _wire_callers(C, monkeypatch, {}, count=0)
    monkeypatch.setattr(C, "API_KEY", "env-secret")
    denied, ident = C._authenticate({"api_key": "wrong"}, "dispatch")
    assert ident is None and denied["unauthorized"] is True


# ── auth off: no authority configured at all ─────────────────────────────────

def test_auth_off_when_no_key_and_no_callers(C, monkeypatch):
    _wire_callers(C, monkeypatch, {}, count=0)
    monkeypatch.setattr(C, "API_KEY", "")
    denied, ident = C._authenticate({}, "dispatch")
    assert denied is None and ident is None      # open install, host-fronted auth
