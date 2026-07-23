#!/usr/bin/env python3
"""Tests for features.py — runtime on/off control with health-aware auto."""
from __future__ import annotations

import responses

import features


def setup_function():
    features.reset_probe_cache()


# ── explicit modes short-circuit without probing ────────────────────────────
def test_off_disables_without_probing(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "off")
    monkeypatch.setattr(features, "_probe_openbao",
                        lambda: (_ for _ in ()).throw(AssertionError("probed!")))
    st = features.openbao_state()
    assert not st.enabled and st.mode == "off" and "off" in st.reason

def test_on_enables_without_probing(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "on")
    monkeypatch.setattr(features, "_probe_openbao",
                        lambda: (_ for _ in ()).throw(AssertionError("probed!")))
    assert features.openbao_state().enabled

def test_invalid_mode_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "banana")
    monkeypatch.setattr(features, "_probe_openbao", lambda: (True, "ok"))
    st = features.openbao_state()
    assert st.mode == "auto"      # invalid -> default, not a crash


# ── auto follows circumstance ───────────────────────────────────────────────
def test_auto_enabled_when_reachable(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "auto")
    monkeypatch.setattr(features, "_probe_openbao", lambda: (True, "reachable"))
    assert features.openbao_state().enabled

def test_auto_disabled_when_unreachable(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "auto")
    monkeypatch.setattr(features, "_probe_openbao", lambda: (False, "down"))
    st = features.openbao_state()
    assert not st.enabled and st.reason == "down"

def test_probe_never_raises(monkeypatch):
    # A probe that explodes must degrade to 'disabled', not propagate.
    monkeypatch.setenv("OPENBAO_MODE", "auto")
    def boom():
        raise RuntimeError("probe blew up")
    monkeypatch.setattr(features, "_probe_openbao", boom)
    st = features.openbao_state()
    assert not st.enabled and "probe error" in st.reason


# ── probe caching ───────────────────────────────────────────────────────────
def test_probe_is_cached(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "auto")
    calls = {"n": 0}
    def counting():
        calls["n"] += 1
        return True, "ok"
    monkeypatch.setattr(features, "_probe_openbao", counting)
    for _ in range(5):
        features.openbao_state()
    assert calls["n"] == 1          # probed once, then cached

def test_reset_probe_cache_forces_reprobe(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "auto")
    calls = {"n": 0}
    def counting():
        calls["n"] += 1
        return True, "ok"
    monkeypatch.setattr(features, "_probe_openbao", counting)
    features.openbao_state()
    features.reset_probe_cache()
    features.openbao_state()
    assert calls["n"] == 2

def test_zero_ttl_reprobes_every_time(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "auto")
    monkeypatch.setenv("FEATURE_PROBE_TTL", "0")
    calls = {"n": 0}
    def counting():
        calls["n"] += 1
        return True, "ok"
    monkeypatch.setattr(features, "_probe_openbao", counting)
    features.openbao_state()
    features.openbao_state()
    assert calls["n"] == 2

def test_bad_ttl_value_does_not_crash(monkeypatch):
    monkeypatch.setenv("FEATURE_PROBE_TTL", "not-a-number")
    assert features._ttl() == 30.0


# ── real probes ─────────────────────────────────────────────────────────────
def test_openbao_probe_requires_token(monkeypatch):
    monkeypatch.delenv("OPENBAO_TOKEN", raising=False)
    ok, detail = features._probe_openbao()
    assert ok is False and "OPENBAO_TOKEN" in detail

@responses.activate
def test_openbao_probe_accepts_sealed_status(monkeypatch):
    # 503 from Vault/OpenBao means "up but sealed" — still reachable.
    monkeypatch.setenv("OPENBAO_TOKEN", "t")
    monkeypatch.setenv("OPENBAO_ADDR", "http://bao:8200")
    responses.add(responses.GET, "http://bao:8200/v1/sys/health", status=503)
    ok, _ = features._probe_openbao()
    assert ok is True

@responses.activate
def test_openbao_probe_unreachable(monkeypatch):
    monkeypatch.setenv("OPENBAO_TOKEN", "t")
    monkeypatch.setenv("OPENBAO_ADDR", "http://bao:8200")
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("refused")
    responses.add_callback(responses.GET, "http://bao:8200/v1/sys/health",
                           callback=boom)
    ok, detail = features._probe_openbao()
    assert ok is False and "unreachable" in detail

def test_auth0_probe_requires_all_creds(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "d.auth0.com")
    monkeypatch.delenv("AUTH0_CLIENT_ID", raising=False)
    monkeypatch.delenv("AUTH0_CLIENT_SECRET", raising=False)
    ok, detail = features._probe_auth0_management()
    assert ok is False and "not all set" in detail

@responses.activate
def test_auth0_probe_reachable(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "d.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "i")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "s")
    responses.add(responses.GET,
                  "https://d.auth0.com/.well-known/openid-configuration",
                  json={"issuer": "x"}, status=200)
    ok, _ = features._probe_auth0_management()
    assert ok is True


# ── summary is honest about the architectural Auth0 link ────────────────────
def test_summary_states_auth0_login_has_no_off_switch(monkeypatch):
    monkeypatch.setenv("OPENBAO_MODE", "off")
    monkeypatch.setenv("AUTH0_MANAGEMENT_MODE", "off")
    text = features.summary()
    assert "ARCHITECTURAL" in text
    assert "no flag to disable it" in text

def test_feature_state_is_truthy_by_enabled():
    assert bool(features.FeatureState("x", True, "on", "r")) is True
    assert bool(features.FeatureState("x", False, "off", "r")) is False
