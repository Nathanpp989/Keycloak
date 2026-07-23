#!/usr/bin/env python3
"""Tests for endpoint_smoke.py — the real-endpoint verification harness."""
from __future__ import annotations

import responses

import endpoint_smoke as es

APP = "http://localhost:8000"


def test_result_tracks_outcomes():
    r = es.Result()
    r.ok("a"); r.bad("b", "why"); r.skip("c", "why")
    assert r.passed == ["a"] and len(r.failed) == 1 and r.skipped == ["c"]

@responses.activate
def test_call_records_pass_on_expected_status():
    responses.add(responses.GET, f"{APP}/x", status=200)
    r = es.Result()
    es._call(r, "GET", "/x")
    assert r.passed and not r.failed

@responses.activate
def test_call_records_failure_on_unexpected_status():
    responses.add(responses.GET, f"{APP}/x", status=500)
    r = es.Result()
    es._call(r, "GET", "/x")
    assert r.failed and not r.passed

@responses.activate
def test_503_is_skipped_not_failed():
    # A disabled subsystem answers 503 — that's a config state, not a bug.
    responses.add(responses.GET, f"{APP}/organizations", status=503)
    r = es.Result()
    es._call(r, "GET", "/organizations")
    assert r.skipped and not r.failed

@responses.activate
def test_call_sends_bearer_token():
    responses.add(responses.GET, f"{APP}/protected", status=200)
    es._call(es.Result(), "GET", "/protected", token="tok123")
    assert responses.calls[0].request.headers["Authorization"] == "Bearer tok123"

@responses.activate
def test_network_error_is_recorded_not_raised():
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("refused")
    responses.add_callback(responses.GET, f"{APP}/x", callback=boom)
    r = es.Result()
    es._call(r, "GET", "/x")
    assert r.failed and "request failed" in r.failed[0]

def test_get_token_prefers_env(monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "from-env")
    tok, how = es._get_token()
    assert tok == "from-env" and "APP_TOKEN" in how

def test_get_token_reports_actionable_message(monkeypatch):
    monkeypatch.delenv("APP_TOKEN", raising=False)
    monkeypatch.delenv("KC_USER", raising=False)
    monkeypatch.delenv("KC_PASS", raising=False)
    tok, how = es._get_token()
    assert tok is None and "login_flow.py" in how

@responses.activate
def test_get_token_direct_grant(monkeypatch):
    monkeypatch.delenv("APP_TOKEN", raising=False)
    monkeypatch.setenv("KC_USER", "u")
    monkeypatch.setenv("KC_PASS", "p")
    monkeypatch.setenv("KEYCLOAK_URL", "http://kc:8080")
    monkeypatch.setenv("KEYCLOAK_REALM", "Premkey")
    responses.add(responses.POST,
                  "http://kc:8080/realms/Premkey/protocol/openid-connect/token",
                  json={"access_token": "granted"}, status=200)
    tok, how = es._get_token()
    assert tok == "granted" and how == "direct grant"

@responses.activate
def test_get_token_direct_grant_failure_explains(monkeypatch):
    monkeypatch.delenv("APP_TOKEN", raising=False)
    monkeypatch.setenv("KC_USER", "u")
    monkeypatch.setenv("KC_PASS", "p")
    monkeypatch.setenv("KEYCLOAK_URL", "http://kc:8080")
    monkeypatch.setenv("KEYCLOAK_REALM", "Premkey")
    responses.add(responses.POST,
                  "http://kc:8080/realms/Premkey/protocol/openid-connect/token",
                  json={"error": "unauthorized_client"}, status=400)
    tok, how = es._get_token()
    assert tok is None and "password grant" in how
