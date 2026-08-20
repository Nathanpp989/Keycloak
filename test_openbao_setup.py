#!/usr/bin/env python3
"""Tests for openbao_setup.py — the live-IdP orchestration CLI."""
from __future__ import annotations

import responses

import openbao_setup as setup

BAO = "http://127.0.0.1:8200"


def _cfg(**over):
    c = setup.Cfg.__new__(setup.Cfg)
    c.bao_addr = BAO
    c.bao_token = "root"
    c.kc_url = "http://kc:8080"
    c.kc_realm = "Premkey"
    c.kc_ob_client = "openbao"
    c.kc_ob_secret = "kc-secret"
    c.a0_domain = "d.auth0.com"
    c.a0_audience = "https://api"
    c.a0_m2m_id = ""
    c.a0_m2m_secret = ""
    for k, v in over.items():
        setattr(c, k, v)
    return c


def test_discovery_urls_built_correctly():
    c = _cfg()
    assert c.kc_discovery == \
        "http://kc:8080/realms/Premkey/.well-known/openid-configuration"
    assert c.a0_discovery == "https://d.auth0.com/.well-known/openid-configuration"


@responses.activate
def test_reachable_rejects_non_discovery_200():
    # A 200 that isn't a discovery doc must be reported as NOT reachable — this
    # is the false-green the live test exposed.
    responses.add(responses.GET, "http://x/wk", body="<html>", status=200)
    ok, detail = setup._reachable_from_here("http://x/wk")
    assert ok is False and "not a valid OIDC discovery" in detail

@responses.activate
def test_reachable_rejects_json_without_jwks():
    responses.add(responses.GET, "http://x/wk", json={"issuer": "x"}, status=200)
    ok, detail = setup._reachable_from_here("http://x/wk")
    assert ok is False and "missing issuer/jwks_uri" in detail

@responses.activate
def test_reachable_accepts_valid_discovery():
    responses.add(responses.GET, "http://x/wk",
                  json={"issuer": "http://x", "jwks_uri": "http://x/jwks"},
                  status=200)
    ok, detail = setup._reachable_from_here("http://x/wk")
    assert ok is True and "valid discovery" in detail

@responses.activate
def test_check_openbao_unreachable_returns_1():
    # No responses registered for /sys/health -> connection error path.
    def boom(req):
        raise __import__("requests").exceptions.ConnectionError("refused")
    responses.add_callback(responses.GET, f"{BAO}/v1/sys/health", callback=boom)
    assert setup.cmd_check(_cfg()) == 1

@responses.activate
def test_check_all_green():
    responses.add(responses.GET, f"{BAO}/v1/sys/health", json={}, status=200)
    responses.add(responses.GET, f"{BAO}/v1/auth/token/lookup-self",
                  json={"data": {}}, status=200)
    disc = {"issuer": "x", "jwks_uri": "x/j"}
    responses.add(responses.GET,
                  "http://kc:8080/realms/Premkey/.well-known/openid-configuration",
                  json=disc, status=200)
    responses.add(responses.GET,
                  "https://d.auth0.com/.well-known/openid-configuration",
                  json=disc, status=200)
    assert setup.cmd_check(_cfg()) == 0

def test_keycloak_requires_secret():
    assert setup.cmd_keycloak(_cfg(kc_ob_secret="")) == 1

def test_auth0_requires_domain():
    assert setup.cmd_auth0(_cfg(a0_domain="")) == 1

def test_unknown_command():
    assert setup.main(["bogus"]) == 2

def test_help():
    assert setup.main(["--help"]) == 0

def test_checklist_runs():
    assert setup.main(["checklist"]) == 0
