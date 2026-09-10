#!/usr/bin/env python3
# features.py
# Runtime on/off control for the optional subsystems (Auth0 management, OpenBao),
# with three modes each and health-aware "auto".
#
# WHY THIS EXISTS
# ---------------
# Not every environment has every backend. A developer may have no Auth0 tenant,
# no Key Vault, or no OpenBao running. Without explicit control the app either
# crashes at startup or hangs retrying an unreachable service. These flags make
# each optional subsystem switchable, and "auto" makes it self-disable when the
# backend isn't there.
#
# AN IMPORTANT HONEST DISTINCTION
# -------------------------------
# Auth0 plays TWO roles in this system and only ONE of them is optional:
#
#   1. Identity provider for the brokered browser login (Keycloak -> Auth0).
#      This is ARCHITECTURAL. If you disable it, brokered login does not
#      degrade — it stops working. There is deliberately NO flag that claims
#      otherwise, because a flag implying "login still works without Auth0"
#      would be actively misleading.
#
#   2. Management API (M2M) calls: creating/listing users and organizations,
#      provisioning the IdP at startup, secret rotation.
#      This IS optional — AUTH0_MANAGEMENT_MODE controls it. With it off, the
#      app still starts and Keycloak-native auth still works; only the Auth0
#      management features are unavailable, and they say so explicitly rather
#      than failing obscurely.
#
# MODES (each flag accepts these values, case-insensitive)
#   on    - always enabled; failures surface as errors
#   off   - always disabled; calls short-circuit with a clear reason
#   auto  - enabled only if the backend is configured AND reachable (probed,
#           with a short cache so we don't probe on every call)
#
# ENV VARS
#   OPENBAO_MODE            on | off | auto     (default: auto)
#   AUTH0_MANAGEMENT_MODE   on | off | auto     (default: auto)
#   FEATURE_PROBE_TTL       seconds to cache a health probe (default: 30)

from __future__ import annotations

import logging
import os
import threading
import time

import requests

logger = logging.getLogger(__name__)

ON = "on"
OFF = "off"
AUTO = "auto"
_VALID = {ON, OFF, AUTO}

_DEFAULT_TTL = 30.0


class FeatureState:
    """The resolved state of one subsystem, with the reason it's in that state."""

    def __init__(self, name: str, enabled: bool, mode: str, reason: str):
        self.name = name
        self.enabled = enabled
        self.mode = mode
        self.reason = reason

    def __bool__(self) -> bool:
        return self.enabled

    def __repr__(self) -> str:
        return (f"<{self.name} {'ENABLED' if self.enabled else 'DISABLED'} "
                f"mode={self.mode} reason={self.reason}>")


# ── probe cache ─────────────────────────────────────────────────────────────
_probe_cache: dict[str, tuple[bool, str, float]] = {}
_probe_lock = threading.Lock()


def _ttl() -> float:
    try:
        return float(os.environ.get("FEATURE_PROBE_TTL", _DEFAULT_TTL))
    except ValueError:
        return _DEFAULT_TTL


def _cached_probe(key: str, probe) -> tuple[bool, str]:
    """Run `probe()` at most once per TTL. probe() -> (ok, detail)."""
    now = time.monotonic()
    with _probe_lock:
        hit = _probe_cache.get(key)
        if hit and (now - hit[2]) < _ttl():
            return hit[0], hit[1]
    try:
        ok, detail = probe()
    except Exception as exc:  # noqa: BLE001 - a probe must never raise
        ok, detail = False, f"probe error: {exc}"
    with _probe_lock:
        _probe_cache[key] = (ok, detail, now)
    return ok, detail


def reset_probe_cache() -> None:
    """Clear cached probe results (tests, or after fixing a backend)."""
    with _probe_lock:
        _probe_cache.clear()


def _mode(env_name: str, default: str = AUTO) -> str:
    raw = os.environ.get(env_name, default).strip().lower()
    if raw not in _VALID:
        logger.warning("%s=%r is not one of %s; using %r",
                       env_name, raw, sorted(_VALID), default)
        return default
    return raw


# ── probes ──────────────────────────────────────────────────────────────────
def _probe_openbao() -> tuple[bool, str]:
    addr = os.environ.get("OPENBAO_ADDR", "http://127.0.0.1:8200").rstrip("/")
    if not os.environ.get("OPENBAO_TOKEN"):
        return False, "OPENBAO_TOKEN not set"
    try:
        r = requests.get(f"{addr}/v1/sys/health", timeout=3)
    except requests.RequestException as exc:
        return False, f"unreachable at {addr}: {exc}"
    # OpenBao/Vault health uses several 2xx/4xx/5xx codes to mean "up but
    # sealed/standby". Anything that answers is 'reachable'; only 5xx-with-no-
    # meaning or a connection error counts as down.
    if r.status_code in (200, 429, 472, 473, 501, 503):
        return True, f"reachable at {addr} ({r.status_code})"
    return False, f"unexpected health status {r.status_code} at {addr}"


def _probe_auth0_management() -> tuple[bool, str]:
    domain = os.environ.get("AUTH0_DOMAIN", "").strip().rstrip("/")
    cid = os.environ.get("AUTH0_CLIENT_ID", "")
    sec = os.environ.get("AUTH0_CLIENT_SECRET", "")
    if not (domain and cid and sec):
        return False, "AUTH0_DOMAIN/CLIENT_ID/CLIENT_SECRET not all set"
    try:
        r = requests.get(f"https://{domain}/.well-known/openid-configuration",
                         timeout=4)
    except requests.RequestException as exc:
        return False, f"Auth0 unreachable: {exc}"
    if r.status_code >= 400:
        return False, f"Auth0 discovery -> {r.status_code}"
    return True, f"Auth0 reachable ({domain})"


# ── public API ──────────────────────────────────────────────────────────────
def openbao_state() -> FeatureState:
    """Is the OpenBao subsystem enabled right now, and why?"""
    mode = _mode("OPENBAO_MODE", AUTO)
    if mode == OFF:
        return FeatureState("openbao", False, mode, "disabled by OPENBAO_MODE=off")
    if mode == ON:
        return FeatureState("openbao", True, mode, "forced on by OPENBAO_MODE=on")
    ok, detail = _cached_probe("openbao", _probe_openbao)
    return FeatureState("openbao", ok, mode, detail)


def auth0_management_state() -> FeatureState:
    """
    Is the Auth0 MANAGEMENT surface (user/org APIs, IdP provisioning) enabled?

    NOTE: this does NOT control Auth0's role as the brokered-login IdP. Keycloak
    brokers through Auth0 for browser logins regardless of this flag; disabling
    management does not (and cannot) make login work without Auth0.
    """
    mode = _mode("AUTH0_MANAGEMENT_MODE", AUTO)
    if mode == OFF:
        return FeatureState("auth0_management", False, mode,
                            "disabled by AUTH0_MANAGEMENT_MODE=off")
    if mode == ON:
        return FeatureState("auth0_management", True, mode,
                            "forced on by AUTH0_MANAGEMENT_MODE=on")
    ok, detail = _cached_probe("auth0_mgmt", _probe_auth0_management)
    return FeatureState("auth0_management", ok, mode, detail)


def summary() -> str:
    """Human-readable status of every switchable subsystem."""
    lines = ["Subsystem status:"]
    for st in (auth0_management_state(), openbao_state()):
        mark = "\u2713" if st.enabled else "\u2717"
        lines.append(f"  {mark} {st.name:18} mode={st.mode:5} {st.reason}")
    lines.append("  \u2139 auth0 (brokered login IdP) is ARCHITECTURAL — Keycloak "
                 "brokers through Auth0")
    lines.append("    for browser logins; there is no flag to disable it, "
                 "because login")
    lines.append("    cannot work without it.")
    return "\n".join(lines)


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    print(summary())
