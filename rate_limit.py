#!/usr/bin/env python3
# rate_limit.py
# A small, dependency-free, thread-safe rate limiter for the abusable public
# endpoints (/token brute-force, /register account-spam). No Redis, no external
# service — a sliding-window counter kept in process memory, which is the right
# fit for this single-process app and adds zero new infrastructure.
#
# HONEST LIMITS (documented, not hidden):
#   - In-process only: counters are per-worker. Behind N replicas the effective
#     limit is N x the configured value. For a single container this is exact;
#     for horizontal scaling, move to a shared store (the interface below is
#     deliberately small enough to reimplement against Redis without touching
#     call sites).
#   - Memory: one deque of timestamps per active key. Old keys are reaped
#     lazily so idle clients don't accumulate forever.
#   - Keying: by client IP by default. Behind a proxy, the caller must pass a
#     trustworthy identifier (e.g. a validated X-Forwarded-For) — the limiter
#     does not trust headers itself, because a spoofable key is worse than none.
#
# Fail-open by design: if the limiter itself errors, requests are ALLOWED. A
# bug in a security add-on must not take down login for everyone.

from __future__ import annotations

import os
import threading
import time
from collections import deque


class RateLimiter:
    """
    Sliding-window limiter: at most `max_events` per `window_seconds` per key.

    Thread-safe. check_and_consume() records an event and returns whether it is
    permitted, plus a retry-after hint when it isn't.
    """

    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        # Reap idle keys occasionally so memory doesn't grow unbounded.
        self._last_reap = time.monotonic()
        self._reap_interval = max(window_seconds * 4, 60.0)

    def _reap(self, now: float) -> None:
        # Caller must hold the lock. Drop keys whose newest event is older than
        # the window (they can't affect any future decision).
        stale = [k for k, dq in self._events.items()
                 if not dq or (now - dq[-1]) > self.window]
        for k in stale:
            del self._events[k]
        self._last_reap = now

    def check_and_consume(self, key: str) -> tuple[bool, float]:
        """
        Record an attempt for `key`. Returns (allowed, retry_after_seconds).
        retry_after is 0.0 when allowed.
        """
        now = time.monotonic()
        with self._lock:
            if (now - self._last_reap) > self._reap_interval:
                self._reap(now)
            dq = self._events.setdefault(key, deque())
            # Drop events outside the window from the left.
            cutoff = now - self.window
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= self.max_events:
                # Denied. Retry after the oldest in-window event expires.
                retry = self.window - (now - dq[0])
                return False, max(retry, 0.0)
            dq.append(now)
            return True, 0.0

    def reset(self, key: str | None = None) -> None:
        """Clear one key, or all keys (tests, or an admin unblock)."""
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# Pre-built limiters for the two abusable endpoints, configurable via env.
# Defaults are conservative but not hostile: 10 logins / 5 registrations a
# minute per IP is far above human use and far below a brute-force rate.
_LOGIN = None
_REGISTER = None
_build_lock = threading.Lock()


def login_limiter() -> RateLimiter:
    global _LOGIN
    if _LOGIN is None:
        with _build_lock:
            if _LOGIN is None:
                _LOGIN = RateLimiter(
                    _int_env("RATE_LIMIT_LOGIN_MAX", 10),
                    _float_env("RATE_LIMIT_LOGIN_WINDOW", 60.0))
    return _LOGIN


def register_limiter() -> RateLimiter:
    global _REGISTER
    if _REGISTER is None:
        with _build_lock:
            if _REGISTER is None:
                _REGISTER = RateLimiter(
                    _int_env("RATE_LIMIT_REGISTER_MAX", 5),
                    _float_env("RATE_LIMIT_REGISTER_WINDOW", 60.0))
    return _REGISTER


def reset_all() -> None:
    """Test hook / admin: rebuild limiters (e.g. after changing env)."""
    global _LOGIN, _REGISTER
    with _build_lock:
        _LOGIN = None
        _REGISTER = None


def client_key(request) -> str:
    """
    Derive a rate-limit key from a Starlette/FastAPI Request. Uses the socket
    peer IP. Does NOT trust X-Forwarded-For unless RATE_LIMIT_TRUST_PROXY is
    set, because a spoofable key lets an attacker dodge the limit AND lock out
    victims by forging their IP.
    """
    try:
        if os.environ.get("RATE_LIMIT_TRUST_PROXY", "").strip().lower() in (
                "1", "true", "yes", "on"):
            fwd = request.headers.get("x-forwarded-for", "")
            if fwd:
                # First hop is the original client per convention.
                return fwd.split(",")[0].strip()
        client = getattr(request, "client", None)
        if client and client.host:
            return client.host
    except Exception:  # noqa: BLE001 - never let keying raise
        pass
    return "unknown"
