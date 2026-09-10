#!/usr/bin/env python3
# rate_limit.py
# A small, thread-safe rate limiter for the abusable public endpoints (/token
# brute-force, /register account-spam). Defaults to a sliding-window counter in
# process memory — zero new infrastructure, the right fit for a single-process
# app. For horizontal scaling, set RATE_LIMIT_BACKEND=redis to keep the counts
# in a shared store so limits are GLOBAL across replicas (see _RedisBackend).
#
# HONEST LIMITS (documented, not hidden):
#   - In-process (default): counters are per-worker. Behind N replicas the
#     effective limit is N x the configured value. Exact for a single container.
#     Switch to the redis backend (RATE_LIMIT_BACKEND=redis, REDIS_URL) for one
#     global limit across replicas — same call sites, no interface change.
#   - Redis backend: approximate atomicity (pipeline add-then-count with
#     roll-back); a boundary race may under-count slightly — fine for limiting.
#     A redis that's unreachable at startup degrades to in-process with a warning.
#   - Memory: one deque of timestamps per active key. Old keys are reaped
#     lazily so idle clients don't accumulate forever.
#   - Keying: by client IP by default. Behind a proxy, the caller must pass a
#     trustworthy identifier (e.g. a validated X-Forwarded-For) — the limiter
#     does not trust headers itself, because a spoofable key is worse than none.
#
# Fail-open by design: if the limiter itself errors, requests are ALLOWED. A
# bug in a security add-on must not take down login for everyone.

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque

logger = logging.getLogger(__name__)


class _MemoryBackend:
    """In-process sliding-window store (the default).

    Exact for a single process. Behind N replicas the effective limit is N x the
    configured value — switch to the Redis backend for global limits.
    """

    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_reap = time.monotonic()
        self._reap_interval = max(window_seconds * 4, 60.0)

    def _reap(self, now: float) -> None:
        stale = [k for k, dq in self._events.items()
                 if not dq or (now - dq[-1]) > self.window]
        for k in stale:
            del self._events[k]
        self._last_reap = now

    def check_and_consume(self, key: str) -> tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            if (now - self._last_reap) > self._reap_interval:
                self._reap(now)
            dq = self._events.setdefault(key, deque())
            cutoff = now - self.window
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= self.max_events:
                retry = self.window - (now - dq[0])
                return False, max(retry, 0.0)
            dq.append(now)
            return True, 0.0

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)


class _RedisBackend:
    """Shared sliding-window store backed by Redis, so limits are GLOBAL across
    multiple app replicas (each replica's counts land in the same store).

    Sliding window via a sorted set per key (score = event time). Atomicity is
    approximate: a pipeline drops old events, tentatively adds this one, and
    counts; if that puts us over the limit we roll our own add back. Two replicas
    racing at the exact boundary may each roll back and slightly under-count —
    acceptable for rate limiting, and it needs no server-side Lua. Wall-clock
    time is used (not monotonic) because it must be comparable across processes.

    Keys are namespaced so a shared Redis can host several limiters (and so
    reset(None) can scan just this limiter's keys).
    """

    def __init__(self, max_events: int, window_seconds: float, client,
                 namespace: str = "rl"):
        self.max_events = max_events
        self.window = window_seconds
        self._r = client
        self._ns = namespace

    def _k(self, key: str) -> str:
        return f"{self._ns}:{key}"

    def check_and_consume(self, key: str) -> tuple[bool, float]:
        import uuid
        rk = self._k(key)
        now = time.time()
        member = f"{now:.6f}-{uuid.uuid4().hex}"  # unique so ZADD never collides
        pipe = self._r.pipeline()
        pipe.zremrangebyscore(rk, 0, now - self.window)
        pipe.zadd(rk, {member: now})
        pipe.zcard(rk)
        pipe.expire(rk, int(self.window) + 1)
        count = pipe.execute()[2]
        if count > self.max_events:
            self._r.zrem(rk, member)  # roll back the tentative add
            oldest = self._r.zrange(rk, 0, 0, withscores=True)
            retry = (self.window - (now - oldest[0][1])) if oldest else self.window
            return False, max(retry, 0.0)
        return True, 0.0

    def reset(self, key: str | None = None) -> None:
        if key is None:
            for k in self._r.scan_iter(f"{self._ns}:*"):
                self._r.delete(k)
        else:
            self._r.delete(self._k(key))


def _make_backend(max_events: int, window_seconds: float):
    """Select the rate-limit backend from env. RATE_LIMIT_BACKEND=redis uses a
    shared Redis store (global limits across replicas); anything else (default)
    uses the in-process store and adds no dependency. A Redis that can't be
    reached at build time falls back to memory with a warning, so a misconfig
    degrades to local limiting rather than erroring on every request."""
    choice = os.environ.get("RATE_LIMIT_BACKEND", "memory").strip().lower()
    if choice == "redis":
        try:
            import redis  # lazy: only imported when explicitly selected
            url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            client = redis.Redis.from_url(
                url, socket_timeout=2, socket_connect_timeout=2)
            client.ping()  # validate now so a misconfig fails ONCE, not per call
            logger.info("Rate limiting using shared Redis store")
            return _RedisBackend(max_events, window_seconds, client)
        except Exception as exc:  # noqa: BLE001 — degrade to local, never crash
            logger.warning("RATE_LIMIT_BACKEND=redis but Redis is unavailable "
                           "(%s); falling back to in-process limiting", exc)
    return _MemoryBackend(max_events, window_seconds)


class RateLimiter:
    """
    Sliding-window limiter: at most `max_events` per `window_seconds` per key.

    Thread-safe. check_and_consume() records an event and returns whether it is
    permitted, plus a retry-after hint when it isn't. Storage is delegated to a
    backend — in-process by default, or a shared Redis store when
    RATE_LIMIT_BACKEND=redis (so limits are global across replicas). The public
    interface is unchanged; call sites don't know which backend is in use.
    """

    def __init__(self, max_events: int, window_seconds: float, backend=None):
        self.max_events = max_events
        self.window = window_seconds
        self._backend = backend if backend is not None else _make_backend(
            max_events, window_seconds)

    def check_and_consume(self, key: str) -> tuple[bool, float]:
        """Record an attempt for `key`. Returns (allowed, retry_after_seconds).
        retry_after is 0.0 when allowed."""
        return self._backend.check_and_consume(key)

    def reset(self, key: str | None = None) -> None:
        """Clear one key, or all keys (tests, or an admin unblock)."""
        self._backend.reset(key)


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
_M2M = None
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


def client_credentials_limiter() -> RateLimiter:
    """Rate limiter for machine-to-machine (client_credentials) token requests.

    Separate from the human login limiter with a higher default ceiling: an app
    legitimately fetches tokens far more often than a person logs in (e.g. a
    fleet of workers refreshing tokens), so a limit tuned for humans would
    throttle normal machine traffic. Still bounded, to contain a misbehaving or
    compromised client. Tunable via RATE_LIMIT_M2M_MAX / _WINDOW.
    """
    global _M2M
    if _M2M is None:
        with _build_lock:
            if _M2M is None:
                _M2M = RateLimiter(
                    _int_env("RATE_LIMIT_M2M_MAX", 60),
                    _float_env("RATE_LIMIT_M2M_WINDOW", 60.0))
    return _M2M


def reset_all() -> None:
    """Test hook / admin: rebuild limiters (e.g. after changing env)."""
    global _LOGIN, _REGISTER, _M2M
    with _build_lock:
        _LOGIN = None
        _REGISTER = None
        _M2M = None


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
