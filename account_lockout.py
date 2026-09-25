"""Per-user failed-login tracking with temporary lockout.

Rate limiting (rate_limit.py) is keyed by client IP, which a distributed attacker
dodges by spreading guesses across many IPs. This tracks failed logins per
USERNAME and temporarily locks an account after too many failures in a window,
so a slow distributed brute-force against ONE account is still stopped.

Storage is pluggable:
  - memory (default): in-process — per replica.
  - redis (LOCKOUT_BACKEND=redis, REDIS_URL): shared across replicas, so lockout
    is global. A Redis that can't be reached falls back to memory with a warning.

Disable entirely with LOCKOUT_ENABLED=false. Tunable via LOCKOUT_MAX_FAILURES /
LOCKOUT_WINDOW_SECONDS.

Known tradeoff: per-username lockout lets an attacker lock a victim out by failing
logins for their username (a DoS). The defaults are lenient (5 / 15min); raise the
threshold or disable if that risk outweighs the brute-force protection.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _enabled() -> bool:
    return os.environ.get("LOCKOUT_ENABLED", "true").strip().lower() in (
        "1", "true", "yes", "on")


# ── backends ────────────────────────────────────────────────────────────────

class _MemoryBackend:
    """In-process sliding-window failure counter (per replica)."""

    def __init__(self, max_failures: int, window_seconds: float):
        self.max_failures = max_failures
        self.window = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, dq: deque, now: float) -> None:
        cutoff = now - self.window
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def is_locked(self, key: str) -> tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            dq = self._events.get(key)
            if not dq:
                return False, 0.0
            self._prune(dq, now)
            if len(dq) >= self.max_failures:
                return True, max(0.0, self.window - (now - dq[0]))
            return False, 0.0

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            dq = self._events[key]
            self._prune(dq, now)
            dq.append(now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


class _RedisBackend:
    """Shared sliding-window failure counter via a Redis sorted set per user, so
    lockout is global across replicas. Wall-clock time (comparable across
    processes); keys auto-expire so a quiet user leaves no residue."""

    def __init__(self, max_failures: int, window_seconds: float, client,
                 namespace: str = "lockout"):
        self.max_failures = max_failures
        self.window = window_seconds
        self._r = client
        self._ns = namespace

    def _k(self, key: str) -> str:
        return f"{self._ns}:{key}"

    def is_locked(self, key: str) -> tuple[bool, float]:
        rk = self._k(key)
        now = time.time()
        pipe = self._r.pipeline()
        pipe.zremrangebyscore(rk, 0, now - self.window)
        pipe.zrange(rk, 0, 0, withscores=True)   # oldest remaining
        pipe.zcard(rk)
        _, oldest, count = pipe.execute()
        if count >= self.max_failures:
            oldest_score = oldest[0][1] if oldest else now
            return True, max(0.0, self.window - (now - oldest_score))
        return False, 0.0

    def record_failure(self, key: str) -> None:
        rk = self._k(key)
        now = time.time()
        member = f"{now:.6f}-{uuid.uuid4().hex}"
        pipe = self._r.pipeline()
        pipe.zremrangebyscore(rk, 0, now - self.window)
        pipe.zadd(rk, {member: now})
        pipe.expire(rk, int(self.window) + 60)
        pipe.execute()

    def clear(self, key: str) -> None:
        self._r.delete(self._k(key))


def _make_backend(max_failures: int, window_seconds: float):
    """Select the lockout backend from env, degrading to memory on a bad Redis."""
    if os.environ.get("LOCKOUT_BACKEND", "memory").strip().lower() == "redis":
        try:
            import redis  # lazy
            url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            client = redis.Redis.from_url(
                url, socket_timeout=2, socket_connect_timeout=2)
            client.ping()
            logger.info("Account lockout using shared Redis store")
            return _RedisBackend(max_failures, window_seconds, client)
        except Exception as exc:  # noqa: BLE001 — degrade, never crash
            logger.warning("LOCKOUT_BACKEND=redis but Redis is unavailable (%s); "
                           "falling back to in-process lockout", exc)
    return _MemoryBackend(max_failures, window_seconds)


# ── tracker ─────────────────────────────────────────────────────────────────

class FailedLoginTracker:
    """Sliding-window failed-login counter with lockout, over a pluggable backend."""

    def __init__(self, max_failures: int, window_seconds: float, backend=None):
        self.max_failures = max(1, max_failures)
        self.window_seconds = window_seconds
        self._backend = backend or _MemoryBackend(self.max_failures, window_seconds)

    def is_locked(self, key: str) -> tuple[bool, float]:
        return self._backend.is_locked(key)

    def record_failure(self, key: str) -> None:
        self._backend.record_failure(key)

    def clear(self, key: str) -> None:
        self._backend.clear(key)


_TRACKER: FailedLoginTracker | None = None
_build_lock = threading.Lock()


def failed_login_tracker() -> FailedLoginTracker:
    global _TRACKER
    if _TRACKER is None:
        with _build_lock:
            if _TRACKER is None:
                mx = _int_env("LOCKOUT_MAX_FAILURES", 5)
                win = _float_env("LOCKOUT_WINDOW_SECONDS", 900.0)
                _TRACKER = FailedLoginTracker(mx, win, _make_backend(mx, win))
    return _TRACKER


def check_locked(username: str) -> tuple[bool, float]:
    """(locked, retry_after) for a username, honoring LOCKOUT_ENABLED."""
    if not _enabled() or not username:
        return False, 0.0
    return failed_login_tracker().is_locked(username)


def note_failure(username: str) -> None:
    if _enabled() and username:
        failed_login_tracker().record_failure(username)


def note_success(username: str) -> None:
    if _enabled() and username:
        failed_login_tracker().clear(username)


def reset_lockouts() -> None:
    """Test hook: rebuild the tracker (e.g. after changing env)."""
    global _TRACKER
    with _build_lock:
        _TRACKER = None
