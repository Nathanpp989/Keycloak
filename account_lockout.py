"""Per-user failed-login tracking with temporary lockout.

Rate limiting (rate_limit.py) is keyed by client IP, which a distributed attacker
dodges by spreading guesses across many IPs. This tracks failed logins per
USERNAME and temporarily locks an account after too many failures in a window,
so a slow distributed brute-force against ONE account is still stopped.

Thread-safe, in-process (per replica — same tradeoff as the default rate-limit
backend; a shared store would give a global view). Disable with LOCKOUT_ENABLED=
false. Tunable via LOCKOUT_MAX_FAILURES / LOCKOUT_WINDOW_SECONDS.

Known tradeoff: per-username lockout lets an attacker lock a victim out by
failing logins for their username (a DoS). The threshold/window default to a
lenient 5 / 15min to limit that; raise the threshold or disable if that risk
outweighs the brute-force protection for your deployment.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque


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


class FailedLoginTracker:
    """Sliding-window failed-login counter per key (username), with lockout."""

    def __init__(self, max_failures: int, window_seconds: float):
        self.max_failures = max(1, max_failures)
        self.window_seconds = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, dq: deque, now: float) -> None:
        cutoff = now - self.window_seconds
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def is_locked(self, key: str) -> tuple[bool, float]:
        """Return (locked, retry_after_seconds). Records nothing."""
        now = time.monotonic()
        with self._lock:
            dq = self._events.get(key)
            if not dq:
                return False, 0.0
            self._prune(dq, now)
            if len(dq) >= self.max_failures:
                return True, max(0.0, self.window_seconds - (now - dq[0]))
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


_TRACKER: FailedLoginTracker | None = None
_build_lock = threading.Lock()


def failed_login_tracker() -> FailedLoginTracker:
    global _TRACKER
    if _TRACKER is None:
        with _build_lock:
            if _TRACKER is None:
                _TRACKER = FailedLoginTracker(
                    _int_env("LOCKOUT_MAX_FAILURES", 5),
                    _float_env("LOCKOUT_WINDOW_SECONDS", 900.0))
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
