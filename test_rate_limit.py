#!/usr/bin/env python3
"""Tests for rate_limit.py — the dependency-free rate limiter."""
from __future__ import annotations


import rate_limit as rl


def test_allows_up_to_limit_then_blocks():
    r = rl.RateLimiter(max_events=3, window_seconds=60)
    assert [r.check_and_consume("k")[0] for _ in range(3)] == [True, True, True]
    allowed, retry = r.check_and_consume("k")
    assert allowed is False and retry > 0

def test_keys_are_independent():
    r = rl.RateLimiter(max_events=1, window_seconds=60)
    assert r.check_and_consume("a")[0] is True
    assert r.check_and_consume("b")[0] is True   # different key unaffected
    assert r.check_and_consume("a")[0] is False

def test_window_slides(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(rl.time, "monotonic", lambda: now[0])
    r = rl.RateLimiter(max_events=2, window_seconds=10)
    assert r.check_and_consume("k")[0] is True
    assert r.check_and_consume("k")[0] is True
    assert r.check_and_consume("k")[0] is False
    now[0] += 11          # both events now outside the window
    assert r.check_and_consume("k")[0] is True

def test_retry_after_is_bounded_by_window(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(rl.time, "monotonic", lambda: now[0])
    r = rl.RateLimiter(max_events=1, window_seconds=30)
    r.check_and_consume("k")
    _, retry = r.check_and_consume("k")
    assert 0 < retry <= 30

def test_reset_clears_key():
    r = rl.RateLimiter(max_events=1, window_seconds=60)
    r.check_and_consume("k")
    assert r.check_and_consume("k")[0] is False
    r.reset("k")
    assert r.check_and_consume("k")[0] is True

def test_reset_all():
    r = rl.RateLimiter(max_events=1, window_seconds=60)
    r.check_and_consume("a"); r.check_and_consume("b")
    r.reset()
    assert r.check_and_consume("a")[0] is True
    assert r.check_and_consume("b")[0] is True

def test_idle_keys_are_reaped(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(rl.time, "monotonic", lambda: now[0])
    r = rl.RateLimiter(max_events=5, window_seconds=10)
    r.check_and_consume("old")
    now[0] += 1000                      # far past reap interval
    r.check_and_consume("new")          # triggers a reap
    assert "old" not in r._events       # stale key gone
    assert "new" in r._events

def test_thread_safety_under_contention():
    import threading
    r = rl.RateLimiter(max_events=100, window_seconds=60)
    allowed = []
    def worker():
        for _ in range(50):
            allowed.append(r.check_and_consume("shared")[0])
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    # Exactly 100 allowed out of 200 attempts — no race let extras through.
    assert sum(allowed) == 100

def test_env_configures_limits(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_LOGIN_MAX", "2")
    monkeypatch.setenv("RATE_LIMIT_LOGIN_WINDOW", "30")
    rl.reset_all()
    lim = rl.login_limiter()
    assert lim.max_events == 2 and lim.window == 30

def test_bad_env_uses_default(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_LOGIN_MAX", "not-a-number")
    rl.reset_all()
    assert rl.login_limiter().max_events == 10   # default

def test_client_key_uses_socket_ip():
    class Req:
        client = type("C", (), {"host": "203.0.113.7"})()
        headers = {}
    assert rl.client_key(Req()) == "203.0.113.7"

def test_client_key_ignores_forwarded_by_default(monkeypatch):
    monkeypatch.delenv("RATE_LIMIT_TRUST_PROXY", raising=False)
    class Req:
        client = type("C", (), {"host": "10.0.0.1"})()
        headers = {"x-forwarded-for": "1.2.3.4"}
    # Must NOT trust the spoofable header unless explicitly opted in.
    assert rl.client_key(Req()) == "10.0.0.1"

def test_client_key_trusts_forwarded_when_opted_in(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_TRUST_PROXY", "true")
    class Req:
        client = type("C", (), {"host": "10.0.0.1"})()
        headers = {"x-forwarded-for": "1.2.3.4, 10.0.0.1"}
    assert rl.client_key(Req()) == "1.2.3.4"

def test_client_key_never_raises():
    class Bad:
        @property
        def client(self):
            raise RuntimeError("boom")
        headers = {}
    assert rl.client_key(Bad()) == "unknown"
