"""Unit tests for account_lockout.FailedLoginTracker."""
from account_lockout import FailedLoginTracker


def test_locks_after_max_failures():
    t = FailedLoginTracker(max_failures=3, window_seconds=60)
    for _ in range(3):
        t.record_failure("u")
    locked, retry = t.is_locked("u")
    assert locked and retry > 0


def test_below_max_not_locked():
    t = FailedLoginTracker(3, 60)
    t.record_failure("u")
    t.record_failure("u")
    assert t.is_locked("u")[0] is False


def test_clear_unlocks():
    t = FailedLoginTracker(3, 60)
    for _ in range(3):
        t.record_failure("u")
    t.clear("u")
    assert t.is_locked("u")[0] is False


def test_per_key_isolated():
    t = FailedLoginTracker(3, 60)
    for _ in range(3):
        t.record_failure("a")
    assert t.is_locked("a")[0] is True
    assert t.is_locked("b")[0] is False


def test_redis_lockout_backend():
    import fakeredis
    from account_lockout import _RedisBackend
    r = fakeredis.FakeRedis()
    b = _RedisBackend(max_failures=3, window_seconds=60, client=r)
    assert b.is_locked("u")[0] is False
    for _ in range(3):
        b.record_failure("u")
    locked, retry = b.is_locked("u")
    assert locked and retry > 0
    assert b.is_locked("other")[0] is False   # isolated per key
    b.clear("u")
    assert b.is_locked("u")[0] is False


def test_tracker_uses_injected_backend():
    import fakeredis
    from account_lockout import FailedLoginTracker, _RedisBackend
    r = fakeredis.FakeRedis()
    t = FailedLoginTracker(2, 60, backend=_RedisBackend(2, 60, r))
    t.record_failure("u")
    t.record_failure("u")
    assert t.is_locked("u")[0] is True


def test_non_numeric_env_falls_back_to_default(monkeypatch):
    import account_lockout as al
    monkeypatch.setenv("LOCKOUT_MAX_FAILURES", "not-a-number")
    monkeypatch.setenv("LOCKOUT_WINDOW_SECONDS", "abc")
    assert al._int_env("LOCKOUT_MAX_FAILURES", 5) == 5        # ValueError -> default
    assert al._float_env("LOCKOUT_WINDOW_SECONDS", 900.0) == 900.0


def test_disabled_lockout_never_locks(monkeypatch):
    import account_lockout as al
    monkeypatch.setenv("LOCKOUT_ENABLED", "false")
    al.reset_lockouts()
    for _ in range(50):
        al.note_failure("victim")           # should be a no-op when disabled
    assert al.check_locked("victim") == (False, 0.0)
    al.reset_lockouts()


def test_memory_backend_prunes_expired(monkeypatch):
    # events older than the window are pruned (covers the sliding-window popleft)
    import account_lockout as al
    import time
    b = al._MemoryBackend(max_failures=3, window_seconds=0.05)
    b.record_failure("u"); b.record_failure("u"); b.record_failure("u")
    assert b.is_locked("u")[0] is True
    time.sleep(0.08)                         # let the window expire
    assert b.is_locked("u")[0] is False      # pruned -> unlocked


def test_make_backend_redis_fallback_to_memory(monkeypatch):
    # LOCKOUT_BACKEND=redis but Redis unreachable -> degrade to memory, don't crash
    import account_lockout as al
    monkeypatch.setenv("LOCKOUT_BACKEND", "redis")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6399/0")
    b = al._make_backend(5, 900.0)
    assert type(b).__name__ == "_MemoryBackend"


def test_make_backend_redis_success(monkeypatch):
    # LOCKOUT_BACKEND=redis with a reachable (fake) Redis -> _RedisBackend
    import sys
    import types
    import fakeredis
    import account_lockout as al
    fake_client = fakeredis.FakeStrictRedis()
    redis_mod = types.ModuleType("redis")
    redis_mod.Redis = types.SimpleNamespace(from_url=lambda *a, **k: fake_client)
    monkeypatch.setitem(sys.modules, "redis", redis_mod)
    monkeypatch.setenv("LOCKOUT_BACKEND", "redis")
    b = al._make_backend(5, 900.0)
    assert type(b).__name__ == "_RedisBackend"
