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
