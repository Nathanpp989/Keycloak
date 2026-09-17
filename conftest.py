"""Shared pytest fixtures.

The rate limiters in rate_limit.py are process-wide singletons keyed by client
IP, and the shared TestClient looks like a single IP to them. Without a reset,
tests that exercise /token, /token/client or /register accumulate hits in the
shared counter, so under some (random) orderings a later test trips the limit
and flakes with a 429. reset_all() is the module's designed test hook; running
it autouse before every test restores isolation.
"""
import pytest

import rate_limit


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    rate_limit.reset_all()
    yield
