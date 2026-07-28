"""
Unit tests for throttling.sliding_window.SlidingWindowCounter

Run with: pytest tests/test_sliding_window.py -v
"""

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from throttling.sliding_window import SlidingWindowCounter
from throttling.cache_manager import CacheManager


@pytest.fixture
def fresh_cache():
    return CacheManager(namespace=f"test_{time.monotonic_ns()}")


def test_allows_requests_within_limit(fresh_cache):
    limiter = SlidingWindowCounter(limit=5, window_seconds=60, cache=fresh_cache)
    for _ in range(5):
        assert limiter.hit("client-1").allowed


def test_rejects_over_limit(fresh_cache):
    limiter = SlidingWindowCounter(limit=3, window_seconds=60, cache=fresh_cache)
    for _ in range(3):
        assert limiter.hit("client-1").allowed
    result = limiter.hit("client-1")
    assert not result.allowed
    assert result.retry_after >= 0


def test_independent_keys(fresh_cache):
    limiter = SlidingWindowCounter(limit=1, window_seconds=60, cache=fresh_cache)
    assert limiter.hit("client-A").allowed
    assert not limiter.hit("client-A").allowed
    assert limiter.hit("client-B").allowed  # separate bucket


def test_weighted_hit_can_exceed_limit_immediately(fresh_cache):
    limiter = SlidingWindowCounter(limit=5, window_seconds=60, cache=fresh_cache)
    result = limiter.hit("client-1", weight=6)
    assert not result.allowed


def test_short_window_allows_again_after_expiry(fresh_cache):
    limiter = SlidingWindowCounter(limit=1, window_seconds=0.2, cache=fresh_cache)
    assert limiter.hit("client-1").allowed
    assert not limiter.hit("client-1").allowed
    time.sleep(0.45)  # roll past current + previous window
    assert limiter.hit("client-1").allowed


def test_peek_does_not_consume(fresh_cache):
    limiter = SlidingWindowCounter(limit=5, window_seconds=60, cache=fresh_cache)
    limiter.hit("client-1")
    before = limiter.peek("client-1")
    after = limiter.peek("client-1")
    assert before == after  # peek is read-only


def test_reset_clears_state(fresh_cache):
    limiter = SlidingWindowCounter(limit=1, window_seconds=60, cache=fresh_cache)
    assert limiter.hit("client-1").allowed
    assert not limiter.hit("client-1").allowed
    limiter.reset("client-1")
    assert limiter.hit("client-1").allowed


def test_invalid_params_raise():
    with pytest.raises(ValueError):
        SlidingWindowCounter(limit=0, window_seconds=60)
    with pytest.raises(ValueError):
        SlidingWindowCounter(limit=5, window_seconds=0)
