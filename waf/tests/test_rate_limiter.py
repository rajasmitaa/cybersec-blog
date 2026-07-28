"""
Unit tests for throttling.rate_limiter.RateLimiter (the framework-agnostic
core only -- middleware/decorator require Django and are covered in
integration tests once the app is wired up).

Run with: pytest tests/test_rate_limiter.py -v
"""

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from throttling.rate_limiter import RateLimiter


def unique_ns():
    return f"test_{time.monotonic_ns()}"


def test_sliding_window_strategy_allows_and_blocks():
    limiter = RateLimiter(strategy="sliding_window", limit=3, window_seconds=60, namespace=unique_ns())
    for _ in range(3):
        assert limiter.check("client-1").allowed
    decision = limiter.check("client-1")
    assert not decision.allowed
    assert decision.limit == 3


def test_token_bucket_strategy_allows_and_blocks():
    limiter = RateLimiter(
        strategy="token_bucket", limit=3, window_seconds=60, capacity=3, refill_rate=0.001,
        namespace=unique_ns(),
    )
    for _ in range(3):
        assert limiter.check("client-1").allowed
    decision = limiter.check("client-1")
    assert not decision.allowed


def test_unknown_strategy_raises():
    with pytest.raises(ValueError):
        RateLimiter(strategy="not_a_real_strategy", namespace=unique_ns())


def test_reset_allows_further_requests():
    limiter = RateLimiter(strategy="sliding_window", limit=1, window_seconds=60, namespace=unique_ns())
    assert limiter.check("client-1").allowed
    assert not limiter.check("client-1").allowed
    limiter.reset("client-1")
    assert limiter.check("client-1").allowed


def test_remaining_decreases_as_requests_consumed():
    limiter = RateLimiter(strategy="sliding_window", limit=5, window_seconds=60, namespace=unique_ns())
    first = limiter.check("client-1")
    second = limiter.check("client-1")
    assert second.remaining < first.remaining


def test_separate_keys_do_not_interfere():
    limiter = RateLimiter(strategy="sliding_window", limit=1, window_seconds=60, namespace=unique_ns())
    assert limiter.check("client-A").allowed
    assert limiter.check("client-B").allowed
    assert not limiter.check("client-A").allowed
