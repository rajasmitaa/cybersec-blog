"""
Unit tests for throttling.token_bucket.TokenBucket

Run with: pytest tests/test_token_bucket.py -v
"""

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from throttling.token_bucket import TokenBucket
from throttling.cache_manager import CacheManager


@pytest.fixture
def fresh_cache():
    # unique namespace per test so state doesn't leak between tests
    return CacheManager(namespace=f"test_{time.monotonic_ns()}")


def test_allows_requests_within_capacity(fresh_cache):
    bucket = TokenBucket(capacity=5, refill_rate=1, cache=fresh_cache)
    for _ in range(5):
        result = bucket.consume("client-1")
        assert result.allowed

    # 6th request should be rejected (bucket empty)
    result = bucket.consume("client-1")
    assert not result.allowed
    assert result.retry_after > 0


def test_rejects_when_bucket_empty(fresh_cache):
    bucket = TokenBucket(capacity=1, refill_rate=0.001, cache=fresh_cache)
    assert bucket.consume("client-1").allowed
    result = bucket.consume("client-1")
    assert not result.allowed


def test_refills_over_time(fresh_cache):
    bucket = TokenBucket(capacity=2, refill_rate=10, cache=fresh_cache)  # fast refill for test speed
    assert bucket.consume("client-1").allowed
    assert bucket.consume("client-1").allowed
    assert not bucket.consume("client-1").allowed

    time.sleep(0.15)  # ~1.5 tokens should have refilled
    result = bucket.consume("client-1")
    assert result.allowed


def test_independent_keys_have_independent_buckets(fresh_cache):
    bucket = TokenBucket(capacity=1, refill_rate=0.001, cache=fresh_cache)
    assert bucket.consume("client-A").allowed
    assert not bucket.consume("client-A").allowed
    # client-B has its own bucket, unaffected by client-A
    assert bucket.consume("client-B").allowed


def test_consume_multiple_tokens(fresh_cache):
    bucket = TokenBucket(capacity=10, refill_rate=1, cache=fresh_cache)
    result = bucket.consume("client-1", tokens=7)
    assert result.allowed
    assert result.tokens_remaining == pytest.approx(3, abs=0.01)

    result = bucket.consume("client-1", tokens=5)
    assert not result.allowed  # only 3 left


def test_capacity_is_never_exceeded(fresh_cache):
    bucket = TokenBucket(capacity=3, refill_rate=100, cache=fresh_cache)
    bucket.consume("client-1")
    time.sleep(0.2)  # plenty of time to "overfill" if capped incorrectly
    assert bucket.peek("client-1") <= 3


def test_reset_restores_full_bucket(fresh_cache):
    bucket = TokenBucket(capacity=2, refill_rate=0.001, cache=fresh_cache)
    bucket.consume("client-1")
    bucket.consume("client-1")
    assert not bucket.consume("client-1").allowed

    bucket.reset("client-1")
    assert bucket.consume("client-1").allowed


def test_invalid_params_raise():
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_rate=1)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, refill_rate=0)


def test_consume_zero_or_negative_tokens_raises(fresh_cache):
    bucket = TokenBucket(capacity=5, refill_rate=1, cache=fresh_cache)
    with pytest.raises(ValueError):
        bucket.consume("client-1", tokens=0)
    with pytest.raises(ValueError):
        bucket.consume("client-1", tokens=-3)
