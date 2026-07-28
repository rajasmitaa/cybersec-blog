"""
sliding_window.py

Sliding window counter algorithm (the "weighted" variant, not the
memory-heavy sliding log). This gives a smooth approximation of a
true sliding window while only storing two integers per key.

How it works:
    Time is divided into fixed windows of size `window_seconds`
    (e.g. 60s buckets). We track the request count in the *current*
    bucket and the *previous* bucket. The estimated count in the
    trailing `window_seconds` is:

        estimated = current_count + previous_count * overlap_fraction

    where overlap_fraction is how much of the previous window still
    falls inside the trailing window, e.g. if we're 30% into the
    current window, 70% of the previous window still "counts".

This is the same approach used by Cloudflare/Kong-style rate limiters:
cheap (O(1) storage per key), no burst-at-boundary problem that a naive
fixed-window counter has.
"""

from __future__ import annotations

import time
import math
from dataclasses import dataclass
from typing import Optional

from .cache_manager import CacheManager


@dataclass
class SlidingWindowResult:
    allowed: bool
    count: float           # estimated requests in the trailing window
    limit: int
    retry_after: float     # seconds until the request would be allowed


class SlidingWindowCounter:
    """Sliding window rate limiter backed by a CacheManager.

    Example:
        limiter = SlidingWindowCounter(limit=100, window_seconds=60)
        result = limiter.hit(key="203.0.113.4:/login")
        if not result.allowed:
            return http_429(retry_after=result.retry_after)
    """

    def __init__(
        self,
        limit: int,
        window_seconds: float,
        cache: Optional[CacheManager] = None,
        state_ttl_padding: float = 5.0,
    ):
        if limit <= 0:
            raise ValueError("limit must be > 0")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")

        self.limit = limit
        self.window_seconds = window_seconds
        self.cache = cache or CacheManager(namespace="sliding_window")
        # keep bucket state around slightly longer than 2 windows so
        # slow-arriving requests near a boundary still find their bucket
        self.state_ttl = window_seconds * 2 + state_ttl_padding

    def _bucket_index(self, timestamp: float) -> int:
        return int(timestamp // self.window_seconds)

    def _key(self, key: str, bucket_index: int) -> str:
        return f"sw:{key}:{bucket_index}"

    def hit(self, key: str, weight: int = 1) -> SlidingWindowResult:
        now = time.time()
        current_idx = self._bucket_index(now)
        previous_idx = current_idx - 1

        elapsed_in_current = now - (current_idx * self.window_seconds)
        overlap_fraction = max(0.0, 1.0 - (elapsed_in_current / self.window_seconds))

        with self.cache.lock(f"sw-lock:{key}:{current_idx}"):
            current_count = self.cache.get(self._key(key, current_idx), 0)
            previous_count = self.cache.get(self._key(key, previous_idx), 0)

            estimated = current_count + previous_count * overlap_fraction

            if estimated + weight > self.limit:
                retry_after = self._estimate_retry_after(
                    estimated, weight, elapsed_in_current
                )
                return SlidingWindowResult(
                    allowed=False, count=estimated, limit=self.limit, retry_after=retry_after
                )

            new_count = current_count + weight
            self.cache.set(self._key(key, current_idx), new_count, timeout=self.state_ttl)
            return SlidingWindowResult(
                allowed=True, count=estimated + weight, limit=self.limit, retry_after=0.0
            )

    def _estimate_retry_after(self, estimated: float, weight: int, elapsed_in_current: float) -> float:
        """Rough estimate of how long until enough capacity frees up, based
        on the previous window's contribution decaying linearly to zero."""
        excess = (estimated + weight) - self.limit
        if excess <= 0:
            return 0.0
        # time remaining until current window rolls over, plus a
        # proportional slice of decay time needed for `excess` to clear
        time_to_next_window = self.window_seconds - elapsed_in_current
        decay_needed_fraction = min(1.0, excess / max(1.0, self.limit))
        return round(time_to_next_window * decay_needed_fraction, 3)

    def peek(self, key: str) -> float:
        now = time.time()
        current_idx = self._bucket_index(now)
        previous_idx = current_idx - 1
        elapsed_in_current = now - (current_idx * self.window_seconds)
        overlap_fraction = max(0.0, 1.0 - (elapsed_in_current / self.window_seconds))

        current_count = self.cache.get(self._key(key, current_idx), 0)
        previous_count = self.cache.get(self._key(key, previous_idx), 0)
        return current_count + previous_count * overlap_fraction

    def reset(self, key: str) -> None:
        now = time.time()
        current_idx = self._bucket_index(now)
        self.cache.delete(self._key(key, current_idx))
        self.cache.delete(self._key(key, current_idx - 1))
