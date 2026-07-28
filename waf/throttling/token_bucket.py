"""
token_bucket.py

Classic token bucket algorithm.

Each key (e.g. an IP address, API key, or "ip:endpoint" pair) gets a
bucket that holds up to `capacity` tokens. Tokens refill continuously
at `refill_rate` tokens/second. Each request consumes 1+ tokens; if
there aren't enough tokens available, the request is rejected.

Token bucket vs sliding window:
    - Token bucket naturally allows short bursts up to `capacity`,
      then throttles to the steady refill rate. Good for "allow bursts
      but cap sustained traffic" (e.g. normal user browsing).
    - Sliding window (see sliding_window.py) gives a hard cap on
      requests within a rolling time period with no burst allowance.
      Good for strict abuse prevention (e.g. login attempts).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from .cache_manager import CacheManager


@dataclass
class TokenBucketResult:
    allowed: bool
    tokens_remaining: float
    retry_after: float  # seconds until at least 1 token is available


class TokenBucket:
    """Token bucket limiter backed by a CacheManager.

    Example:
        bucket = TokenBucket(capacity=20, refill_rate=5)  # 5 tokens/sec, burst of 20
        result = bucket.consume(key="203.0.113.4")
        if not result.allowed:
            return http_429(retry_after=result.retry_after)
    """

    def __init__(
        self,
        capacity: int,
        refill_rate: float,
        cache: Optional[CacheManager] = None,
        state_ttl: float = 3600.0,
    ):
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_rate <= 0:
            raise ValueError("refill_rate must be > 0")

        self.capacity = capacity
        self.refill_rate = refill_rate
        self.cache = cache or CacheManager(namespace="token_bucket")
        self.state_ttl = state_ttl

    def _state_key(self, key: str) -> str:
        return f"bucket:{key}"

    def _load_state(self, key: str) -> tuple[float, float]:
        """Returns (tokens, last_refill_timestamp). Starts full if unseen."""
        state = self.cache.get(self._state_key(key))
        if state is None:
            return float(self.capacity), time.monotonic()
        return state["tokens"], state["last_refill"]

    def _save_state(self, key: str, tokens: float, last_refill: float) -> None:
        self.cache.set(
            self._state_key(key),
            {"tokens": tokens, "last_refill": last_refill},
            timeout=self.state_ttl,
        )

    def consume(self, key: str, tokens: int = 1) -> TokenBucketResult:
        if tokens <= 0:
            raise ValueError("tokens to consume must be > 0")

        with self.cache.lock(f"bucket-lock:{key}"):
            current_tokens, last_refill = self._load_state(key)

            now = time.monotonic()
            elapsed = max(0.0, now - last_refill)
            refilled = min(self.capacity, current_tokens + elapsed * self.refill_rate)

            if refilled >= tokens:
                remaining = refilled - tokens
                self._save_state(key, remaining, now)
                return TokenBucketResult(allowed=True, tokens_remaining=remaining, retry_after=0.0)

            # Not enough tokens: persist the refilled (but not consumed) amount
            self._save_state(key, refilled, now)
            deficit = tokens - refilled
            retry_after = deficit / self.refill_rate
            return TokenBucketResult(allowed=False, tokens_remaining=refilled, retry_after=retry_after)

    def peek(self, key: str) -> float:
        """Read current token count without consuming (for monitoring/headers)."""
        current_tokens, last_refill = self._load_state(key)
        elapsed = max(0.0, time.monotonic() - last_refill)
        return min(self.capacity, current_tokens + elapsed * self.refill_rate)

    def reset(self, key: str) -> None:
        self.cache.delete(self._state_key(key))
