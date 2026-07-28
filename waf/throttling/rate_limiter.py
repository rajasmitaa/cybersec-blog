"""
rate_limiter.py

Ties token_bucket / sliding_window into something usable directly in
Django: a middleware for global/per-IP limits, and a decorator for
per-view limits (e.g. stricter limits on /login or /api/search).

Usage - global middleware (settings.py):

    MIDDLEWARE = [
        ...
        "throttling.rate_limiter.RateLimitMiddleware",
    ]

    WAF_RATE_LIMIT = {
        "strategy": "sliding_window",   # or "token_bucket"
        "limit": 100,                    # requests
        "window_seconds": 60,            # per minute
        # token_bucket only:
        "capacity": 50,
        "refill_rate": 5,
    }

Usage - per-view decorator:

    from throttling.rate_limiter import rate_limit

    @rate_limit(limit=5, window_seconds=60, strategy="sliding_window")
    def login_view(request):
        ...
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Callable, Optional, Literal

from .cache_manager import CacheManager
from .token_bucket import TokenBucket
from .sliding_window import SlidingWindowCounter

Strategy = Literal["token_bucket", "sliding_window"]


class RateLimitExceeded(Exception):
    """Raised by RateLimiter.check() in non-Django/manual usage."""

    def __init__(self, retry_after: float):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded, retry after {retry_after:.2f}s")


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after: float
    remaining: float
    limit: float


def default_key_func(request) -> str:
    """Default: rate limit per client IP. Respects X-Forwarded-For if
    present (assumes the WAF sits behind a trusted reverse proxy that
    sets it correctly)."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


class RateLimiter:
    """Framework-agnostic core. `check(key)` returns a RateLimitDecision;
    it never touches the Django request/response objects directly, so
    it's independently unit-testable and reusable outside middleware."""

    def __init__(
        self,
        strategy: Strategy = "sliding_window",
        limit: int = 100,
        window_seconds: float = 60,
        capacity: Optional[int] = None,
        refill_rate: Optional[float] = None,
        cache: Optional[CacheManager] = None,
        namespace: str = "rate_limiter",
    ):
        self.strategy_name = strategy
        cache = cache or CacheManager(namespace=namespace)

        if strategy == "sliding_window":
            self._impl = SlidingWindowCounter(limit=limit, window_seconds=window_seconds, cache=cache)
        elif strategy == "token_bucket":
            capacity = capacity if capacity is not None else limit
            refill_rate = refill_rate if refill_rate is not None else (limit / window_seconds)
            self._impl = TokenBucket(capacity=capacity, refill_rate=refill_rate, cache=cache)
        else:
            raise ValueError(f"Unknown strategy: {strategy}")

    def check(self, key: str, weight: int = 1) -> RateLimitDecision:
        if isinstance(self._impl, SlidingWindowCounter):
            result = self._impl.hit(key, weight=weight)
            return RateLimitDecision(
                allowed=result.allowed,
                retry_after=result.retry_after,
                remaining=max(0.0, result.limit - result.count),
                limit=result.limit,
            )
        else:  # TokenBucket
            result = self._impl.consume(key, tokens=weight)
            return RateLimitDecision(
                allowed=result.allowed,
                retry_after=result.retry_after,
                remaining=result.tokens_remaining,
                limit=self._impl.capacity,
            )

    def reset(self, key: str) -> None:
        self._impl.reset(key)


class RateLimitMiddleware:
    """Django middleware. Reads config from settings.WAF_RATE_LIMIT.

    Add to MIDDLEWARE, ideally early in the chain (after security
    middleware but before anything expensive like auth/session)."""

    def __init__(self, get_response: Callable):
        self.get_response = get_response

        from django.conf import settings  # type: ignore
        from django.http import JsonResponse  # type: ignore

        self._JsonResponse = JsonResponse
        config = getattr(settings, "WAF_RATE_LIMIT", {})

        self.enabled = config.get("enabled", True)
        self.key_func = config.get("key_func", default_key_func)
        self.exempt_paths = tuple(config.get("exempt_paths", ()))

        self.limiter = RateLimiter(
            strategy=config.get("strategy", "sliding_window"),
            limit=config.get("limit", 100),
            window_seconds=config.get("window_seconds", 60),
            capacity=config.get("capacity"),
            refill_rate=config.get("refill_rate"),
        )

    def __call__(self, request):
        if not self.enabled or request.path.startswith(self.exempt_paths):
            return self.get_response(request)

        key = self.key_func(request)
        decision = self.limiter.check(key)

        if not decision.allowed:
            response = self._JsonResponse(
                {"error": "rate_limit_exceeded", "retry_after": decision.retry_after},
                status=429,
            )
            response["Retry-After"] = str(int(decision.retry_after) + 1)
            response["X-RateLimit-Limit"] = str(int(decision.limit))
            response["X-RateLimit-Remaining"] = str(int(max(0, decision.remaining)))
            return response

        response = self.get_response(request)
        response["X-RateLimit-Limit"] = str(int(decision.limit))
        response["X-RateLimit-Remaining"] = str(int(max(0, decision.remaining)))
        return response


def rate_limit(
    limit: int = 10,
    window_seconds: float = 60,
    strategy: Strategy = "sliding_window",
    key_func: Optional[Callable] = None,
    capacity: Optional[int] = None,
    refill_rate: Optional[float] = None,
):
    """Per-view rate limit decorator, for stricter limits on sensitive
    endpoints like /login or /password-reset.

    Example:
        @rate_limit(limit=5, window_seconds=60)
        def login_view(request):
            ...
    """
    limiter = RateLimiter(
        strategy=strategy,
        limit=limit,
        window_seconds=window_seconds,
        capacity=capacity,
        refill_rate=refill_rate,
        namespace=f"view_rl",
    )
    resolved_key_func = key_func or default_key_func

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(request, *args, **kwargs):
            from django.http import JsonResponse  # type: ignore

            key = f"{view_func.__module__}.{view_func.__name__}:{resolved_key_func(request)}"
            decision = limiter.check(key)
            if not decision.allowed:
                response = JsonResponse(
                    {"error": "rate_limit_exceeded", "retry_after": decision.retry_after},
                    status=429,
                )
                response["Retry-After"] = str(int(decision.retry_after) + 1)
                return response
            return view_func(request, *args, **kwargs)

        return wrapped

    return decorator
