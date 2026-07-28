"""
cache_manager.py

Storage abstraction used by the rate limiting algorithms.

Why this exists:
    Token bucket / sliding window state has to live *somewhere* shared
    across requests. In production that's Django's cache framework
    (which can be backed by Redis, Memcached, etc). But we don't want
    every unit test to require a running Django project + cache server,
    so this module transparently falls back to a thread-safe in-memory
    store when Django isn't configured.

Concurrency note:
    Per-key updates go through `CacheManager.lock(key)`, a context
    manager. With the in-memory backend this is a real threading.Lock.
    With Django's cache framework this uses cache.add() as a distributed
    "best effort" lock (works fine for LocMemCache / single-process dev,
    and works correctly for Redis/Memcached in a real multi-process
    deployment, though under very high contention a Redis Lua script
    would be a stronger guarantee than this soft-lock).
"""

from __future__ import annotations

import time
import threading
import contextlib
from typing import Any, Optional


class _InMemoryStore:
    """Simple thread-safe TTL key/value store used when Django's cache
    framework isn't available (e.g. running unit tests standalone)."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[Any, Optional[float]]] = {}
        self._lock = threading.RLock()

    def _is_expired(self, expires_at: Optional[float]) -> bool:
        return expires_at is not None and time.monotonic() >= expires_at

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return default
            value, expires_at = item
            if self._is_expired(expires_at):
                del self._data[key]
                return default
            return value

    def set(self, key: str, value: Any, timeout: Optional[float] = None) -> None:
        with self._lock:
            expires_at = time.monotonic() + timeout if timeout is not None else None
            self._data[key] = (value, expires_at)

    def add(self, key: str, value: Any, timeout: Optional[float] = None) -> bool:
        """Set only if the key doesn't already exist (or has expired).
        Returns True if the value was set."""
        with self._lock:
            item = self._data.get(key)
            if item is not None and not self._is_expired(item[1]):
                return False
            self.set(key, value, timeout)
            return True

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def incr(self, key: str, delta: int = 1) -> int:
        with self._lock:
            item = self._data.get(key)
            if item is None or self._is_expired(item[1]):
                raise ValueError(f"Key '{key}' does not exist")
            value, expires_at = item
            new_value = int(value) + delta
            self._data[key] = (new_value, expires_at)
            return new_value


class CacheManager:
    """Unified interface over Django's cache framework or an in-memory
    fallback. Use one instance per logical "namespace" (e.g. one for
    rate limiting, one for anything else) to avoid key collisions.
    """

    def __init__(self, namespace: str = "waf", django_cache_alias: Optional[str] = "default"):
        self.namespace = namespace
        self._backend = None
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()

        try:
            from django.core.cache import caches  # type: ignore
            self._backend = caches[django_cache_alias]
            self._is_django = True
        except Exception:
            # Django not installed, not configured, or alias missing ->
            # fall back to standalone in-memory store.
            self._backend = _InMemoryStore()
            self._is_django = False

    def _make_key(self, key: str) -> str:
        return f"{self.namespace}:{key}"

    def get(self, key: str, default: Any = None) -> Any:
        return self._backend.get(self._make_key(key), default)

    def set(self, key: str, value: Any, timeout: Optional[float] = None) -> None:
        self._backend.set(self._make_key(key), value, timeout)

    def add(self, key: str, value: Any, timeout: Optional[float] = None) -> bool:
        return bool(self._backend.add(self._make_key(key), value, timeout))

    def delete(self, key: str) -> None:
        self._backend.delete(self._make_key(key))

    def incr(self, key: str, delta: int = 1) -> int:
        return self._backend.incr(self._make_key(key), delta)

    @contextlib.contextmanager
    def lock(self, key: str, timeout: float = 2.0):
        """Best-effort per-key mutual exclusion. In-memory backend uses a
        real lock object; Django backend uses cache.add() as a distributed
        soft-lock with a short TTL so it self-heals if a process dies
        while holding it."""
        lock_key = f"lock:{key}"

        if not self._is_django:
            with self._locks_guard:
                lock_obj = self._locks.setdefault(key, threading.RLock())
            acquired = lock_obj.acquire(timeout=timeout)
            try:
                yield acquired
            finally:
                if acquired:
                    lock_obj.release()
            return

        # Django backend: spin briefly on cache.add() as the mutex.
        deadline = time.monotonic() + timeout
        acquired = False
        while time.monotonic() < deadline:
            if self.add(lock_key, "1", timeout=timeout):
                acquired = True
                break
            time.sleep(0.01)
        try:
            yield acquired
        finally:
            if acquired:
                self.delete(lock_key)
