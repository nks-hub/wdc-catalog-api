"""Tiny in-process TTL cache for hot read endpoints.

Two call sites today:

- ``catalog_response_cache`` — serialized catalog body + ETag, invalidated
  by admin mutations (via ``invalidate_catalog()``).
- ``stats_overview_cache`` — admin dashboard JSON, time-bound TTL only
  (30 s is fine, operators refresh manually anyway).

The value is intentionally small. Redis-backed caching is documented in
the architecture report as the next step when we scale past one worker.
"""

from __future__ import annotations

import time
from threading import RLock
from typing import Any, Callable, Optional


class _TTLEntry:
    __slots__ = ("value", "expires")

    def __init__(self, value: Any, expires: float) -> None:
        self.value = value
        self.expires = expires


class TTLCache:
    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._lock = RLock()
        self._store: dict[str, _TTLEntry] = {}

    def get(self, key: str) -> Optional[Any]:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None or entry.expires <= now:
                return None
            return entry.value

    def set(self, key: str, value: Any, *, ttl: Optional[float] = None) -> None:
        expires = time.monotonic() + (ttl if ttl is not None else self._ttl)
        with self._lock:
            self._store[key] = _TTLEntry(value, expires)

    def get_or_compute(self, key: str, compute: Callable[[], Any]) -> Any:
        hit = self.get(key)
        if hit is not None:
            return hit
        value = compute()
        self.set(key, value)
        return value

    def invalidate(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._store.clear()
            else:
                self._store.pop(key, None)


catalog_response_cache = TTLCache(ttl_seconds=30.0)
stats_overview_cache = TTLCache(ttl_seconds=30.0)

# Short positive+negative cache for JWT jti revocation lookups. Every
# authenticated request hits the DB otherwise; at typical sync cadence
# that dominates auth-path latency. TTL kept low so ``POST /auth/logout``
# is visible to other workers within a few seconds.
revoked_token_cache = TTLCache(ttl_seconds=30.0)


def invalidate_catalog() -> None:
    catalog_response_cache.invalidate()


def invalidate_stats() -> None:
    stats_overview_cache.invalidate()


def invalidate_revoked(jti: Optional[str] = None) -> None:
    revoked_token_cache.invalidate(jti)


__all__ = [
    "TTLCache",
    "catalog_response_cache",
    "stats_overview_cache",
    "revoked_token_cache",
    "invalidate_catalog",
    "invalidate_stats",
    "invalidate_revoked",
]
