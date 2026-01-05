"""Caching module for GhidraInsight analysis results."""

import hashlib
import json
from typing import Any, Dict, Optional
from functools import wraps
import time
from threading import Lock

from ..config import settings


class Cache:
    """Simple in-memory cache with TTL support."""

    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()

    def _get_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate cache key from function name and arguments."""
        key_data = {
            "func": func_name,
            "args": args,
            "kwargs": sorted(kwargs.items())
        }
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if time.time() - entry["timestamp"] < self.ttl:
                    return entry["value"]
                else:
                    del self._cache[key]
        return None

    def set(self, key: str, value: Any) -> None:
        """Set value in cache."""
        with self._lock:
            if len(self._cache) >= self.max_size:
                # Simple LRU: remove oldest entry
                oldest_key = min(self._cache.keys(),
                               key=lambda k: self._cache[k]["timestamp"])
                del self._cache[oldest_key]

            self._cache[key] = {
                "value": value,
                "timestamp": time.time()
            }

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()


# Global cache instance
cache = Cache(max_size=settings.cache.max_size, ttl=settings.cache.ttl)


def cached(func):
    """Decorator to cache function results."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not settings.cache.enabled:
            return await func(*args, **kwargs)

        key = cache._get_key(func.__name__, args, kwargs)
        cached_result = cache.get(key)

        if cached_result is not None:
            return cached_result

        result = await func(*args, **kwargs)
        cache.set(key, result)
        return result

    return wrapper
