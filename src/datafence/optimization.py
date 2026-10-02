"""
Performance optimization utilities.

Caching, memoization, and performance helpers.
"""

import functools
import hashlib
import json
from collections.abc import Callable
from typing import Any


class SchemaCache:
    """
    Cache for framework-specific schemas.

    Schemas are expensive to generate and rarely change. Cache them
    to avoid regeneration on every request.
    """

    def __init__(self):
        self._cache: dict[str, Any] = {}

    def get(self, policy_hash: str, framework: str) -> Any | None:
        """Get cached schema."""
        key = f"{framework}:{policy_hash}"
        return self._cache.get(key)

    def set(self, policy_hash: str, framework: str, schema: Any):
        """Set cached schema."""
        key = f"{framework}:{policy_hash}"
        self._cache[key] = schema

    def clear(self):
        """Clear cache."""
        self._cache.clear()

    def invalidate(self, policy_hash: str):
        """Invalidate all schemas for a policy."""
        keys_to_delete = [k for k in self._cache.keys() if k.endswith(policy_hash)]
        for key in keys_to_delete:
            del self._cache[key]


# Global schema cache
_schema_cache = SchemaCache()


def cache_schema(framework: str):
    """
    Decorator to cache schema generation.

    Usage:
        @cache_schema("openai")
        def get_functions(self):
            # Expensive schema generation
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            # Generate policy hash
            policy_dict = self.fence.policy.model_dump() if hasattr(self.fence, "policy") else {}
            policy_json = json.dumps(policy_dict, sort_keys=True)
            policy_hash = hashlib.sha256(policy_json.encode()).hexdigest()[:16]

            # Check cache
            cached = _schema_cache.get(policy_hash, framework)
            if cached is not None:
                return cached

            # Generate and cache
            result = func(self, *args, **kwargs)
            _schema_cache.set(policy_hash, framework, result)

            return result

        return wrapper

    return decorator


def clear_schema_cache():
    """Clear the global schema cache."""
    _schema_cache.clear()


class QueryCache:
    """
    Simple query result cache.

    Cache query results for identical requests. Use with caution in
    production as data may become stale.
    """

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: dict[str, Any] = {}
        self._access_count: dict[str, int] = {}

    def _make_key(self, request_dict: dict[str, Any]) -> str:
        """Generate cache key from request."""
        # Sort keys for consistent hashing
        request_json = json.dumps(request_dict, sort_keys=True)
        return hashlib.sha256(request_json.encode()).hexdigest()

    def get(self, request_dict: dict[str, Any]) -> Any | None:
        """Get cached result."""
        key = self._make_key(request_dict)
        if key in self._cache:
            self._access_count[key] = self._access_count.get(key, 0) + 1
            return self._cache[key]
        return None

    def set(self, request_dict: dict[str, Any], result: Any):
        """Set cached result."""
        key = self._make_key(request_dict)

        # Evict if full (LRU-like)
        if len(self._cache) >= self.max_size:
            # Remove least accessed item
            min_key = min(self._access_count, key=self._access_count.get)
            del self._cache[min_key]
            del self._access_count[min_key]

        self._cache[key] = result
        self._access_count[key] = 1

    def clear(self):
        """Clear cache."""
        self._cache.clear()
        self._access_count.clear()

    def stats(self) -> dict[str, int]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "total_accesses": sum(self._access_count.values()),
        }


def measure_time(func: Callable) -> Callable:
    """
    Decorator to measure execution time.

    Usage:
        @measure_time
        def expensive_function():
            ...
    """
    import logging
    import time

    logger = logging.getLogger(__name__)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000  # ms
        logger.debug(f"{func.__name__} took {elapsed:.2f}ms")
        return result

    return wrapper


class PerformanceMonitor:
    """
    Monitor performance metrics.

    Tracks timing and counts for various operations.
    """

    def __init__(self):
        self._timings: dict[str, list[float]] = {}
        self._counts: dict[str, int] = {}

    def record_time(self, operation: str, elapsed: float):
        """Record timing for an operation."""
        if operation not in self._timings:
            self._timings[operation] = []
        self._timings[operation].append(elapsed)

    def increment(self, counter: str):
        """Increment a counter."""
        self._counts[counter] = self._counts.get(counter, 0) + 1

    def get_stats(self, operation: str) -> dict[str, float]:
        """Get statistics for an operation."""
        if operation not in self._timings:
            return {}

        times = self._timings[operation]
        sorted_times = sorted(times)

        return {
            "count": len(times),
            "avg": sum(times) / len(times),
            "min": min(times),
            "max": max(times),
            "p50": sorted_times[len(sorted_times) // 2],
            "p95": sorted_times[int(len(sorted_times) * 0.95)],
            "p99": sorted_times[int(len(sorted_times) * 0.99)],
        }

    def get_all_stats(self) -> dict[str, dict[str, float]]:
        """Get all statistics."""
        return {op: self.get_stats(op) for op in self._timings.keys()}

    def get_counts(self) -> dict[str, int]:
        """Get all counters."""
        return self._counts.copy()

    def reset(self):
        """Reset all metrics."""
        self._timings.clear()
        self._counts.clear()


# Global performance monitor
_performance_monitor = PerformanceMonitor()


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor."""
    return _performance_monitor
