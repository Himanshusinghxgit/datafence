"""
Core DataFence benchmarks.

Measures performance of policy evaluation, execution, and security features.
"""

import time
from typing import Any

from datafence import DataFence
from datafence.connectors import MemoryConnector, SQLiteConnector
from datafence.core.request import ExecutionRequest


class BenchmarkResult:
    """Benchmark result container."""

    def __init__(self, name: str):
        self.name = name
        self.times: list[float] = []
        self.errors: int = 0

    def add_time(self, elapsed: float):
        """Add timing measurement."""
        self.times.append(elapsed)

    def add_error(self):
        """Record an error."""
        self.errors += 1

    @property
    def avg(self) -> float:
        """Average time in milliseconds."""
        return (sum(self.times) / len(self.times)) * 1000 if self.times else 0

    @property
    def min(self) -> float:
        """Minimum time in milliseconds."""
        return min(self.times) * 1000 if self.times else 0

    @property
    def max(self) -> float:
        """Maximum time in milliseconds."""
        return max(self.times) * 1000 if self.times else 0

    @property
    def p50(self) -> float:
        """50th percentile (median) in milliseconds."""
        if not self.times:
            return 0
        sorted_times = sorted(self.times)
        return sorted_times[len(sorted_times) // 2] * 1000

    @property
    def p95(self) -> float:
        """95th percentile in milliseconds."""
        if not self.times:
            return 0
        sorted_times = sorted(self.times)
        idx = int(len(sorted_times) * 0.95)
        return sorted_times[idx] * 1000

    @property
    def p99(self) -> float:
        """99th percentile in milliseconds."""
        if not self.times:
            return 0
        sorted_times = sorted(self.times)
        idx = int(len(sorted_times) * 0.99)
        return sorted_times[idx] * 1000

    def print_summary(self):
        """Print benchmark summary."""
        print(f"\n{self.name}")
        print("=" * 60)
        print(f"  Iterations: {len(self.times)}")
        print(f"  Errors: {self.errors}")
        print(f"  Average: {self.avg:.2f}ms")
        print(f"  Median (p50): {self.p50:.2f}ms")
        print(f"  p95: {self.p95:.2f}ms")
        print(f"  p99: {self.p99:.2f}ms")
        print(f"  Min: {self.min:.2f}ms")
        print(f"  Max: {self.max:.2f}ms")


def benchmark_policy_evaluation(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark policy evaluation performance.

    Args:
        iterations: Number of iterations

    Returns:
        Benchmark result
    """
    result = BenchmarkResult("Policy Evaluation")

    # Setup
    data = {
        "users": [{"id": i, "tenant_id": "acme", "name": f"User{i}"} for i in range(100)]
    }

    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml("policies/basic.yaml", connector)

    request_dict = {
        "actor": {"id": "agent:test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "users",
        "fields": ["id", "name"],
        "filters": {"tenant_id": "acme"},
        "limit": 10,
    }

    # Warmup
    for _ in range(10):
        fence.execute(request_dict)

    # Benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            fence.execute(request_dict)
            elapsed = time.perf_counter() - start
            result.add_time(elapsed)
        except Exception:
            result.add_error()

    return result


def benchmark_sql_firewall(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark SQL firewall performance.

    Args:
        iterations: Number of iterations

    Returns:
        Benchmark result
    """
    result = BenchmarkResult("SQL Firewall")

    # Setup
    data = {"users": [{"id": i, "tenant_id": "acme"} for i in range(100)]}

    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml(
        "policies/basic.yaml", connector, enable_sql_firewall=True
    )

    request_dict = {
        "actor": {"id": "agent:test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "users",
        "fields": ["id"],
        "limit": 10,
    }

    # Warmup
    for _ in range(10):
        fence.execute(request_dict)

    # Benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            fence.execute(request_dict)
            elapsed = time.perf_counter() - start
            result.add_time(elapsed)
        except Exception:
            result.add_error()

    return result


def benchmark_pii_detection(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark PII detection performance.

    Args:
        iterations: Number of iterations

    Returns:
        Benchmark result
    """
    result = BenchmarkResult("PII Detection")

    # Setup - data with PII
    data = {
        "users": [
            {
                "id": i,
                "tenant_id": "acme",
                "email": f"user{i}@example.com",
                "phone": "555-123-4567",
            }
            for i in range(100)
        ]
    }

    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml(
        "policies/basic.yaml", connector, enable_pii_detection=True
    )

    request_dict = {
        "actor": {"id": "agent:test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "users",
        "fields": ["id", "email", "phone"],
        "limit": 10,
    }

    # Warmup
    for _ in range(10):
        fence.execute(request_dict)

    # Benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            fence.execute(request_dict)
            elapsed = time.perf_counter() - start
            result.add_time(elapsed)
        except Exception:
            result.add_error()

    return result


def benchmark_memory_connector(iterations: int = 1000, rows: int = 100) -> BenchmarkResult:
    """
    Benchmark Memory connector performance.

    Args:
        iterations: Number of iterations
        rows: Number of rows in data

    Returns:
        Benchmark result
    """
    result = BenchmarkResult(f"Memory Connector ({rows} rows)")

    # Setup
    data = {
        "users": [{"id": i, "tenant_id": "acme", "name": f"User{i}"} for i in range(rows)]
    }

    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml("policies/basic.yaml", connector)

    request_dict = {
        "actor": {"id": "agent:test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "users",
        "fields": ["id", "name"],
        "limit": 50,
    }

    # Warmup
    for _ in range(10):
        fence.execute(request_dict)

    # Benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            fence.execute(request_dict)
            elapsed = time.perf_counter() - start
            result.add_time(elapsed)
        except Exception:
            result.add_error()

    return result


def benchmark_field_restriction(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark field restriction performance.

    Args:
        iterations: Number of iterations

    Returns:
        Benchmark result
    """
    result = BenchmarkResult("Field Restriction")

    # Setup
    data = {
        "users": [
            {
                "id": i,
                "tenant_id": "acme",
                "name": f"User{i}",
                "email": f"user{i}@example.com",
                "password": "secret",
                "ssn": "123-45-6789",
            }
            for i in range(100)
        ]
    }

    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml("policies/basic.yaml", connector)

    request_dict = {
        "actor": {"id": "agent:test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "users",
        "fields": ["id", "name", "email"],  # password and ssn denied
        "limit": 10,
    }

    # Warmup
    for _ in range(10):
        fence.execute(request_dict)

    # Benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            fence.execute(request_dict)
            elapsed = time.perf_counter() - start
            result.add_time(elapsed)
        except Exception:
            result.add_error()

    return result


def benchmark_full_stack(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark full stack (all features enabled).

    Args:
        iterations: Number of iterations

    Returns:
        Benchmark result
    """
    result = BenchmarkResult("Full Stack (All Features)")

    # Setup
    data = {
        "users": [
            {
                "id": i,
                "tenant_id": "acme",
                "email": f"user{i}@example.com",
                "phone": "555-123-4567",
            }
            for i in range(100)
        ]
    }

    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml(
        "policies/basic.yaml",
        connector,
        enable_sql_firewall=True,
        enable_pii_detection=True,
    )

    request_dict = {
        "actor": {"id": "agent:test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "users",
        "fields": ["id", "email", "phone"],
        "filters": {"tenant_id": "acme"},
        "limit": 10,
    }

    # Warmup
    for _ in range(10):
        fence.execute(request_dict)

    # Benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            fence.execute(request_dict)
            elapsed = time.perf_counter() - start
            result.add_time(elapsed)
        except Exception:
            result.add_error()

    return result


def run_all_benchmarks(iterations: int = 1000):
    """
    Run all core benchmarks.

    Args:
        iterations: Number of iterations per benchmark
    """
    print("=" * 60)
    print("DataFence Performance Benchmarks")
    print("=" * 60)
    print(f"Iterations per benchmark: {iterations}")

    benchmarks = [
        benchmark_policy_evaluation,
        benchmark_sql_firewall,
        benchmark_pii_detection,
        benchmark_field_restriction,
        lambda: benchmark_memory_connector(iterations, 100),
        lambda: benchmark_memory_connector(iterations, 1000),
        benchmark_full_stack,
    ]

    results = []
    for benchmark_func in benchmarks:
        result = benchmark_func(iterations) if callable(benchmark_func) else benchmark_func
        result.print_summary()
        results.append(result)

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for result in results:
        print(f"{result.name:40} {result.avg:>8.2f}ms (p95: {result.p95:.2f}ms)")


if __name__ == "__main__":
    import sys

    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    run_all_benchmarks(iterations)
