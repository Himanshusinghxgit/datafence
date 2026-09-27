"""
Integration benchmarks.

Measures performance overhead of framework integrations.
"""

import time
import json
from unittest.mock import Mock

from datafence import DataFence
from datafence.connectors import MemoryConnector
from benchmarks.benchmark_core import BenchmarkResult


def benchmark_openai_adapter(iterations: int = 1000) -> BenchmarkResult:
    """Benchmark OpenAI adapter overhead."""
    result = BenchmarkResult("OpenAI Adapter")

    # Setup
    data = {"users": [{"id": i, "tenant_id": "acme"} for i in range(100)]}
    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml("policies/basic.yaml", connector)

    try:
        from datafence.integrations.openai_adapter import OpenAIAdapter

        adapter = OpenAIAdapter(fence)

        # Get functions once (cached)
        functions = adapter.get_functions()

        function_call = {
            "name": "read_users",
            "arguments": json.dumps({"fields": ["id"], "limit": 10}),
        }

        actor = {"id": "test", "tenant_id": "acme"}

        # Warmup
        for _ in range(10):
            adapter.execute_function_call(function_call, actor)

        # Benchmark
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                adapter.execute_function_call(function_call, actor)
                elapsed = time.perf_counter() - start
                result.add_time(elapsed)
            except Exception:
                result.add_error()

    except ImportError:
        print("⚠️  OpenAI integration not installed")

    return result


def benchmark_claude_adapter(iterations: int = 1000) -> BenchmarkResult:
    """Benchmark Claude adapter overhead."""
    result = BenchmarkResult("Claude Adapter")

    # Setup
    data = {"users": [{"id": i, "tenant_id": "acme"} for i in range(100)]}
    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml("policies/basic.yaml", connector)

    try:
        from datafence.integrations.anthropic_adapter import ClaudeAdapter

        adapter = ClaudeAdapter(fence)

        # Get tools once (cached)
        tools = adapter.get_tools()

        tool_name = "read_users"
        tool_input = {"fields": ["id"], "limit": 10}
        actor = {"id": "test", "tenant_id": "acme"}

        # Warmup
        for _ in range(10):
            adapter.execute_tool(tool_name, tool_input, actor)

        # Benchmark
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                adapter.execute_tool(tool_name, tool_input, actor)
                elapsed = time.perf_counter() - start
                result.add_time(elapsed)
            except Exception:
                result.add_error()

    except ImportError:
        print("⚠️  Claude integration not installed")

    return result


def benchmark_langchain_tool(iterations: int = 1000) -> BenchmarkResult:
    """Benchmark LangChain tool overhead."""
    result = BenchmarkResult("LangChain Tool")

    # Setup
    data = {"users": [{"id": i, "tenant_id": "acme"} for i in range(100)]}
    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml("policies/basic.yaml", connector)

    try:
        from datafence.integrations.langchain_tool import DataFenceTool

        actor = {"id": "test", "tenant_id": "acme"}
        tool = DataFenceTool(fence=fence, actor=actor)

        # Warmup
        for _ in range(10):
            tool._run(resource="users", fields=["id"], limit=10)

        # Benchmark
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                tool._run(resource="users", fields=["id"], limit=10)
                elapsed = time.perf_counter() - start
                result.add_time(elapsed)
            except Exception:
                result.add_error()

    except ImportError:
        print("⚠️  LangChain integration not installed")

    return result


def benchmark_schema_generation(iterations: int = 100) -> BenchmarkResult:
    """Benchmark schema generation performance."""
    result = BenchmarkResult("Schema Generation")

    # Setup
    data = {"users": []}
    connector = MemoryConnector(data=data)
    fence = DataFence.from_yaml("policies/basic.yaml", connector)

    try:
        from datafence.integrations.openai_adapter import OpenAIAdapter

        # Benchmark schema generation (not cached)
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                adapter = OpenAIAdapter(fence)
                functions = adapter.get_functions()
                elapsed = time.perf_counter() - start
                result.add_time(elapsed)
            except Exception:
                result.add_error()

    except ImportError:
        print("⚠️  OpenAI integration not installed")

    return result


def run_all_benchmarks(iterations: int = 1000):
    """Run all integration benchmarks."""
    print("=" * 60)
    print("DataFence Integration Benchmarks")
    print("=" * 60)
    print(f"Iterations per benchmark: {iterations}")

    benchmarks = [
        (benchmark_openai_adapter, iterations),
        (benchmark_claude_adapter, iterations),
        (benchmark_langchain_tool, iterations),
        (benchmark_schema_generation, 100),
    ]

    results = []
    for benchmark_func, iters in benchmarks:
        result = benchmark_func(iters)
        if result.times:  # Only print if benchmark ran
            result.print_summary()
            results.append(result)

    # Summary
    if results:
        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)
        for result in results:
            print(f"{result.name:40} {result.avg:>8.2f}ms (p95: {result.p95:.2f}ms)")


if __name__ == "__main__":
    import sys

    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    run_all_benchmarks(iterations)
