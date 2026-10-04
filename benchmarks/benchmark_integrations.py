"""
DataFence v0.1 integration adapter benchmarks.

Measures per-call overhead of the OpenAI, Anthropic, and LangChain adapters.
No actual network calls are made — only the authorization boundary is exercised.

Run:
    python -m benchmarks.benchmark_integrations
"""

from __future__ import annotations

import json
import statistics
import time
from secrets import token_bytes

from datafence import (
    ActionDecision,
    DataFenceBoundary,
    DataFencePolicy,
    DataFencePolicyEngine,
    FieldDefinition,
    Principal,
    ResourceDefinition,
    ResourcePolicy,
    ResourceRegistry,
    RowRule,
)
from datafence.core.resources import PredicateOperator
from datafence.integrations.openai_tool import DataFenceOpenAITool
from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
from datafence.integrations.langchain_tool import DataFenceLangChainTool


def _make_boundary() -> DataFenceBoundary:
    registry = ResourceRegistry()
    registry.register(ResourceDefinition(
        "orders",
        fields={
            "id":        FieldDefinition("id", "integer"),
            "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            "total":     FieldDefinition("total", "decimal"),
            "status":    FieldDefinition("status", "string"),
        },
        supported_operations=("read",),
    ))
    policy = DataFencePolicy("bench", "1.0", {"orders": ResourcePolicy(
        "orders",
        actions={"read": ActionDecision.ALLOW},
        allowed_fields=["id", "tenant_id", "total", "status"],
        filterable_fields=["id", "tenant_id", "status"],
        row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
        max_rows=50,
    )})
    engine = DataFencePolicyEngine(policy, registry=registry)
    return DataFenceBoundary.create(engine, registry, token_bytes(32), capability_audience="bench")


def bench(name: str, fn: "callable", iterations: int = 500) -> None:
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    mean_ms = statistics.mean(times) * 1000
    p99_ms = sorted(times)[int(0.99 * len(times))] * 1000
    print(f"  {name:<45} mean={mean_ms:.3f}ms  p99={p99_ms:.3f}ms")


def main() -> None:
    boundary = _make_boundary()
    principal = Principal("user:alice", "tenant-acme")
    args_json = json.dumps({"resource": "orders", "fields": ["id", "total"], "limit": 5})

    openai_tool = DataFenceOpenAITool(boundary)
    anthropic_tool = DataFenceAnthropicTool(boundary)
    lc_tool = DataFenceLangChainTool(boundary, principal)

    print("DataFence v0.1 integration benchmarks")
    print("=" * 70)
    bench("OpenAI handle_call()", lambda: openai_tool.handle_call(principal, args_json))
    bench("Anthropic handle_call()", lambda: anthropic_tool.handle_call(
        principal, json.loads(args_json)
    ))
    bench("LangChain run()", lambda: lc_tool.run(args_json))
    print()


if __name__ == "__main__":
    main()
