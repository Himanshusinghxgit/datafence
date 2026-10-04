"""
DataFence v0.1 performance benchmarks.

Measures the authorization boundary throughput — policy evaluation and
capability issuance — without any database I/O.

Run:
    python -m benchmarks.benchmark_core
"""

from __future__ import annotations

import statistics
import time
from secrets import token_bytes

from datafence import (
    ActionDecision,
    DataFenceBoundary,
    DataFencePolicy,
    DataFencePolicyEngine,
    FieldDefinition,
    Intent,
    Operation,
    Principal,
    ResourceDefinition,
    ResourcePolicy,
    ResourceRegistry,
    RowRule,
)
from datafence.core.capability import CapabilityToken
from datafence.core.resources import PredicateOperator


def _make_boundary() -> tuple[DataFenceBoundary, bytes]:
    registry = ResourceRegistry()
    registry.register(ResourceDefinition(
        "orders",
        fields={
            "id":        FieldDefinition("id", "integer"),
            "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            "total":     FieldDefinition("total", "decimal"),
            "status":    FieldDefinition("status", "string"),
            "merchant":  FieldDefinition("merchant", "string"),
        },
        supported_operations=("read",),
    ))
    policy = DataFencePolicy("bench", "1.0", {"orders": ResourcePolicy(
        "orders",
        actions={"read": ActionDecision.ALLOW},
        allowed_fields=["id", "tenant_id", "total", "status", "merchant"],
        filterable_fields=["id", "tenant_id", "status"],
        row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
        max_rows=100,
    )})
    engine = DataFencePolicyEngine(policy, registry=registry)
    key = token_bytes(32)
    return DataFenceBoundary.create(engine, registry, key, capability_audience="bench"), key


def bench(name: str, fn: "callable", iterations: int = 1000) -> None:
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)

    mean_ms = statistics.mean(times) * 1000
    p99_ms = sorted(times)[int(0.99 * len(times))] * 1000
    print(f"  {name:<45} mean={mean_ms:.3f}ms  p99={p99_ms:.3f}ms  n={iterations}")


def main() -> None:
    boundary, key = _make_boundary()
    principal = Principal("user:alice", "tenant-acme")
    intent = Intent("orders", Operation.READ, ["id", "total", "status"])

    print("DataFence v0.1 benchmarks")
    print("=" * 70)
    print()

    # Authorize (registry + policy evaluation + HMAC signing)
    bench("authorize()", lambda: boundary.authorize(principal, intent))

    # Authorize + encode to CapabilityToken
    def authorize_and_encode() -> None:
        cap = boundary.authorize(principal, intent)
        CapabilityToken.encode(cap)

    bench("authorize() + CapabilityToken.encode()", authorize_and_encode)

    # Token decode + verify
    cap = boundary.authorize(principal, intent)
    token = CapabilityToken.encode(cap)
    from datafence import CapabilityVerifier
    verifier = CapabilityVerifier(key, expected_audience="bench")
    bench("CapabilityVerifier.verify_token()", lambda: verifier.verify_token(token))

    print()


if __name__ == "__main__":
    main()
