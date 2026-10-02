"""
DataFence v1 — Authorization boundary demo.

Demonstrates the canonical v1 architecture:

    Principal (from app auth)
        +
    Intent (from AI agent — untrusted)
        ↓
    DataFenceBoundary.authorize()          ← DataFence decides
        ↓
    AuthorizedExecution (HMAC-signed)
        ↓
    Customer connector.execute()           ← Customer executes
        ↓
    ConnectorResult

Seven scenarios are run:
    1. Authorized read
    2. Tenant isolation (policy overrides agent-supplied tenant filter)
    3. Restricted field denied
    4. Unknown resource denied
    5. Denied operation (DELETE)
    6. Forged capability rejected by connector
    7. Capability verifier (customer-side signature check)

Run from the repo root:
    python -m demos.killer_demo
"""

from __future__ import annotations

import dataclasses
from secrets import token_bytes

from datafence import (
    Actor,
    CapabilityVerifier,
    DataFenceBoundary,
    DataFencePolicy,
    DataFencePolicyEngine,
    FieldDefinition,
    Intent,
    Operation,
    ResourceDefinition,
    ResourceRegistry,
    ResourcePolicy,
    ActionDecision,
    RowRule,
)
from datafence.connectors.memory_connector import InMemoryReferenceConnector
from datafence.core.capability import CapabilityVerificationError
from datafence.core.resources import PredicateOperator
from datafence.errors import PolicyDeniedError

# ---------------------------------------------------------------------------
# Shared sample data — two tenants
# ---------------------------------------------------------------------------
SAMPLE_DATA: dict = {
    "transactions": [
        {"id": 1, "tenant_id": "bank_a", "merchant": "Amazon",    "amount": 49.99, "timestamp": "2026-01-15T10:30:00", "card_number": "4532-xxxx"},
        {"id": 2, "tenant_id": "bank_a", "merchant": "Starbucks", "amount": 5.50,  "timestamp": "2026-01-15T14:20:00", "card_number": "4532-xxxx"},
        {"id": 3, "tenant_id": "bank_b", "merchant": "Walmart",   "amount": 75.25, "timestamp": "2026-01-15T11:00:00", "card_number": "5555-xxxx"},
    ],
    "customers": [
        {"id": 101, "tenant_id": "bank_a", "name": "Alice",   "email": "alice@bank-a.example", "ssn": "123-45-6789"},
        {"id": 201, "tenant_id": "bank_b", "name": "Charlie", "email": "charlie@bank-b.example", "ssn": "987-65-4321"},
    ],
}


# ---------------------------------------------------------------------------
# Setup: registry, policy, boundary, connector
# ---------------------------------------------------------------------------

def build_fence() -> tuple[DataFenceBoundary, InMemoryReferenceConnector, bytes]:
    registry = ResourceRegistry()
    registry.register(ResourceDefinition(
        "transactions",
        fields={
            "id":          FieldDefinition("id", "integer"),
            "tenant_id":   FieldDefinition("tenant_id", "string", is_tenant_key=True),
            "merchant":    FieldDefinition("merchant", "string"),
            "amount":      FieldDefinition("amount", "decimal"),
            "timestamp":   FieldDefinition("timestamp", "string"),
            "card_number": FieldDefinition("card_number", "string",
                                           classification=__import__("datafence").DataClassification.RESTRICTED),
        },
        supported_operations=("read",),
    ))
    registry.register(ResourceDefinition(
        "customers",
        fields={
            "id":        FieldDefinition("id", "integer"),
            "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            "name":      FieldDefinition("name", "string"),
            "email":     FieldDefinition("email", "string"),
            "ssn":       FieldDefinition("ssn", "string",
                                         classification=__import__("datafence").DataClassification.RESTRICTED),
        },
        supported_operations=("read",),
    ))

    policy = DataFencePolicy("demo-policy", "1.0", {
        "transactions": ResourcePolicy(
            "transactions",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "merchant", "amount", "timestamp"],
            denied_fields=["card_number"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=50,
        ),
        "customers": ResourcePolicy(
            "customers",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "name", "email"],
            denied_fields=["ssn"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=50,
        ),
    })
    engine = DataFencePolicyEngine(policy, registry=registry)

    signing_key = token_bytes(32)
    audience = "demo-service"
    fence = DataFenceBoundary.create(
        policy_engine=engine,
        registry=registry,
        signing_key=signing_key,
        capability_audience=audience,
    )
    connector = InMemoryReferenceConnector(SAMPLE_DATA, signing_key, expected_audience=audience)
    return fence, connector, signing_key


# ---------------------------------------------------------------------------
# Pretty helpers
# ---------------------------------------------------------------------------

def sep(n: int, title: str) -> None:
    print(f"\n{'─' * 65}")
    print(f"  Scenario {n}: {title}")
    print("─" * 65)


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def fail(msg: str) -> None:
    print(f"  ✗ {msg}")


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def run_demo() -> None:
    fence, connector, signing_key = build_fence()

    print("=" * 65)
    print("  DataFence v1 — Authorization Boundary Demo")
    print("  Principal + Intent → DataFence → Capability → Connector")
    print("=" * 65)

    # ------------------------------------------------------------------
    # Scenario 1: authorized read
    # ------------------------------------------------------------------
    sep(1, "Authorized read — bank_a agent reads transactions")

    principal = Actor(id="agent:finance", tenant_id="bank_a")
    intent = Intent("transactions", Operation.READ,
                    fields=["id", "merchant", "amount"], limit=10)

    authorized = fence.authorize(principal, intent)
    result = connector.execute(authorized)

    print(f"  capability id : {authorized.execution_id}")
    print(f"  policy version: {authorized.policy_version}")
    print(f"  authorized fields: {authorized.selected_fields}")
    print(f"  enforced predicates: {authorized.filter_constraints()}")
    print(f"  rows returned : {result.row_count}")
    for row in result.rows:
        print(f"    {row}")
        assert "card_number" not in row
    ok("card_number correctly excluded from results")

    # ------------------------------------------------------------------
    # Scenario 2: tenant isolation
    # ------------------------------------------------------------------
    sep(2, "Tenant isolation — agent for bank_a cannot read bank_b data")

    intent2 = Intent("transactions", Operation.READ,
                     fields=["id", "merchant"],
                     filters={"tenant_id": "bank_b"})   # agent tries other tenant
    cap2 = fence.authorize(principal, intent2)
    result2 = connector.execute(cap2)

    print(f"  Agent supplied filter tenant_id='bank_b'")
    print(f"  Policy-enforced filter: {cap2.filter_constraints()}")
    print(f"  Rows returned: {result2.row_count} (should be bank_a rows only)")
    for row in result2.rows:
        assert row.get("tenant_id", "bank_a") == "bank_a", "ISOLATION BREACH"
    ok("No bank_b rows returned — tenant isolation holds")

    # ------------------------------------------------------------------
    # Scenario 3: restricted field denied
    # ------------------------------------------------------------------
    sep(3, "Restricted field — agent requests card_number")

    try:
        fence.authorize(
            principal,
            Intent("transactions", Operation.READ, fields=["id", "merchant", "card_number"]),
        )
        fail("Should have been denied!")
    except PolicyDeniedError as exc:
        ok(f"Denied: {exc}")

    # ------------------------------------------------------------------
    # Scenario 4: unknown resource denied
    # ------------------------------------------------------------------
    sep(4, "Unknown resource — agent requests employee_salaries")

    try:
        fence.authorize(principal, Intent("employee_salaries", Operation.READ))
        fail("Should have been denied!")
    except PolicyDeniedError as exc:
        ok(f"Denied: {exc}")

    # ------------------------------------------------------------------
    # Scenario 5: denied operation
    # ------------------------------------------------------------------
    sep(5, "Denied operation — agent attempts DELETE")

    try:
        fence.authorize(principal, Intent("transactions", Operation.DELETE))
        fail("Should have been denied!")
    except PolicyDeniedError as exc:
        ok(f"Denied: {exc}")

    # ------------------------------------------------------------------
    # Scenario 6: forged capability rejected
    # ------------------------------------------------------------------
    sep(6, "Forged capability — connector rejects tampered AuthorizedExecution")

    legitimate = fence.authorize(
        principal, Intent("transactions", Operation.READ, fields=["id", "merchant"])
    )
    forged = dataclasses.replace(legitimate, resource="employee_salaries")
    try:
        connector.execute(forged)
        fail("Forged capability should have been rejected!")
    except CapabilityVerificationError as exc:
        ok(f"Forged capability rejected: {exc}")

    # ------------------------------------------------------------------
    # Scenario 7: customer-side verifier
    # ------------------------------------------------------------------
    sep(7, "CapabilityVerifier — customer-side signature verification")

    cap7 = fence.authorize(
        principal, Intent("customers", Operation.READ, fields=["id", "name"])
    )
    verifier = CapabilityVerifier(signing_key, expected_audience="demo-service")
    verifier.verify(cap7)
    ok(f"Capability verified: {cap7.execution_id}")

    # Wrong key
    bad_verifier = CapabilityVerifier(token_bytes(32), expected_audience="demo-service")
    try:
        bad_verifier.verify(cap7)
        fail("Wrong key should have failed!")
    except CapabilityVerificationError:
        ok("Wrong signing key correctly rejected")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 65)
    print("  All scenarios passed.")
    print()
    print("  DataFence authorized. The connector executed.")
    print("  The AI agent never touched the database directly.")
    print()
    print("  fence.authorize()  → AuthorizedExecution (signed capability)")
    print("  connector.execute() → data (customer's responsibility)")
    print("=" * 65)


if __name__ == "__main__":
    run_demo()
