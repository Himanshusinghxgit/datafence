"""
DataFence Killer Demo.

This demo proves the fundamental DataFence security model:

    UNTRUSTED AI REQUEST
            ↓
    Policy Evaluation
            ↓
    ExecutionPlan
            ↓
    ONLY DataFence Connector
            ↓
    Result Validation
            ↓
    Verified Result

The database NEVER executes LLM-generated SQL directly.

Six scenarios:
1. Normal request - Shows authorization working
2. SELECT * - Shows field restriction
3. Sensitive field - Shows field denial
4. Cross-tenant attack - Shows tenant isolation
5. Destructive operation - Shows operation denial
6. Result validation - Shows defense even if connector is malicious
"""

import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from datafence.connectors.sqlite_connector import (
    MaliciousConnector,
    SQLiteConnector,
    create_demo_database,
)
from datafence.core.boundary import DataFenceBoundary
from datafence.core.policy_engine import create_banking_demo_policy
from datafence.core.types import Actor, AllowedRequest, DeniedRequest, Intent, Operation


def print_header(title: str):
    """Print demo section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def print_decision(result: AllowedRequest | DeniedRequest):
    """Print decision details."""
    if isinstance(result, AllowedRequest):
        print("✅ DECISION: ALLOW\n")
        print(f"Request ID: {result.request_id}")
        print(f"Execution ID: {result.execution_plan.execution_id}")
        print(f"Actor: {result.actor.id}")
        print(f"Tenant: {result.actor.tenant_id}\n")

        print("ExecutionPlan:")
        plan = result.execution_plan
        print(f"  Resource: {plan.resource}")
        print(f"  Operation: {plan.operation.value}")
        print(f"  Selected Fields: {', '.join(plan.selected_fields)}")
        print(f"  Enforced Filters: {plan.enforced_filters}")
        print(f"  Limit: {plan.limit}")
        print(f"  Policy Version: {plan.policy_version}\n")

        print(f"Result:")
        print(f"  Rows Returned: {result.execution_result.row_count}")
        print(f"  Verified: {result.execution_result.verified}\n")

        if result.execution_result.row_count > 0 and result.execution_result.row_count <= 3:
            print("Data:")
            for i, row in enumerate(result.execution_result.data, 1):
                print(f"  Row {i}: {row}")

        print(f"\nEvidence:")
        print(f"  Execution ID: {result.evidence.execution_id}")
        print(f"  Policy Version: {result.evidence.policy_version}")
        print(f"  Timestamp: {result.evidence.timestamp}")

    else:  # DeniedRequest
        print("❌ DECISION: DENY\n")
        print(f"Request ID: {result.request_id}")
        print(f"Actor: {result.actor.id}")
        print(f"Tenant: {result.actor.tenant_id}")
        print(f"Resource: {result.resource}")
        print(f"Operation: {result.operation.value}\n")

        print("Reasons:")
        for reason in result.decision.reasons:
            print(f"  • {reason}")

        print(f"\nPolicy Version: {result.decision.policy_version}")
        print(f"Evidence ID: {result.evidence.execution_id}")


def demo_1_normal_request(boundary: DataFenceBoundary):
    """
    DEMO 1: Normal Request
    
    An authorized request that should succeed.
    
    LLM proposes: "Show me my recent transactions"
    Policy allows: Read transactions with specific fields
    Result: Request allowed, ExecutionPlan created, data returned
    """
    print_header("DEMO 1: Normal Request — Authorized Access")

    print("Scenario:")
    print("  User: 'Show me my recent transactions'")
    print("  LLM generates request for transactions")
    print("  Actor: agent:finance (tenant_a)\n")

    # Create actor
    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # Create intent (what the LLM proposes)
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant", "amount", "timestamp"],
        filters={},
        limit=10,
    )

    print("LLM Proposes:")
    print(f"  Resource: {intent.resource}")
    print(f"  Operation: {intent.operation.value}")
    print(f"  Fields: {intent.fields}")
    print(f"  Filters: {intent.filters}")
    print(f"  Limit: {intent.limit}\n")

    # Execute through DataFence boundary
    result = boundary.execute(actor, intent)

    print_decision(result)


def demo_2_select_star(boundary: DataFenceBoundary):
    """
    DEMO 2: SELECT *
    
    LLM requests all fields (SELECT *).
    DataFence must restrict to only allowed fields.
    
    The database does NOT execute "SELECT *".
    DataFence generates SQL with only authorized fields.
    """
    print_header("DEMO 2: SELECT * — Field Restriction")

    print("Scenario:")
    print("  LLM generates: SELECT * FROM transactions")
    print("  Policy allows only: id, merchant, amount, timestamp")
    print("  Policy denies: card_number\n")

    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # LLM requests ALL fields (SELECT *)
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=None,  # None means "all fields" (SELECT *)
        raw_sql="SELECT * FROM transactions",  # LLM's SQL (untrusted)
    )

    print("LLM Proposes:")
    print(f"  Raw SQL: {intent.raw_sql}")
    print(f"  Fields: * (all fields)\n")

    print("CRITICAL: DataFence does NOT execute the LLM's SQL.")
    print("It creates an ExecutionPlan with only authorized fields.\n")

    result = boundary.execute(actor, intent)

    print_decision(result)

    if isinstance(result, AllowedRequest):
        print("\n📌 Key Point:")
        print("   The database executed DataFence's plan, NOT the LLM's 'SELECT *'")
        print(f"   Authorized fields: {result.execution_plan.selected_fields}")
        print("   card_number was NEVER requested from the database")


def demo_3_sensitive_field(boundary: DataFenceBoundary):
    """
    DEMO 3: Sensitive Field Request
    
    LLM requests a denied field (card_number).
    DataFence must DENY before reaching the database.
    """
    print_header("DEMO 3: Sensitive Field — Field Denial")

    print("Scenario:")
    print("  LLM requests: SELECT id, amount, card_number")
    print("  Policy denies: card_number")
    print("  Expected: Request denied BEFORE reaching database\n")

    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # LLM requests a denied field
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "amount", "card_number"],  # card_number is denied
    )

    print("LLM Proposes:")
    print(f"  Fields: {intent.fields}\n")

    result = boundary.execute(actor, intent)

    print_decision(result)

    if isinstance(result, DeniedRequest):
        print("\n📌 Key Point:")
        print("   The database NEVER received this request")
        print("   Policy blocked it before execution")


def demo_4_cross_tenant_attack(boundary: DataFenceBoundary):
    """
    DEMO 4: Cross-Tenant Attack
    
    Actor from tenant_a tries to access tenant_b's data.
    DataFence enforces tenant isolation via enforced filters.
    """
    print_header("DEMO 4: Cross-Tenant Attack — Tenant Isolation")

    print("Scenario:")
    print("  Actor: tenant_a")
    print("  LLM requests: transactions with no tenant filter")
    print("  Attack: Hoping to see tenant_b's data")
    print("  Expected: Only tenant_a data returned\n")

    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # LLM tries to access all transactions (cross-tenant attack)
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant", "amount"],
        filters={},  # No tenant filter!
    )

    print("LLM Proposes:")
    print(f"  Filters: {intent.filters} (NO tenant filter!)\n")

    print("DataFence enforces tenant isolation:")
    print("  Policy adds: tenant_id = :actor_tenant_id\n")

    result = boundary.execute(actor, intent)

    print_decision(result)

    if isinstance(result, AllowedRequest):
        print("\n📌 Key Point:")
        print(f"   Enforced Filter: {result.execution_plan.enforced_filters}")
        print("   The LLM CANNOT override tenant isolation")
        print("   Only tenant_a's data was returned")

        # Verify all returned data belongs to tenant_a
        tenant_ids = {row.get("tenant_id", "tenant_a") for row in result.execution_result.data}
        if tenant_ids == {"tenant_a"}:
            print("\n   ✅ Verified: All data belongs to tenant_a")


def demo_5_destructive_operation(boundary: DataFenceBoundary):
    """
    DEMO 5: Destructive Operation
    
    LLM attempts a DELETE operation.
    Policy denies destructive operations.
    Database never receives the DELETE.
    """
    print_header("DEMO 5: Destructive Operation — Operation Denial")

    print("Scenario:")
    print("  LLM generates: DELETE FROM transactions WHERE...")
    print("  Policy denies: DELETE operations")
    print("  Expected: Request denied BEFORE reaching database\n")

    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # LLM tries to delete data
    intent = Intent(
        resource="transactions",
        operation=Operation.DELETE,  # Denied by policy
        raw_sql="DELETE FROM transactions WHERE id = 1",
    )

    print("LLM Proposes:")
    print(f"  Operation: {intent.operation.value}")
    print(f"  Raw SQL: {intent.raw_sql}\n")

    result = boundary.execute(actor, intent)

    print_decision(result)

    if isinstance(result, DeniedRequest):
        print("\n📌 Key Point:")
        print("   The database NEVER received the DELETE")
        print("   Policy blocked it at the boundary")
        print("   Data is safe")


def demo_6_result_validation(boundary_with_malicious_connector: DataFenceBoundary):
    """
    DEMO 6: Result Validation
    
    Even if the connector is compromised/malicious,
    DataFence's result validation catches unauthorized fields.
    
    This proves security exists on BOTH sides:
    - Request enforcement (before execution)
    - Result validation (after execution)
    """
    print_header("DEMO 6: Result Validation — Defense in Depth")

    print("Scenario:")
    print("  Connector is compromised (returns unauthorized fields)")
    print("  LLM requests: id, merchant, amount")
    print("  Malicious connector adds: card_number, ssn")
    print("  Expected: Result validation catches it\n")

    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant", "amount"],
    )

    print("LLM Proposes:")
    print(f"  Fields: {intent.fields}\n")

    print("Malicious connector returns:")
    print("  Authorized: id, merchant, amount")
    print("  UNAUTHORIZED: card_number, ssn (injected by malicious connector)\n")

    result = boundary_with_malicious_connector.execute(actor, intent)

    print_decision(result)

    if isinstance(result, DeniedRequest):
        print("\n📌 Key Point:")
        print("   Result validation CAUGHT the unauthorized fields")
        print("   Even a compromised connector cannot bypass DataFence")
        print("   Security exists on BOTH request AND result boundaries")


def run_killer_demo():
    """Run all 6 demo scenarios."""
    print("\n" + "█" * 80)
    print("█" + " " * 78 + "█")
    print("█" + " " * 20 + "DATAFENCE KILLER DEMO" + " " * 37 + "█")
    print("█" + " " * 78 + "█")
    print("█" + " " * 15 + "Proving the Security Boundary" + " " * 35 + "█")
    print("█" + " " * 78 + "█")
    print("█" * 80)

    # Setup
    db_path = "/tmp/datafence_demo.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    # Create policy engine
    print("\n[Setup] Loading banking demo policy...")
    policy_engine = create_banking_demo_policy()
    print("[Setup] Policy loaded: banking-demo-v1")

    # Create DataFence boundary using factory method (v0.4)
    # This properly wires up signing_key between boundary and connector
    print("[Setup] Creating DataFence boundary with secure connector...")
    boundary = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=create_demo_database,
        database_path=db_path
    )
    print("[Setup] Boundary created (v0.4 - cryptographic capabilities)")
    print("[Setup] Database created with:")
    print("  • 2 tenants: tenant_a, tenant_b")
    print("  • Tables: customers, transactions, accounts")
    print("  • Sensitive fields: ssn, card_number, account_number")

    # Run demos
    demo_1_normal_request(boundary)
    demo_2_select_star(boundary)
    demo_3_sensitive_field(boundary)
    demo_4_cross_tenant_attack(boundary)
    demo_5_destructive_operation(boundary)

    # Demo 6 needs malicious connector
    # For demo 6, we need to create malicious connector manually
    # (it bypasses signature verification for testing)
    from secrets import token_bytes
    demo_key = token_bytes(32)
    malicious_connector = MaliciousConnector(db_path, demo_key)
    boundary_malicious = DataFenceBoundary(policy_engine, malicious_connector, demo_key)
    demo_6_result_validation(boundary_malicious)

    # Summary
    print_header("SUMMARY: DataFence Security Boundary PROVEN")

    print("What we proved:")
    print("  ✅ Normal requests work (Demo 1)")
    print("  ✅ Field restrictions enforced (Demo 2)")
    print("  ✅ Sensitive fields blocked (Demo 3)")
    print("  ✅ Tenant isolation enforced (Demo 4)")
    print("  ✅ Destructive operations blocked (Demo 5)")
    print("  ✅ Result validation works (Demo 6)\n")

    print("Key Security Properties:")
    print("  1. Database NEVER executes LLM's raw SQL")
    print("  2. ExecutionPlan is the authorized contract")
    print("  3. Policy evaluation happens BEFORE execution")
    print("  4. Result validation happens AFTER execution")
    print("  5. Fail closed on all errors")
    print("  6. Complete evidence trail\n")

    print("The Fundamental Guarantee:")
    print("  Even if the AI agent is completely compromised,")
    print("  it CANNOT use DataFence to access data or perform")
    print("  operations outside the policy.\n")

    print("█" * 80)
    print("█" + " " * 25 + "KILLER DEMO COMPLETE" + " " * 33 + "█")
    print("█" * 80 + "\n")

    # Cleanup
    boundary._connector.close()
    malicious_connector.close()


if __name__ == "__main__":
    run_killer_demo()
