"""
Basic DataFence example — generic enterprise authorization.

Demonstrates the complete flow:

    Authentication (application-owned)
        ↓
    Principal + Intent
        ↓
    DataFenceBoundary.authorize()          ← DataFence decides
        ↓
    AuthorizedExecution (signed capability)
        ↓
    Customer connector.execute()           ← Customer executes
        ↓
    ConnectorResult

Run from the repo root:
    python -m examples.basic.application
"""

from __future__ import annotations

from secrets import token_bytes

from datafence import CapabilityVerifier, DataFenceBoundary, Intent, Operation, Principal
from datafence.errors import PolicyDeniedError
from examples.basic.connector import create_example_connector
from examples.basic.policy import create_policy


def separator(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print("─" * 60)


def main() -> None:
    # ── Setup ────────────────────────────────────────────────────────
    # The signing key is shared between the boundary (DataFence) and the
    # customer connector verifier.  Keep it secret.
    signing_key = token_bytes(32)
    audience = "basic-example-service"

    # Build policy engine (creates registry internally).
    engine = create_policy()

    # Create the DataFence boundary.
    fence = DataFenceBoundary.create(
        policy_engine=engine,
        registry=engine.registry,
        signing_key=signing_key,
        capability_audience=audience,
    )

    # Customer-owned connector — DataFence never touches this.
    connector = create_example_connector(signing_key, audience=audience)

    # ── Scenario 1: authorized read ──────────────────────────────────
    separator("1. Authorized read — ACME tenant reads their orders")

    principal = Principal(id="user:alice", tenant_id="acme")
    intent = Intent(
        resource="orders",
        operation=Operation.READ,
        fields=["id", "total", "status"],
        limit=10,
    )

    authorized = fence.authorize(principal, intent)
    print(f"  Authorization granted:  {authorized.execution_id}")
    print(f"  Authorized fields:      {authorized.selected_fields}")
    print(f"  Enforced predicates:    {authorized.filter_constraints()}")
    print(f"  Row limit:              {authorized.limit}")

    # Customer connector verifies + executes.
    result = connector.execute(authorized)
    print(f"  Rows returned:          {result.row_count}")
    for row in result.rows:
        print(f"    {row}")

    # ── Scenario 2: tenant isolation ─────────────────────────────────
    separator("2. Tenant isolation — ACME agent cannot read Globex orders")

    # The LLM proposes a filter for a different tenant.
    intent_cross_tenant = Intent(
        resource="orders",
        operation=Operation.READ,
        fields=["id", "total"],
        filters={"tenant_id": "globex"},  # agent tries another tenant
    )
    authorized2 = fence.authorize(principal, intent_cross_tenant)
    result2 = connector.execute(authorized2)
    print("  Policy enforced tenant_id = 'acme' regardless of agent request.")
    print(f"  Rows returned for ACME:   {result2.row_count}")
    for row in result2.rows:
        assert row.get("tenant_id", "acme") == "acme", "TENANT ISOLATION BREACH"
    print("  ✓ No Globex rows returned — tenant isolation holds.")

    # ── Scenario 3: restricted field blocked ─────────────────────────
    separator("3. Restricted field — agent cannot access SSN")

    try:
        fence.authorize(
            principal,
            Intent("customers", Operation.READ, fields=["id", "name", "ssn"]),
        )
        print("  ERROR: Should have been denied!")
    except PolicyDeniedError as exc:
        print(f"  ✓ Denied as expected:  {exc}")

    # ── Scenario 4: unknown resource blocked ─────────────────────────
    separator("4. Unknown resource — agent requests unregistered data source")

    try:
        fence.authorize(
            principal,
            Intent("employee_salaries", Operation.READ),
        )
        print("  ERROR: Should have been denied!")
    except PolicyDeniedError as exc:
        print(f"  ✓ Denied as expected:  {exc}")

    # ── Scenario 5: denied operation ─────────────────────────────────
    separator("5. Denied operation — agent attempts DELETE")

    try:
        fence.authorize(
            principal,
            Intent("orders", Operation.DELETE),
        )
        print("  ERROR: Should have been denied!")
    except PolicyDeniedError as exc:
        print(f"  ✓ Denied as expected:  {exc}")

    # ── Scenario 6: forged capability rejected ───────────────────────
    separator("6. Forged capability — connector rejects tampered capability")

    legitimate = fence.authorize(
        principal,
        Intent("orders", Operation.READ, fields=["id", "total"]),
    )
    # Attacker tries to change the resource in the capability.
    import dataclasses
    forged = dataclasses.replace(legitimate, resource="employee_salaries")
    try:
        connector.execute(forged)
        print("  ERROR: Should have been rejected!")
    except Exception as exc:
        print(f"  ✓ Forged capability rejected:  {exc}")

    # ── Scenario 7: capability verification ──────────────────────────
    separator("7. CapabilityVerifier — customer side verification")

    verifier = CapabilityVerifier(signing_key, expected_audience=audience)
    cap = fence.authorize(
        principal,
        Intent("documents", Operation.READ, fields=["id", "title"]),
    )
    verifier.verify(cap)   # raises on any failure
    print(f"  ✓ Capability verified:  {cap.execution_id}")
    print(f"  Policy version:         {cap.policy_version}")

    print("\n" + "═" * 60)
    print("  Summary: DataFence authorized. Customer connector executed.")
    print("  The AI never touched the database directly.")
    print("═" * 60)


if __name__ == "__main__":
    main()
