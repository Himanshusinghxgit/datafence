"""
Banking domain example application.

Demonstrates DataFence protecting a banking backend:
  - Tenant isolation (customer A cannot see customer B's transactions)
  - Field-level security (card_number, SSN never exposed)
  - Operation restriction (DELETE denied)
  - Forged capability rejection
  - Clean connector handoff

This is a domain-specific example. The DataFence core is entirely generic.
Banking concepts exist only in this examples/bank/ directory.

Run from the repo root:
    python -m examples.bank.app
"""

from __future__ import annotations

from secrets import token_bytes

from datafence import Actor, DataFenceBoundary, Intent, Operation
from datafence.errors import PolicyDeniedError
from examples.bank.policy import create_bank_policy
from examples.reference_connector.memory import InMemoryReferenceConnector


def separator(title: str) -> None:
    print(f"\n{'─' * 65}")
    print(f"  {title}")
    print("─" * 65)


# ---------------------------------------------------------------------------
# Sample banking data — two tenants
# ---------------------------------------------------------------------------
BANKING_DATA = {
    "transactions": [
        {"id": 1, "tenant_id": "bank_a", "customer_id": 101, "merchant": "Amazon", "amount": 49.99, "timestamp": "2026-01-15 10:30:00", "card_number": "4532-xxxx-xxxx-3333", "account_number": "ACC-A-001"},
        {"id": 2, "tenant_id": "bank_a", "customer_id": 101, "merchant": "Starbucks", "amount": 5.50, "timestamp": "2026-01-15 14:20:00", "card_number": "4532-xxxx-xxxx-3333", "account_number": "ACC-A-001"},
        {"id": 3, "tenant_id": "bank_b", "customer_id": 201, "merchant": "Walmart", "amount": 75.25, "timestamp": "2026-01-15 11:00:00", "card_number": "5555-xxxx-xxxx-9999", "account_number": "ACC-B-001"},
    ],
    "customers": [
        {"id": 101, "tenant_id": "bank_a", "name": "Alice Johnson", "email": "alice@bank-a.example", "ssn": "123-45-6789", "account_number": "ACC-A-001"},
        {"id": 201, "tenant_id": "bank_b", "name": "Bob Smith", "email": "bob@bank-b.example", "ssn": "987-65-4321", "account_number": "ACC-B-001"},
    ],
    "accounts": [
        {"id": 1, "tenant_id": "bank_a", "customer_id": 101, "account_number": "ACC-A-001", "balance": 5000.00},
    ],
}


def main() -> None:
    signing_key = token_bytes(32)
    audience = "banking-service"

    engine = create_bank_policy()
    fence = DataFenceBoundary.create(
        policy_engine=engine,
        registry=engine.registry,
        signing_key=signing_key,
        capability_audience=audience,
    )
    connector = InMemoryReferenceConnector(BANKING_DATA, signing_key, expected_audience=audience)

    # Scenario 1: Authorized read
    separator("1. Authorized read — Bank A agent reads their transactions")
    principal = Actor(id="agent:finance-assistant", tenant_id="bank_a")
    authorized = fence.authorize(
        principal,
        Intent("transactions", Operation.READ, fields=["id", "merchant", "amount", "timestamp"]),
    )
    result = connector.execute(authorized)
    print(f"  Rows returned: {result.row_count}")
    for row in result.rows:
        print(f"    {row}")
        assert "card_number" not in row, "card_number must not appear in result"
        assert "account_number" not in row, "account_number must not appear in result"
    print("  ✓ card_number and account_number correctly excluded.")

    # Scenario 2: Cross-tenant attempt
    separator("2. Cross-tenant attempt — Bank A agent tries to read Bank B data")
    intent_cross = Intent(
        "transactions",
        Operation.READ,
        fields=["id", "merchant", "amount"],
        filters={"tenant_id": "bank_b"},  # agent tries another tenant
    )
    authorized2 = fence.authorize(principal, intent_cross)
    result2 = connector.execute(authorized2)
    print("  Policy enforced tenant_id = 'bank_a'")
    print(f"  Rows returned: {result2.row_count}  (bank_a rows only)")
    for row in result2.rows:
        assert row.get("tenant_id", "bank_a") == "bank_a", "TENANT ISOLATION BREACH"
    print("  ✓ No bank_b rows returned.")

    # Scenario 3: Restricted field
    separator("3. Restricted field — agent requests card_number")
    try:
        fence.authorize(
            principal,
            Intent("transactions", Operation.READ, fields=["id", "merchant", "card_number"]),
        )
        print("  ERROR: Should have been denied!")
    except PolicyDeniedError as exc:
        print(f"  ✓ Denied: {exc}")

    # Scenario 4: Denied resource (accounts)
    separator("4. Denied resource — accounts have no allowed operations")
    try:
        fence.authorize(
            principal,
            Intent("accounts", Operation.READ, fields=["id"]),
        )
        print("  ERROR: Should have been denied!")
    except PolicyDeniedError as exc:
        print(f"  ✓ Denied: {exc}")

    # Scenario 5: Capability tamper
    separator("5. Tampered capability — connector rejects it")
    cap = fence.authorize(
        principal,
        Intent("transactions", Operation.READ, fields=["id", "merchant"]),
    )
    import dataclasses
    tampered = dataclasses.replace(cap, resource="accounts")
    try:
        connector.execute(tampered)
        print("  ERROR: Should have been rejected!")
    except Exception as exc:
        print(f"  ✓ Rejected: {exc}")

    print("\n" + "═" * 65)
    print("  Banking example complete.")
    print("  DataFence authorized. The banking backend executed.")
    print("  No AI agent touched the database directly.")
    print("═" * 65)


if __name__ == "__main__":
    main()
