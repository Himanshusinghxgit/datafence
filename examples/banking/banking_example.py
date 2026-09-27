"""
Banking example showing tenant isolation and field-level security.

Demonstrates:
- Row-level filtering (tenant isolation)
- Column-level security (no card numbers)
- Policy enforcement against compromised agent attempts
"""

from pathlib import Path

from datafence import DataFence
from datafence.connectors.memory import MemoryConnector

# Get the path to the policy file
REPO_ROOT = Path(__file__).parent.parent.parent
POLICY_PATH = REPO_ROOT / "policies" / "banking.yaml"

# Create sample transaction data
transactions_data = [
    {
        "transaction_id": "tx_001",
        "customer_id": "123",
        "merchant": "Coffee Shop",
        "amount": 4.50,
        "currency": "USD",
        "timestamp": "2026-09-15T08:30:00",
        "category": "food",
        "card_number": "4111111111111111",
        "cvv": "123",
    },
    {
        "transaction_id": "tx_002",
        "customer_id": "123",
        "merchant": "Gas Station",
        "amount": 45.00,
        "currency": "USD",
        "timestamp": "2026-09-16T17:45:00",
        "category": "transport",
        "card_number": "4111111111111111",
        "cvv": "123",
    },
    {
        "transaction_id": "tx_003",
        "customer_id": "456",
        "merchant": "Restaurant",
        "amount": 67.50,
        "currency": "USD",
        "timestamp": "2026-09-17T19:00:00",
        "category": "food",
        "card_number": "4222222222222222",
        "cvv": "456",
    },
]

# Create connector
connector = MemoryConnector({"transactions": transactions_data})

# Create DataFence with banking policy
fence = DataFence.from_yaml(POLICY_PATH, connector)

print("=" * 70)
print("DataFence Banking Example - Tenant Isolation & Security")
print("=" * 70)

# Example 1: Authorized customer access
print("\n1. AUTHORIZED ACCESS - Customer 123")
print("-" * 70)

result = fence.execute(
    {
        "actor": {
            "id": "agent:finance-assistant",
            "type": "agent",
            "attributes": {"customer_id": "123"},
        },
        "operation": "read",
        "resource": "transactions",
        "fields": ["transaction_id", "merchant", "amount", "timestamp"],
        "filters": {"customer_id": "123"},
    }
)

print(f"Status: {result}")
print(f"Rows returned: {result.row_count}")
print(f"Data: {result.data}")
print(f"Policy: {result.decision.policy_name}")

# Example 2: Attempt to access another customer's data
print("\n2. DENIED - Cross-tenant access attempt")
print("-" * 70)
print("Agent for customer 123 tries to access customer 456's data...")

result = fence.execute(
    {
        "actor": {
            "id": "agent:finance-assistant",
            "type": "agent",
            "attributes": {"customer_id": "123"},
        },
        "operation": "read",
        "resource": "transactions",
        "fields": ["transaction_id", "merchant", "amount"],
        "filters": {
            "customer_id": "456"  # Different customer!
        },
    }
)

print(f"Status: {result}")
print(f"Decision: {result.decision.status}")
print(f"Reasons: {result.decision.reasons}")

# Example 3: Attempt to access card number
print("\n3. DENIED - Attempting to access card_number")
print("-" * 70)

result = fence.execute(
    {
        "actor": {
            "id": "agent:compromised-agent",
            "type": "agent",
            "attributes": {"customer_id": "123"},
        },
        "operation": "read",
        "resource": "transactions",
        "fields": ["transaction_id", "merchant", "card_number"],  # card_number denied
        "filters": {"customer_id": "123"},
    }
)

print(f"Status: {result}")
print(f"Decision: {result.decision.status}")
print(f"Reasons: {result.decision.reasons}")

# Example 4: Attempt dangerous operation
print("\n4. DENIED - DELETE operation")
print("-" * 70)

result = fence.execute(
    {
        "actor": {
            "id": "agent:malicious-agent",
            "type": "agent",
            "attributes": {"customer_id": "123"},
        },
        "operation": "delete",
        "resource": "transactions",
        "filters": {"customer_id": "123"},
    }
)

print(f"Status: {result}")
print(f"Decision: {result.decision.status}")
print(f"Reasons: {result.decision.reasons}")

# Example 5: Success with provenance
print("\n5. SUCCESS WITH PROVENANCE")
print("-" * 70)

result = fence.execute(
    {
        "actor": {
            "id": "agent:finance-assistant",
            "type": "agent",
            "attributes": {"customer_id": "123"},
        },
        "operation": "read",
        "resource": "transactions",
        "fields": ["transaction_id", "merchant", "amount", "category"],
        "filters": {"customer_id": "123"},
        "limit": 10,
    }
)

print(f"Status: {result}")
if result.provenance:
    print("\nProvenance:")
    print(f"  Source: {result.provenance.source}")
    print(f"  Resource: {result.provenance.resource}")
    print(f"  Policy: {result.provenance.policy_name}:{result.provenance.policy_version}")
    print(f"  Actor: {result.provenance.actor}")

if result.evidence:
    print("\nEvidence:")
    print(f"  Verified: {result.evidence.verified}")
    print(f"  Request ID: {result.evidence.request_id}")
    print(f"  Checks: {', '.join(result.evidence.checks)}")

print("\n" + "=" * 70)
print("Key Takeaway: The agent could NOT bypass security through any")
print("SQL manipulation, parameter change, or prompt injection.")
print("DataFence enforced the boundary deterministically.")
print("=" * 70)
