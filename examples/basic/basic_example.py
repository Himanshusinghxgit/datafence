"""
Basic DataFence example.

Shows simple policy enforcement with an in-memory connector.
"""

from pathlib import Path

from datafence import DataFence
from datafence.connectors.memory import MemoryConnector

# Get the path to the policy file
REPO_ROOT = Path(__file__).parent.parent.parent
POLICY_PATH = REPO_ROOT / "policies" / "basic.yaml"

# Create sample data
users_data = [
    {
        "user_id": 1,
        "username": "alice",
        "email": "alice@example.com",
        "password_hash": "secret123",
        "api_key": "key_abc",
        "created_at": "2026-01-01",
    },
    {
        "user_id": 2,
        "username": "bob",
        "email": "bob@example.com",
        "password_hash": "secret456",
        "api_key": "key_def",
        "created_at": "2026-01-15",
    },
]

# Create connector
connector = MemoryConnector({"users": users_data})

# Create DataFence with policy
fence = DataFence.from_yaml(POLICY_PATH, connector)

print("=" * 60)
print("DataFence Basic Example")
print("=" * 60)

# Example 1: Allowed request
print("\n1. ALLOWED REQUEST")
print("-" * 60)

result = fence.execute(
    {
        "actor": {"id": "agent:user-assistant", "type": "agent"},
        "operation": "read",
        "resource": "users",
        "fields": ["user_id", "username", "email"],
    }
)

print(f"Status: {result}")
print(f"Data: {result.data}")
print(f"Evidence: {result.evidence.verified if result.evidence else 'N/A'}")

# Example 2: Denied request - accessing denied field
print("\n2. DENIED REQUEST - Accessing password_hash")
print("-" * 60)

result = fence.execute(
    {
        "actor": {"id": "agent:user-assistant", "type": "agent"},
        "operation": "read",
        "resource": "users",
        "fields": ["user_id", "username", "password_hash"],  # password_hash is denied
    }
)

print(f"Status: {result}")
print(f"Decision: {result.decision.status}")
print(f"Reasons: {result.decision.reasons}")

# Example 3: Denied request - dangerous operation
print("\n3. DENIED REQUEST - DELETE operation")
print("-" * 60)

result = fence.execute(
    {
        "actor": {"id": "agent:admin", "type": "agent"},
        "operation": "delete",
        "resource": "users",
        "filters": {"user_id": 1},
    }
)

print(f"Status: {result}")
print(f"Decision: {result.decision.status}")
print(f"Reasons: {result.decision.reasons}")

# Example 4: Dry-run check
print("\n4. DRY-RUN CHECK")
print("-" * 60)

result = fence.check(
    {
        "actor": {"id": "agent:user-assistant", "type": "agent"},
        "operation": "read",
        "resource": "users",
        "fields": ["user_id", "api_key"],  # api_key is denied
    }
)

print(f"Would be allowed: {result.verified}")
print(f"Decision: {result.decision.status}")
print(f"Reasons: {result.decision.reasons}")

print("\n" + "=" * 60)
print("Example complete!")
print("=" * 60)
