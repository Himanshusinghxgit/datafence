"""
SQL Security Example - SQL Firewall in Action

Demonstrates how DataFence SQL firewall protects against:
- SQL injection
- Dangerous operations
- Comment injection
"""

from pathlib import Path

from datafence import DataFence
from datafence.connectors.memory import MemoryConnector
from datafence.security.sql_firewall import SQLFirewall, QueryRisk

# Get policy path
REPO_ROOT = Path(__file__).parent.parent.parent
POLICY_PATH = REPO_ROOT / "policies" / "basic.yaml"

# Sample data
users_data = [
    {"user_id": 1, "username": "alice", "email": "alice@example.com", "role": "user"},
    {"user_id": 2, "username": "admin", "email": "admin@example.com", "role": "admin"},
]

connector = MemoryConnector({"users": users_data})

# Create DataFence with SQL firewall enabled
fence = DataFence.from_yaml(
    POLICY_PATH,
    connector,
    enable_sql_firewall=True,
)

print("=" * 70)
print("DataFence SQL Security Demo")
print("=" * 70)

# Attack 1: SQL Injection via Comment
print("\n1. SQL INJECTION - Comment Attack")
print("-" * 70)
print("Attacker tries: SELECT * FROM users WHERE id = 1 -- AND role = 'user'")

result = fence.execute(
    {
        "actor": {"id": "attacker", "type": "agent"},
        "operation": "read",
        "resource": "users",
        "raw_query": "SELECT * FROM users WHERE id = 1 -- AND role = 'user'",
    }
)

print(f"Result: {result.verified}")
print(f"Decision: {result.decision.status}")
if not result.verified:
    print(f"Blocked: {result.decision.reasons[0]}")

# Attack 2: DROP TABLE
print("\n2. DANGEROUS OPERATION - DROP TABLE")
print("-" * 70)
print("Attacker tries: DROP TABLE users")

result = fence.execute(
    {
        "actor": {"id": "attacker", "type": "agent"},
        "operation": "read",  # Lies about operation
        "resource": "users",
        "raw_query": "DROP TABLE users",
    }
)

print(f"Result: {result.verified}")
print(f"Decision: {result.decision.status}")
if not result.verified:
    print(f"Blocked: {result.decision.reasons[0]}")

# Attack 3: DELETE FROM
print("\n3. DANGEROUS OPERATION - DELETE")
print("-" * 70)
print("Attacker tries: DELETE FROM users WHERE role = 'user'")

result = fence.execute(
    {
        "actor": {"id": "attacker", "type": "agent"},
        "operation": "read",
        "resource": "users",
        "raw_query": "DELETE FROM users WHERE role = 'user'",
    }
)

print(f"Result: {result.verified}")
print(f"Decision: {result.decision.status}")
if not result.verified:
    print(f"Blocked: {result.decision.reasons[0]}")

# Attack 4: UNION Injection
print("\n4. SQL INJECTION - UNION Attack")
print("-" * 70)
print("Attacker tries: SELECT id FROM users UNION SELECT password FROM secrets")

# Create firewall that blocks UNIONs
strict_firewall = SQLFirewall(allow_unions=False, block_comments=True)

risk, reasons = strict_firewall.validate("SELECT id FROM users UNION SELECT password FROM secrets")

print(f"Risk Level: {risk}")
if risk == QueryRisk.BLOCKED:
    print(f"Blocked: {reasons[0]}")

# Safe Query
print("\n5. SAFE QUERY - Allowed")
print("-" * 70)
print("Legitimate query: SELECT user_id, username FROM users")

result = fence.execute(
    {
        "actor": {"id": "legitimate-agent", "type": "agent"},
        "operation": "read",
        "resource": "users",
        "fields": ["user_id", "username"],
        "raw_query": "SELECT user_id, username FROM users",
    }
)

print(f"Result: {result.verified}")
print(f"Rows returned: {result.row_count}")
print(f"Evidence verified: {result.evidence.verified if result.evidence else 'N/A'}")

# Firewall statistics
print("\n" + "=" * 70)
print("SUMMARY: SQL Firewall Protection")
print("=" * 70)
print("✓ SQL comments:      BLOCKED")
print("✓ DROP operations:   BLOCKED")
print("✓ DELETE operations: BLOCKED")
print("✓ UNION injections:  BLOCKED")
print("✓ Safe queries:      ALLOWED")
print()
print("The SQL firewall provides deterministic protection against")
print("SQL injection and dangerous operations, independent of the AI.")
print("=" * 70)
