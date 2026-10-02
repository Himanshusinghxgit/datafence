"""
Integration tests for SQL firewall in DataFence engine.
"""

import pytest
from datafence.connectors.memory import MemoryConnector
from datafence.policy.models import (
    FieldPolicy,
    OperationPolicy,
    Policy,
    ResourcePolicy,
)

from datafence import DataFence


@pytest.fixture
def test_data():
    """Sample test data."""
    return {
        "users": [
            {"user_id": 1, "username": "alice", "email": "alice@example.com"},
            {"user_id": 2, "username": "bob", "email": "bob@example.com"},
        ]
    }


@pytest.fixture
def test_policy():
    """Sample test policy."""
    return Policy(
        version="1",
        name="test-policy",
        resources={
            "users": ResourcePolicy(
                operations=OperationPolicy(allow=["read"]),
                fields=FieldPolicy(allow=["user_id", "username", "email"]),
            )
        },
    )


def test_sql_firewall_blocks_drop_table(test_data, test_policy):
    """Test that SQL firewall blocks DROP TABLE."""
    connector = MemoryConnector(test_data)
    fence = DataFence(
        test_policy,
        connector,
        enable_sql_firewall=True,
    )

    result = fence.execute(
        {
            "actor": {"id": "test", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "raw_query": "DROP TABLE users",
        }
    )

    assert not result.verified
    assert "SQL firewall" in str(result.decision.reasons)


def test_sql_firewall_blocks_sql_injection(test_data, test_policy):
    """Test that SQL firewall blocks SQL injection attempts."""
    connector = MemoryConnector(test_data)
    fence = DataFence(
        test_policy,
        connector,
        enable_sql_firewall=True,
    )

    # SQL comment injection
    result = fence.execute(
        {
            "actor": {"id": "test", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "raw_query": "SELECT * FROM users WHERE id = 1 -- AND role = 'admin'",
        }
    )

    assert not result.verified
    assert (
        "SQL firewall" in str(result.decision.reasons)
        or "comment" in str(result.decision.reasons).lower()
    )


def test_sql_firewall_allows_safe_query(test_data, test_policy):
    """Test that SQL firewall allows safe queries."""
    connector = MemoryConnector(test_data)
    fence = DataFence(
        test_policy,
        connector,
        enable_sql_firewall=True,
    )

    # Note: MemoryConnector doesn't actually execute raw SQL,
    # but the firewall should validate it
    result = fence.execute(
        {
            "actor": {"id": "test", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "username"],
            "raw_query": "SELECT user_id, username FROM users WHERE user_id = 1",
        }
    )

    # Should pass SQL firewall and policy checks
    assert result.verified


def test_sql_firewall_disabled(test_data, test_policy):
    """Test that SQL firewall can be disabled."""
    connector = MemoryConnector(test_data)
    fence = DataFence(
        test_policy,
        connector,
        enable_sql_firewall=False,
    )

    # With firewall disabled, query validation is skipped
    # (though other policy checks still apply)
    result = fence.execute(
        {
            "actor": {"id": "test", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id"],
        }
    )

    assert result.verified
