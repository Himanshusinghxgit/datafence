"""
Security tests for tenant isolation.

These tests verify that one tenant cannot access another tenant's data.
"""

import pytest
from datafence.connectors.memory import MemoryConnector
from datafence.core.decision import DecisionStatus
from datafence.policy.models import (
    FieldPolicy,
    OperationPolicy,
    Policy,
    ResourcePolicy,
)

from datafence import DataFence
from datafence.audit.logger import MemoryAuditLogger


@pytest.fixture
def multi_tenant_data():
    """Multi-tenant test data."""
    return {
        "transactions": [
            {
                "id": 1,
                "customer_id": "customer-a",
                "amount": 100,
                "merchant": "Store A",
            },
            {
                "id": 2,
                "customer_id": "customer-a",
                "amount": 200,
                "merchant": "Store B",
            },
            {
                "id": 3,
                "customer_id": "customer-b",
                "amount": 300,
                "merchant": "Store C",
            },
            {
                "id": 4,
                "customer_id": "customer-b",
                "amount": 400,
                "merchant": "Store D",
            },
        ]
    }


@pytest.fixture
def tenant_policy():
    """Policy with tenant isolation."""
    return Policy(
        version="1",
        name="tenant-isolation-policy",
        resources={
            "transactions": ResourcePolicy(
                operations=OperationPolicy(allow=["read"]),
                fields=FieldPolicy(allow=["id", "customer_id", "amount", "merchant"]),
                row_filters={"customer_id": "{{ actor.customer_id }}"},
            )
        },
    )


@pytest.fixture
def datafence(multi_tenant_data, tenant_policy):
    """DataFence with multi-tenant setup."""
    connector = MemoryConnector(multi_tenant_data)
    return DataFence(tenant_policy, connector, MemoryAuditLogger())


def test_tenant_can_access_own_data(datafence):
    """Test that a tenant can access their own data."""
    result = datafence.execute(
        {
            "actor": {
                "id": "agent-a",
                "type": "agent",
                "attributes": {"customer_id": "customer-a"},
            },
            "operation": "read",
            "resource": "transactions",
            "fields": ["id", "amount", "merchant"],
            "filters": {"customer_id": "customer-a"},
        }
    )

    assert result.verified
    assert result.row_count == 2
    # Verify only customer-a's data is returned
    for record in result.data:
        assert record.get("customer_id") == "customer-a" or "customer_id" not in record


def test_tenant_cannot_access_other_tenant_data(datafence):
    """Test that a tenant CANNOT access another tenant's data."""
    result = datafence.execute(
        {
            "actor": {
                "id": "agent-a",
                "type": "agent",
                "attributes": {"customer_id": "customer-a"},
            },
            "operation": "read",
            "resource": "transactions",
            "fields": ["id", "amount"],
            "filters": {"customer_id": "customer-b"},  # Trying to access customer-b!
        }
    )

    assert not result.verified
    assert result.decision.status == DecisionStatus.DENY
    assert "mismatch" in result.decision.reasons[0].lower()


def test_tenant_must_provide_filter(datafence):
    """Test that tenant filter is required."""
    result = datafence.execute(
        {
            "actor": {
                "id": "agent-a",
                "type": "agent",
                "attributes": {"customer_id": "customer-a"},
            },
            "operation": "read",
            "resource": "transactions",
            "fields": ["id", "amount"],
            "filters": {},  # Missing customer_id filter
        }
    )

    assert not result.verified
    assert result.decision.status == DecisionStatus.DENY
    assert "missing" in result.decision.reasons[0].lower()


def test_different_tenants_isolated(datafence):
    """Test that different tenants see only their own data."""
    # Customer A
    result_a = datafence.execute(
        {
            "actor": {
                "id": "agent-a",
                "type": "agent",
                "attributes": {"customer_id": "customer-a"},
            },
            "operation": "read",
            "resource": "transactions",
            "fields": ["id", "amount"],
            "filters": {"customer_id": "customer-a"},
        }
    )

    # Customer B
    result_b = datafence.execute(
        {
            "actor": {
                "id": "agent-b",
                "type": "agent",
                "attributes": {"customer_id": "customer-b"},
            },
            "operation": "read",
            "resource": "transactions",
            "fields": ["id", "amount"],
            "filters": {"customer_id": "customer-b"},
        }
    )

    assert result_a.verified
    assert result_b.verified
    assert result_a.row_count == 2
    assert result_b.row_count == 2

    # Verify data separation
    ids_a = {r["id"] for r in result_a.data}
    ids_b = {r["id"] for r in result_b.data}

    assert ids_a == {1, 2}
    assert ids_b == {3, 4}
    assert ids_a.isdisjoint(ids_b)  # No overlap
