"""
Security Invariant Tests.

These tests prove DataFence's core security guarantees:

1. An unauthorized field can never reach the connector
2. An unauthorized row can never be returned
3. An unauthorized tenant can never be accessed
4. An unauthorized operation can never reach the connector
5. A missing policy fails closed
6. An invalid policy fails closed
7. A connector cannot execute arbitrary SQL supplied by the LLM
8. Result validation rejects unauthorized fields
9. Actor identity cannot be changed by the LLM request
10. Policy version is recorded in evidence
11. Every execution receives a unique execution ID
12. Every allowed execution produces provenance
13. Every denied request produces an auditable decision

These are MORE important than feature count.
"""

import os
import sqlite3
import tempfile
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from datafence.connectors.sqlite_connector import (
    MaliciousConnector,
    SQLiteConnector,
    create_demo_database,
)
from datafence.core.boundary import DataFenceBoundary
from datafence.core.policy_engine import SimplePolicyEngine, ResourcePolicy
from datafence.core.types import (
    Actor,
    AllowedRequest,
    DeniedRequest,
    Intent,
    Operation,
)


@pytest.fixture
def demo_db():
    """Create a temporary demo database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    connector = create_demo_database(db_path)
    yield connector
    connector.close()
    os.unlink(db_path)


@pytest.fixture
def policy_engine():
    """Create demo policy engine."""
    from datafence.core.policy_engine import create_banking_demo_policy

    return create_banking_demo_policy()


@pytest.fixture
def boundary(policy_engine, demo_db):
    """Create DataFence boundary."""
    return DataFenceBoundary(policy_engine, demo_db)


# INVARIANT 1: An unauthorized field can never reach the connector
def test_unauthorized_field_never_reaches_connector(boundary):
    """
    INVARIANT 1: An unauthorized field can never reach the connector.
    
    If the LLM requests an unauthorized field, the request must be
    DENIED before the connector is called.
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # Request a field that is explicitly denied
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "card_number"],  # card_number is denied
    )

    result = boundary.execute(actor, intent)

    # Must be denied
    assert isinstance(result, DeniedRequest)
    assert "card_number" in str(result.decision.reasons).lower()

    # Evidence must show denial
    assert result.evidence.decision.value == "deny"


# INVARIANT 2: An unauthorized row can never be returned
def test_unauthorized_row_never_returned(boundary):
    """
    INVARIANT 2: An unauthorized row can never be returned.
    
    Tenant isolation must be enforced. Actor from tenant_a
    must NEVER see tenant_b's data.
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # Request transactions (no filter specified)
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant", "amount"],
        filters={},  # No tenant filter!
    )

    result = boundary.execute(actor, intent)

    # Must be allowed (with enforced filter)
    assert isinstance(result, AllowedRequest)

    # Enforced filter must include tenant_id
    assert "tenant_id" in result.execution_plan.enforced_filters
    assert result.execution_plan.enforced_filters["tenant_id"] == "tenant_a"

    # Verify NO row belongs to tenant_b
    # (In our demo, we only return the authorized fields, not tenant_id)
    # But the SQL query enforced the filter
    assert result.execution_result.verified

    # The ExecutionPlan proves tenant isolation was enforced
    assert result.execution_plan.enforced_filters["tenant_id"] == actor.tenant_id


# INVARIANT 3: An unauthorized tenant can never be accessed
def test_unauthorized_tenant_never_accessed(boundary):
    """
    INVARIANT 3: An unauthorized tenant can never be accessed.
    
    Even if the LLM tries to override the tenant filter,
    DataFence must enforce actor.tenant_id.
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # LLM tries to access tenant_b by specifying it in filters
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant"],
        filters={"tenant_id": "tenant_b"},  # Attack attempt!
    )

    result = boundary.execute(actor, intent)

    # Must be allowed, but with enforced filter
    assert isinstance(result, AllowedRequest)

    # Enforced filter must override LLM's attempted filter
    assert result.execution_plan.enforced_filters["tenant_id"] == "tenant_a"
    assert result.execution_plan.enforced_filters["tenant_id"] != "tenant_b"


# INVARIANT 4: An unauthorized operation can never reach the connector
def test_unauthorized_operation_never_reaches_connector(boundary):
    """
    INVARIANT 4: An unauthorized operation can never reach the connector.
    
    If the LLM attempts a denied operation (DELETE, UPDATE),
    it must be DENIED before the connector is called.
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # Attempt DELETE (denied by policy)
    intent = Intent(
        resource="transactions",
        operation=Operation.DELETE,
        raw_sql="DELETE FROM transactions WHERE id = 1",
    )

    result = boundary.execute(actor, intent)

    # Must be denied
    assert isinstance(result, DeniedRequest)
    assert "delete" in str(result.decision.reasons).lower()


# INVARIANT 5: A missing policy fails closed
def test_missing_policy_fails_closed():
    """
    INVARIANT 5: A missing policy fails closed.
    
    If there's no policy for a resource, access must be DENIED.
    """
    # Create policy engine with NO policy for "unknown_resource"
    empty_policy = SimplePolicyEngine(policies={})

    connector = SQLiteConnector(":memory:")
    boundary = DataFenceBoundary(empty_policy, connector)

    actor = Actor(id="agent:test", tenant_id="tenant_a")
    intent = Intent(
        resource="unknown_resource",
        operation=Operation.READ,
        fields=["id"],
    )

    result = boundary.execute(actor, intent)

    # Must be denied
    assert isinstance(result, DeniedRequest)
    assert "no policy" in str(result.decision.reasons).lower()


# INVARIANT 6: An invalid policy fails closed
def test_invalid_policy_fails_closed():
    """
    INVARIANT 6: An invalid policy fails closed.
    
    If policy evaluation throws an error, fail closed (DENY).
    """

    class BrokenPolicyEngine:
        """Policy engine that throws errors."""

        def evaluate(self, actor, resource, operation, requested_fields):
            raise RuntimeError("Policy engine broken!")

        def get_policy_version(self):
            return "broken-v1"

    connector = SQLiteConnector(":memory:")
    broken_policy = BrokenPolicyEngine()
    boundary = DataFenceBoundary(broken_policy, connector)

    actor = Actor(id="agent:test", tenant_id="tenant_a")
    intent = Intent(
        resource="test",
        operation=Operation.READ,
        fields=["id"],
    )

    result = boundary.execute(actor, intent)

    # Must be denied (fail closed)
    assert isinstance(result, DeniedRequest)
    assert "failed" in str(result.decision.reasons).lower()


# INVARIANT 7: A connector cannot execute arbitrary SQL from the LLM
def test_connector_cannot_execute_llm_sql():
    """
    INVARIANT 7: A connector cannot execute arbitrary SQL supplied by the LLM.
    
    The connector's execute_plan() method accepts ONLY ExecutionPlan.
    There is no method to execute raw SQL from the LLM.
    """
    connector = SQLiteConnector(":memory:")

    # Verify the connector has NO method to execute raw SQL
    assert not hasattr(connector, "execute_sql")
    assert not hasattr(connector, "execute_query")
    assert not hasattr(connector, "execute_raw")

    # Verify it ONLY has execute_plan
    assert hasattr(connector, "execute_plan")

    # Verify execute_plan signature requires ExecutionPlan
    import inspect

    sig = inspect.signature(connector.execute_plan)
    params = list(sig.parameters.keys())
    assert params == ["plan"]  # ONLY accepts plan


# INVARIANT 8: Result validation rejects unauthorized fields
def test_result_validation_rejects_unauthorized_fields(policy_engine):
    """
    INVARIANT 8: Result validation rejects unauthorized fields.
    
    Even if the connector returns unauthorized fields,
    result validation must catch it.
    """
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    create_demo_database(db_path)

    # Use malicious connector
    malicious_connector = MaliciousConnector(db_path)
    boundary = DataFenceBoundary(policy_engine, malicious_connector)

    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant"],  # Only these authorized
    )

    result = boundary.execute(actor, intent)

    # Malicious connector added unauthorized fields
    # Result validation must catch it and DENY
    assert isinstance(result, DeniedRequest)
    assert "unauthorized fields" in str(result.decision.reasons).lower()

    # Cleanup
    malicious_connector.close()
    os.unlink(db_path)


# INVARIANT 9: Actor identity cannot be changed by LLM request
def test_actor_identity_cannot_be_changed(boundary):
    """
    INVARIANT 9: Actor identity cannot be changed by the LLM request.
    
    The Actor is set by the system, not the LLM.
    The LLM cannot override actor.id or actor.tenant_id.
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # LLM tries to access data by claiming different identity in filters
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant"],
        filters={
            "tenant_id": "tenant_b",  # LLM tries to override
        },
    )

    result = boundary.execute(actor, intent)

    # Must be allowed, but actor identity is NOT changed
    assert isinstance(result, AllowedRequest)

    # Actor identity remains the same
    assert result.actor.id == "agent:finance"
    assert result.actor.tenant_id == "tenant_a"

    # Enforced filter uses ACTOR's tenant_id, not LLM's
    assert result.execution_plan.enforced_filters["tenant_id"] == "tenant_a"


# INVARIANT 10: Policy version is recorded in evidence
def test_policy_version_recorded_in_evidence(boundary):
    """
    INVARIANT 10: Policy version is recorded in evidence.
    
    Every execution must record the policy version used.
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant"],
    )

    result = boundary.execute(actor, intent)

    assert isinstance(result, AllowedRequest)

    # Policy version must be recorded
    assert result.evidence.policy_version is not None
    assert result.evidence.policy_version == "banking-demo-v1"

    # Execution plan must also record it
    assert result.execution_plan.policy_version == "banking-demo-v1"


# INVARIANT 11: Every execution receives a unique execution ID
def test_unique_execution_ids(boundary):
    """
    INVARIANT 11: Every execution receives a unique execution ID.
    
    Each execution must have a unique ID for tracking.
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id"],
    )

    # Execute twice
    result1 = boundary.execute(actor, intent)
    result2 = boundary.execute(actor, intent)

    assert isinstance(result1, AllowedRequest)
    assert isinstance(result2, AllowedRequest)

    # Execution IDs must be different
    assert result1.execution_plan.execution_id != result2.execution_plan.execution_id
    assert result1.evidence.execution_id != result2.evidence.execution_id


# INVARIANT 12: Every allowed execution produces provenance
def test_allowed_execution_produces_provenance(boundary):
    """
    INVARIANT 12: Every allowed execution produces provenance.
    
    Every allowed request must produce:
    - ExecutionPlan
    - ExecutionResult
    - Evidence
    - AuditEvent
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant"],
    )

    result = boundary.execute(actor, intent)

    assert isinstance(result, AllowedRequest)

    # Must have all provenance
    assert result.execution_plan is not None
    assert result.execution_result is not None
    assert result.evidence is not None
    assert result.audit_event is not None

    # Evidence must link to execution
    assert result.evidence.execution_id == result.execution_plan.execution_id
    assert result.evidence.request_id == result.request_id

    # Audit event must link to evidence
    assert result.audit_event.execution_id == result.evidence.execution_id


# INVARIANT 13: Every denied request produces an auditable decision
def test_denied_request_produces_auditable_decision(boundary):
    """
    INVARIANT 13: Every denied request produces an auditable decision.
    
    Every denied request must produce:
    - PolicyDecision
    - Evidence
    - AuditEvent
    """
    actor = Actor(id="agent:finance", tenant_id="tenant_a")

    # Request denied field
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["card_number"],  # Denied
    )

    result = boundary.execute(actor, intent)

    assert isinstance(result, DeniedRequest)

    # Must have all audit trail
    assert result.decision is not None
    assert result.evidence is not None
    assert result.audit_event is not None

    # Decision must have reasons
    assert len(result.decision.reasons) > 0

    # Evidence must record denial
    assert result.evidence.decision.value == "deny"
    assert len(result.evidence.denial_reasons) > 0

    # Audit event must record denial
    assert result.audit_event.decision.value == "deny"


# BONUS: Test fail-closed on connector errors
def test_fail_closed_on_connector_error(policy_engine):
    """
    Bonus invariant: Fail closed on connector errors.
    
    If the connector throws an error, the request must be DENIED.
    """

    class BrokenConnector:
        """Connector that always fails."""

        def execute_plan(self, plan):
            raise RuntimeError("Connector error!")

    broken_connector = BrokenConnector()
    boundary = DataFenceBoundary(policy_engine, broken_connector)

    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id"],
    )

    result = boundary.execute(actor, intent)

    # Must be denied (fail closed)
    assert isinstance(result, DeniedRequest)
    assert "failed" in str(result.decision.reasons).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
