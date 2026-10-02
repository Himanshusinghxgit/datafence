"""
Tests for DataFence execution engine.
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

from datafence import DataFence, Operation
from datafence.audit.logger import MemoryAuditLogger
from datafence.errors import PolicyDeniedError


@pytest.fixture
def test_data():
    """Sample test data."""
    return {
        "users": [
            {
                "user_id": 1,
                "username": "alice",
                "email": "alice@example.com",
                "password_hash": "secret",
            },
            {
                "user_id": 2,
                "username": "bob",
                "email": "bob@example.com",
                "password_hash": "secret",
            },
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
                operations=OperationPolicy(allow=[Operation.READ]),
                fields=FieldPolicy(allow=["user_id", "username", "email"], deny=["password_hash"]),
            )
        },
    )


@pytest.fixture
def datafence(test_data, test_policy):
    """DataFence instance with test data and policy."""
    connector = MemoryConnector(test_data)
    audit_logger = MemoryAuditLogger()
    return DataFence(test_policy, connector, audit_logger)


def test_execute_allowed_request(datafence):
    """Test successful execution of allowed request."""
    result = datafence.execute(
        {
            "actor": {"id": "test-agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "username"],
        }
    )

    assert result.verified
    assert result.decision.status == DecisionStatus.ALLOW
    assert result.data is not None
    assert len(result.data) == 2
    assert "user_id" in result.data[0]
    assert "password_hash" not in result.data[0]
    assert result.provenance is not None
    assert result.evidence is not None
    assert result.evidence.verified


def test_execute_denied_request(datafence):
    """Test that denied requests return denied result."""
    result = datafence.execute(
        {
            "actor": {"id": "test-agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "password_hash"],  # password_hash denied
        }
    )

    assert not result.verified
    assert result.decision.status == DecisionStatus.DENY
    assert result.data is None
    assert result.provenance is None
    assert result.evidence is None
    assert len(result.decision.reasons) > 0


def test_execute_with_raise_on_deny(datafence):
    """Test that raise_on_deny raises PolicyDeniedError."""
    with pytest.raises(PolicyDeniedError) as exc_info:
        datafence.execute(
            {
                "actor": {"id": "test-agent", "type": "agent"},
                "operation": "delete",  # Denied operation
                "resource": "users",
            },
            raise_on_deny=True,
        )

    assert "denied" in str(exc_info.value).lower()


def test_check_dry_run(datafence):
    """Test dry-run checking without execution."""
    result = datafence.check(
        {
            "actor": {"id": "test-agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "username"],
        }
    )

    assert result.verified
    assert result.data is None  # No data in dry-run
    assert result.metadata.get("dry_run") is True


def test_audit_logging(datafence, test_policy):
    """Test that audit events are logged."""
    audit_logger = datafence.audit_logger

    # Execute request
    datafence.execute(
        {
            "actor": {"id": "test-agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id"],
        }
    )

    # Check audit log
    assert len(audit_logger.events) == 1
    event = audit_logger.events[0]

    assert event.actor_id == "agent:test-agent"
    assert event.operation == "read"
    assert event.resource == "users"
    assert event.decision == DecisionStatus.ALLOW


def test_provenance_generation(datafence):
    """Test that provenance is generated correctly."""
    result = datafence.execute(
        {
            "actor": {"id": "test-agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id"],
        }
    )

    assert result.provenance is not None
    assert result.provenance.source == "MemoryConnector"
    assert result.provenance.resource == "users"
    assert result.provenance.policy_name == "test-policy"
    assert result.provenance.actor == "agent:test-agent"


def test_evidence_generation(datafence):
    """Test that evidence is generated correctly."""
    result = datafence.execute(
        {
            "actor": {"id": "test-agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id"],
        }
    )

    assert result.evidence is not None
    assert result.evidence.verified
    assert result.evidence.request_hash is not None
    assert result.evidence.policy_name == "test-policy"
    assert len(result.evidence.checks) > 0
