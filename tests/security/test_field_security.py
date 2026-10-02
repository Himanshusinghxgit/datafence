"""
Security tests for field-level (column-level) access control.

Verifies that sensitive fields cannot be accessed.
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


@pytest.fixture
def sensitive_data():
    """Data with sensitive fields."""
    return {
        "users": [
            {
                "user_id": 1,
                "username": "alice",
                "email": "alice@example.com",
                "password_hash": "bcrypt:secret123",
                "api_key": "test_key_FAKE_NOT_REAL_12345",
                "ssn": "123-45-6789",
            }
        ]
    }


@pytest.fixture
def field_policy():
    """Policy with field restrictions."""
    return Policy(
        version="1",
        name="field-security-policy",
        resources={
            "users": ResourcePolicy(
                operations=OperationPolicy(allow=["read"]),
                fields=FieldPolicy(
                    allow=["user_id", "username", "email"],
                    deny=["password_hash", "api_key", "ssn"],
                ),
            )
        },
    )


@pytest.fixture
def datafence(sensitive_data, field_policy):
    """DataFence with field security."""
    connector = MemoryConnector(sensitive_data)
    return DataFence(field_policy, connector)


def test_allow_safe_fields(datafence):
    """Test that safe fields are allowed."""
    result = datafence.execute(
        {
            "actor": {"id": "agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "username", "email"],
        }
    )

    assert result.verified
    assert "user_id" in result.data[0]
    assert "username" in result.data[0]
    assert "password_hash" not in result.data[0]


def test_deny_password_hash(datafence):
    """Test that password_hash is denied."""
    result = datafence.execute(
        {
            "actor": {"id": "agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "password_hash"],
        }
    )

    assert not result.verified
    assert result.decision.status == DecisionStatus.DENY
    assert "password_hash" in result.decision.reasons[0]


def test_deny_api_key(datafence):
    """Test that api_key is denied."""
    result = datafence.execute(
        {
            "actor": {"id": "agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "api_key"],
        }
    )

    assert not result.verified
    assert "api_key" in result.decision.reasons[0]


def test_deny_ssn(datafence):
    """Test that SSN is denied."""
    result = datafence.execute(
        {
            "actor": {"id": "agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "ssn"],
        }
    )

    assert not result.verified
    assert "ssn" in result.decision.reasons[0]


def test_deny_multiple_sensitive_fields(datafence):
    """Test that multiple sensitive fields are denied."""
    result = datafence.execute(
        {
            "actor": {"id": "agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["password_hash", "api_key", "ssn"],
        }
    )

    assert not result.verified
    assert result.decision.status == DecisionStatus.DENY


def test_deny_field_not_in_allow_list(datafence):
    """Test that fields not in allow list are denied."""
    result = datafence.execute(
        {
            "actor": {"id": "agent", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "nonexistent_field"],
        }
    )

    assert not result.verified
    assert "nonexistent_field" in result.decision.reasons[0]
