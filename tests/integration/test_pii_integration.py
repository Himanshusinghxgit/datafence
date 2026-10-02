"""
Integration tests for PII detection in DataFence engine.
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
from datafence.security.pii import RedactionStrategy


@pytest.fixture
def test_data_with_pii():
    """Sample data containing PII."""
    return {
        "users": [
            {
                "user_id": 1,
                "username": "alice",
                "email": "alice@example.com",
                "phone": "123-456-7890",
                "notes": "Contact at alice@example.com",
            },
            {
                "user_id": 2,
                "username": "bob",
                "email": "bob@example.com",
                "phone": "555-123-4567",
                "notes": "Call 555-123-4567",
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
                operations=OperationPolicy(allow=["read"]),
                fields=FieldPolicy(allow=["user_id", "username", "email", "phone", "notes"]),
            )
        },
    )


def test_pii_redaction_enabled(test_data_with_pii, test_policy):
    """Test that PII is redacted when enabled."""
    connector = MemoryConnector(test_data_with_pii)
    fence = DataFence(
        test_policy,
        connector,
        enable_pii_detection=True,
        pii_redaction_strategy=RedactionStrategy.MASK,
    )

    result = fence.execute(
        {
            "actor": {"id": "test", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "username", "email", "phone", "notes"],
        }
    )

    assert result.verified

    # Check that PII is redacted
    for record in result.data:
        # Email should be masked
        if "email" in record:
            assert "***@***.***" in str(record["email"]) or "[EMAIL]" in str(record)

        # Phone should be masked
        if "phone" in record:
            phone_str = str(record["phone"])
            # Either masked or contains redaction marker
            assert "***" in phone_str or "[PHONE]" in phone_str or record["phone"] == "***-***-****"


def test_pii_redaction_disabled(test_data_with_pii, test_policy):
    """Test that PII is not redacted when disabled."""
    connector = MemoryConnector(test_data_with_pii)
    fence = DataFence(
        test_policy,
        connector,
        enable_pii_detection=False,
    )

    result = fence.execute(
        {
            "actor": {"id": "test", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "email"],
        }
    )

    assert result.verified

    # PII should NOT be redacted
    assert "alice@example.com" in str(result.data)


def test_pii_redaction_with_token_strategy(test_data_with_pii, test_policy):
    """Test PII redaction with token strategy."""
    connector = MemoryConnector(test_data_with_pii)
    fence = DataFence(
        test_policy,
        connector,
        enable_pii_detection=True,
        pii_redaction_strategy=RedactionStrategy.TOKEN,
    )

    result = fence.execute(
        {
            "actor": {"id": "test", "type": "agent"},
            "operation": "read",
            "resource": "users",
            "fields": ["user_id", "email", "notes"],
        }
    )

    assert result.verified

    # Check for tokens
    result_str = str(result.data)
    assert "[EMAIL]" in result_str or "***@***.***" in result_str
