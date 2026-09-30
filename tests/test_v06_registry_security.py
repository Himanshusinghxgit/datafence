"""v0.6 boundary and Resource Registry regression tests."""

import os
import tempfile

import pytest

from datafence import Actor, DataFenceBoundary, Intent, Operation, create_banking_policy
from datafence.connectors.sqlite_connector import SQLiteConnector, create_demo_database


@pytest.fixture
def boundary():
    path = tempfile.mktemp(suffix=".db")
    result = DataFenceBoundary.create(
        policy_engine=create_banking_policy(),
        connector_factory=SQLiteConnector,
        database_path=path,
    )
    create_demo_database(path, result._signing_key)
    try:
        yield result
    finally:
        result._connector.close()
        if os.path.exists(path):
            os.unlink(path)


def test_boundary_uses_one_canonical_policy_call(boundary):
    calls = 0
    engine = boundary.policy_engine
    original = engine.evaluate

    def counted(*, principal, intent):
        nonlocal calls
        calls += 1
        return original(principal=principal, intent=intent)

    engine.evaluate = counted
    result = boundary.execute(
        Actor("user", "tenant_a"),
        Intent("transactions", Operation.READ, ["id"]),
    )
    assert result.execution_result.verified
    assert calls == 1


def test_registry_rejects_unknown_resource_before_policy(boundary):
    result = boundary.execute(
        Actor("user", "tenant_a"),
        Intent("not_registered", Operation.READ, ["id"]),
    )
    assert result.decision.reasons
    assert "Unknown resource" in result.decision.reasons[0]


def test_registry_rejects_unknown_field(boundary):
    result = boundary.execute(
        Actor("user", "tenant_a"),
        Intent("transactions", Operation.READ, ["not_a_column"]),
    )
    assert result.decision.reasons
    assert "Unknown fields" in result.decision.reasons[0]


def test_registry_rejects_unsupported_operation(boundary):
    result = boundary.execute(
        Actor("user", "tenant_a"),
        Intent("transactions", Operation.DELETE, ["id"]),
    )
    assert result.decision.reasons
    assert "denied" in result.decision.reasons[0].lower()
