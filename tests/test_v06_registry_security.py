"""v0.6 boundary and Resource Registry regression tests."""

import os
import tempfile
from datetime import datetime, timedelta

import pytest

from datafence import Actor, DataFenceBoundary, Intent, Operation, create_banking_policy
from datafence.connectors.sqlite_connector import SQLiteConnector, create_demo_database
from datafence.core.boundary import DataFenceBoundary
from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError


@pytest.fixture
def boundary():
    path = tempfile.mktemp(suffix=".db")
    policy_engine = create_banking_policy()
    result = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=SQLiteConnector,
        registry=policy_engine.registry,
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


def test_boundary_requires_explicit_registry():
    with tempfile.NamedTemporaryFile(suffix=".db") as db:
        with pytest.raises(ValueError, match="requires a ResourceRegistry"):
            DataFenceBoundary.create(
                policy_engine=create_banking_policy(),
                connector_factory=SQLiteConnector,
                database_path=db.name,
            )


def test_registry_is_frozen_when_boundary_is_constructed(boundary):
    with pytest.raises(RuntimeError, match="frozen"):
        boundary._registry.register(object())


def test_expired_capability_is_rejected(boundary):
    cap = AuthorizedExecution.create_signed(
        execution_id="expired",
        actor=Actor("user", "tenant_a"),
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id"],
        enforced_filters={"tenant_id": "tenant_a"},
        limit=1,
        policy_version="1.0",
        policy_decisions=["transactions.action.read"],
        signing_key=boundary._signing_key,
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )
    with pytest.raises(CapabilityVerificationError, match="Expired capability"):
        boundary._connector.execute(cap)


def test_legacy_policy_evaluation_forms_are_rejected():
    engine = create_banking_policy()
    actor = Actor("user", "tenant_a")
    with pytest.raises(TypeError):
        engine.evaluate(actor, "transactions", "read")
    with pytest.raises(TypeError):
        engine.evaluate(actor=actor, resource="transactions", operation="read")
