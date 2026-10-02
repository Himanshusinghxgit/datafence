"""Security invariants for the canonical v1 boundary."""

from __future__ import annotations

import os
import tempfile

import pytest

from datafence import (
    Actor,
    DataFenceBoundary,
    Decision,
    Intent,
    Operation,
    create_banking_policy,
)
from datafence.connectors.sqlite_connector import SQLiteConnector, create_demo_database


@pytest.fixture
def boundary() -> DataFenceBoundary:
    database_path = tempfile.mktemp(suffix=".db")
    policy_engine = create_banking_policy()
    boundary = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=SQLiteConnector,
        registry=policy_engine.registry,
        database_path=database_path,
    )
    create_demo_database(database_path, boundary._signing_key)
    try:
        yield boundary
    finally:
        boundary._connector.close()
        if os.path.exists(database_path):
            os.unlink(database_path)


def test_unknown_resource_is_rejected_before_policy(boundary: DataFenceBoundary) -> None:
    result = boundary.execute(
        Actor("security-test", "tenant_a"),
        Intent("unknown_table", Operation.READ, ["id"]),
    )

    assert result.evidence.decision == Decision.DENY
    assert "Unknown resource" in result.evidence.denial_reasons[0]


def test_unknown_field_is_rejected_by_registry(boundary: DataFenceBoundary) -> None:
    result = boundary.execute(
        Actor("security-test", "tenant_a"),
        Intent("transactions", Operation.READ, ["not_a_real_field"]),
    )

    assert result.evidence.decision == Decision.DENY
    assert "Unknown fields" in result.evidence.denial_reasons[0]


def test_destructive_operation_is_denied(boundary: DataFenceBoundary) -> None:
    result = boundary.execute(
        Actor("security-test", "tenant_a"),
        Intent("transactions", Operation.DELETE, ["id"]),
    )

    assert result.evidence.decision == Decision.DENY
    assert "denied" in result.evidence.denial_reasons[0].lower()


def test_registry_definitions_are_deeply_immutable(boundary: DataFenceBoundary) -> None:
    resource = boundary._registry.get("transactions")
    assert resource is not None

    with pytest.raises(TypeError):
        resource.fields["injected"] = resource.fields["id"]
    with pytest.raises(AttributeError):
        resource.tags.append("injected")
