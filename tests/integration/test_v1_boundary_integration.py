"""Integration coverage for the canonical v1 boundary."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta

import pytest

from datafence import Actor, DataFenceBoundary, Decision, Intent, Operation, create_banking_policy
from datafence.connectors.sqlite_connector import SQLiteConnector, create_demo_database
from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError


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


def test_boundary_executes_authorized_tenant_scoped_read(boundary: DataFenceBoundary) -> None:
    result = boundary.execute(
        Actor("integration-agent", "tenant_a"),
        Intent("transactions", Operation.READ, ["id", "merchant", "amount"]),
    )

    assert result.execution_result.verified
    assert result.execution_result.data
    assert all(set(row) <= {"id", "merchant", "amount"} for row in result.execution_result.data)


def test_boundary_denies_unauthorized_field(boundary: DataFenceBoundary) -> None:
    result = boundary.execute(
        Actor("integration-agent", "tenant_a"),
        Intent("transactions", Operation.READ, ["id", "card_number"]),
    )

    assert result.evidence.decision == Decision.DENY
    assert result.decision.reasons


def test_boundary_requires_registry() -> None:
    with pytest.raises(ValueError, match="requires a ResourceRegistry"):
        DataFenceBoundary.create(
            policy_engine=create_banking_policy(),
            connector_factory=SQLiteConnector,
            database_path=":memory:",
        )


def test_connector_rejects_expired_signed_capability(boundary: DataFenceBoundary) -> None:
    capability = AuthorizedExecution.create_signed(
        execution_id="integration-expired",
        actor=Actor("integration-agent", "tenant_a"),
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
        boundary._connector.execute(capability)


def test_non_equality_predicate_is_preserved_in_capability(boundary: DataFenceBoundary) -> None:
    capability = AuthorizedExecution.create_signed(
        execution_id="integration-gt",
        actor=Actor("integration-agent", "tenant_a"),
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "amount"],
        enforced_filters={},
        enforced_predicates=[{"field": "amount", "operator": ">", "value": 100}],
        limit=10,
        policy_version="1.0",
        policy_decisions=["transactions.rows.amount_gt"],
        signing_key=boundary._signing_key,
    )

    sql, params = boundary._connector._compile(capability)
    assert "amount >" in sql
    assert params["filter_0"] == 100


def test_restricted_filter_field_is_rejected(boundary: DataFenceBoundary) -> None:
    result = boundary.execute(
        Actor("integration-agent", "tenant_a"),
        Intent(
            "transactions",
            Operation.READ,
            ["id"],
            filters={"card_number": "4111111111111111"},
        ),
    )

    assert result.evidence.decision == Decision.DENY
    assert "restricted field" in result.evidence.denial_reasons[0]


def test_connector_enforces_capability_audience(boundary: DataFenceBoundary) -> None:
    capability = AuthorizedExecution.create_signed(
        execution_id="integration-audience",
        actor=Actor("integration-agent", "tenant_a"),
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id"],
        enforced_filters={"tenant_id": "tenant_a"},
        limit=1,
        policy_version="1.0",
        policy_decisions=["transactions.action.read"],
        signing_key=boundary._signing_key,
        audience="another-connector",
    )

    with pytest.raises(CapabilityVerificationError, match="audience"):
        boundary._connector.execute(capability)


def test_postgres_boundary_read() -> None:
    """Exercise the canonical PostgreSQL connector when CI provides PostgreSQL."""
    psycopg = pytest.importorskip("psycopg")
    host = os.getenv("DATAFENCE_POSTGRES_HOST")
    if not host:
        pytest.skip("PostgreSQL integration environment is not configured")

    connection_kwargs = {
        "host": host,
        "port": os.getenv("DATAFENCE_POSTGRES_PORT", "5432"),
        "dbname": os.getenv("DATAFENCE_POSTGRES_DATABASE", "testdb"),
        "user": os.getenv("DATAFENCE_POSTGRES_USER", "postgres"),
        "password": os.getenv("DATAFENCE_POSTGRES_PASSWORD", "testpass"),
    }
    with psycopg.connect(**connection_kwargs) as connection:
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE IF EXISTS transactions")
            cursor.execute(
                """
                CREATE TABLE transactions (
                    id INTEGER PRIMARY KEY,
                    merchant TEXT NOT NULL,
                    amount DOUBLE PRECISION NOT NULL,
                    timestamp TEXT NOT NULL,
                    tenant_id TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                "INSERT INTO transactions VALUES (1, 'Coffee', 4.50, '2026-01-01', 'tenant_a')"
            )
        connection.commit()

    from datafence.connectors.postgres_connector import PostgreSQLConnector

    policy_engine = create_banking_policy()
    boundary = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=PostgreSQLConnector,
        registry=policy_engine.registry,
        **connection_kwargs,
    )
    try:
        result = boundary.execute(
            Actor("integration-agent", "tenant_a"),
            Intent("transactions", Operation.READ, ["id", "merchant", "amount"]),
        )
        assert result.execution_result.verified
        assert result.execution_result.data == [{"id": 1, "merchant": "Coffee", "amount": 4.5}]
    finally:
        boundary._connector.close()
        with psycopg.connect(**connection_kwargs) as connection:
            with connection.cursor() as cursor:
                cursor.execute("DROP TABLE IF EXISTS transactions")
            connection.commit()
