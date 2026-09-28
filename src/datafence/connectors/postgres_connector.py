"""
PostgreSQL connector for DataFence (Phase 4).

This is the first production-grade connector.  It replaces the legacy
postgres.py which used the old ExecutionRequest interface.

SECURITY:
    - Accepts ONLY signed AuthorizedExecution capabilities
    - Verifies HMAC signature before any query is built
    - All identifiers validated (table + column names)
    - All filter values passed as parameterised query arguments
    - Never executes raw SQL from the LLM

Requires:  psycopg[binary] >= 3.1  (install with: pip install datafence[postgres])

Usage::

    from datafence.connectors.postgres_connector import PostgreSQLConnector
    from datafence.core.boundary import DataFenceBoundary
    from datafence.core.policy import create_banking_policy

    boundary = DataFenceBoundary.create(
        policy_engine=create_banking_policy(),
        connector_factory=PostgreSQLConnector,
        conninfo="postgresql://user:pass@localhost/dbname",
    )

    result = boundary.execute(principal, intent)
"""

from __future__ import annotations

from typing import Any

from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.resources import validate_identifier
from datafence.core.types import Operation


class PostgreSQLConnector:
    """
    PostgreSQL connector with cryptographic capability verification (Phase 4).

    Authentication / connection management:
    - Accepts a libpq connection string (conninfo) or keyword arguments.
    - Opens a single synchronous psycopg connection.
    - Use close() / context manager to release the connection.

    Thread safety:
    - This connector is NOT thread-safe.  Create one per thread or use a pool.
    """

    def __init__(self, signing_key: bytes, conninfo: str = "", **kwargs: Any) -> None:
        """
        Initialise the connector.

        Args:
            signing_key : 32-byte HMAC key shared with DataFenceBoundary.
            conninfo    : libpq connection string, e.g.
                          "postgresql://user:pass@host/db"
            **kwargs    : Passed directly to psycopg.connect() (e.g.
                          host=, port=, dbname=, user=, password=).
        """
        try:
            import psycopg
        except ImportError as exc:
            raise ImportError(
                "psycopg is required for PostgreSQL support. "
                "Install with: pip install 'datafence[postgres]'"
            ) from exc

        self._signing_key = signing_key
        self._conn = psycopg.connect(conninfo, **kwargs) if conninfo else psycopg.connect(**kwargs)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """
        Execute a signed capability against PostgreSQL.

        Raises:
            CapabilityVerificationError: If the HMAC signature is invalid.
        """
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid capability signature for execution "
                f"{capability.execution_id!r}."
            )

        sql, params = self._compile(capability)

        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()

        authorised = set(capability.selected_fields)
        return [
            {col: val for col, val in zip(columns, row) if col in authorised}
            for row in rows
        ]

    # ------------------------------------------------------------------
    # SQL compiler
    # ------------------------------------------------------------------

    def _compile(
        self, capability: AuthorizedExecution
    ) -> tuple[str, list[Any]]:
        if capability.operation == Operation.READ:
            return self._compile_select(capability)
        raise NotImplementedError(
            f"Operation {capability.operation!r} not implemented"
        )

    def _compile_select(
        self, capability: AuthorizedExecution
    ) -> tuple[str, list[Any]]:
        """
        Compile a parameterised SELECT for PostgreSQL.

        Uses %s placeholders (psycopg style).
        All identifiers validated before interpolation.
        """
        resource = validate_identifier(capability.resource, "resource name")
        fields_sql = ", ".join(
            validate_identifier(f, "field name") for f in capability.selected_fields
        )

        sql = f"SELECT {fields_sql} FROM {resource}"
        params: list[Any] = []

        if capability.enforced_filters:
            conditions: list[str] = []
            for col, val in capability.enforced_filters.items():
                safe_col = validate_identifier(col, "filter column")
                conditions.append(f"{safe_col} = %s")
                params.append(val)
            sql += " WHERE " + " AND ".join(conditions)

        sql += f" LIMIT {int(capability.limit)}"
        return sql, params

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._conn:
            self._conn.close()

    def __enter__(self) -> "PostgreSQLConnector":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
