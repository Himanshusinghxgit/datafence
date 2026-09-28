"""
SQLite connector for local development and testing (DEPRECATED - v0.1-v0.3).

⚠️  DEPRECATED: This is the legacy SQLite connector from v0.1-v0.3.
    Use SQLiteConnector from datafence.connectors.sqlite_connector instead.

SECURITY WARNING: This connector uses the old ExecutionRequest interface
and lacks v0.4 cryptographic capability verification. It is vulnerable
to attacks discovered in v0.3 security review.

The v0.4 SQLiteConnector provides:
- HMAC-SHA256 signature verification
- AuthorizedExecution (not forgeable ExecutionRequest)
- Defense against capability forgery attacks

This module is kept for backward compatibility only.
"""

import sqlite3
import warnings
from typing import Any

from datafence.connectors.base import DataConnector
from datafence.core.request import ExecutionRequest, Operation
from datafence.errors import ConnectorError, ValidationError


class SQLiteConnector(DataConnector):
    """
    SQLite connector (DEPRECATED - v0.1-v0.3).

    ⚠️  DEPRECATED: Use SQLiteConnector from datafence.connectors.sqlite_connector instead.

    SECURITY WARNING: This connector lacks v0.4 cryptographic capability
    verification and is vulnerable to forgery attacks.

    Supports safe SQL execution with field filtering.
    """

    def __init__(self, database: str):
        """
        Initialize SQLite connector (DEPRECATED).

        ⚠️  DEPRECATED: Use the v0.4 SQLiteConnector instead.

        Args:
            database: Path to SQLite database file (or ':memory:' for in-memory)
        """
        warnings.warn(
            "SQLite connector (v0.1-v0.3) is deprecated. "
            "Use SQLiteConnector from datafence.connectors.sqlite_connector for v0.4 security model. "
            "The legacy connector lacks cryptographic capability verification.",
            DeprecationWarning,
            stacklevel=2
        )
        self.database = database
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.database)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def execute(
        self, request: ExecutionRequest, allowed_fields: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """
        Execute request against SQLite database.

        Args:
            request: Execution request
            allowed_fields: List of allowed fields

        Returns:
            Query results

        Raises:
            ConnectorError: If execution fails
            ValidationError: If operation is not supported
        """
        if request.operation != Operation.READ:
            raise ValidationError(
                f"SQLiteConnector currently only supports READ operations, got: {request.operation}"
            )

        try:
            # Build safe query
            query, params = self._build_query(request, allowed_fields)

            # Execute
            cursor = self.conn.cursor()
            cursor.execute(query, params)

            # Fetch results
            rows = cursor.fetchall()

            # Convert to dictionaries
            return [dict(row) for row in rows]

        except sqlite3.Error as e:
            raise ConnectorError(f"SQLite execution failed: {e}") from e

    def describe(self, resource: str) -> dict[str, Any]:
        """
        Describe a SQLite table.

        Args:
            resource: Table name

        Returns:
            Table metadata
        """
        try:
            cursor = self.conn.cursor()

            # Get table info
            cursor.execute(f"PRAGMA table_info({resource})")
            columns = cursor.fetchall()

            if not columns:
                raise ConnectorError(f"Table '{resource}' not found")

            fields = [col[1] for col in columns]

            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {resource}")
            row_count = cursor.fetchone()[0]

            return {"resource": resource, "fields": fields, "row_count": row_count}

        except sqlite3.Error as e:
            raise ConnectorError(f"Failed to describe table '{resource}': {e}") from e

    def _build_query(
        self, request: ExecutionRequest, allowed_fields: list[str] | None
    ) -> tuple[str, list[Any]]:
        """
        Build a safe SQL query from request.

        Args:
            request: Execution request
            allowed_fields: List of allowed fields

        Returns:
            Tuple of (query, parameters)
        """
        # Determine fields to select
        if allowed_fields:
            # Use only allowed fields
            fields_str = ", ".join(allowed_fields)
        elif request.fields:
            # Use requested fields (already validated by policy)
            fields_str = ", ".join(request.fields)
        else:
            # Should not happen if policy is configured correctly
            fields_str = "*"

        # Start query
        query = f"SELECT {fields_str} FROM {request.resource}"

        # Build WHERE clause
        params: list[Any] = []
        if request.filters:
            conditions = []
            for key, value in request.filters.items():
                conditions.append(f"{key} = ?")
                params.append(value)

            query += " WHERE " + " AND ".join(conditions)

        # Add LIMIT
        if request.limit:
            query += f" LIMIT {request.limit}"

        return query, params

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self) -> None:
        """Cleanup connection on deletion."""
        self.close()
