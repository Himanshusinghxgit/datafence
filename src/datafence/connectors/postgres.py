"""
PostgreSQL connector with connection pooling and prepared statements.

Production-ready connector for PostgreSQL databases.
"""

from typing import Any

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool
except ImportError:
    psycopg = None
    ConnectionPool = None
    dict_row = None

from datafence.connectors.base import DataConnector
from datafence.core.request import ExecutionRequest, Operation
from datafence.errors import ConnectorError, ValidationError


class PostgreSQLConnector(DataConnector):
    """
    PostgreSQL connector with connection pooling.

    Features:
    - Connection pooling for performance
    - Prepared statements for security
    - Proper error handling
    - Transaction support
    - Dict-based results

    Example:
        connector = PostgreSQLConnector(
            host="localhost",
            port=5432,
            database="mydb",
            user="user",
            password="password",
            min_pool_size=2,
            max_pool_size=10
        )
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str | None = None,
        user: str | None = None,
        password: str | None = None,
        connection_string: str | None = None,
        min_pool_size: int = 2,
        max_pool_size: int = 10,
        timeout: float = 30.0,
    ):
        """
        Initialize PostgreSQL connector.

        Args:
            host: Database host
            port: Database port
            database: Database name
            user: Database user
            password: Database password
            connection_string: Full connection string (overrides individual params)
            min_pool_size: Minimum connections in pool
            max_pool_size: Maximum connections in pool
            timeout: Query timeout in seconds

        Raises:
            ImportError: If psycopg is not installed
            ConnectorError: If connection fails
        """
        if psycopg is None:
            raise ImportError(
                "psycopg is not installed. Install with: pip install 'datafence[postgres]'"
            )

        self.timeout = timeout

        # Build connection string
        if connection_string:
            self.conninfo = connection_string
        else:
            if not all([database, user]):
                raise ConnectorError(
                    "Must provide either connection_string or (database, user)"
                )

            # Build connection string
            parts = [
                f"host={host}",
                f"port={port}",
                f"dbname={database}",
                f"user={user}",
            ]
            if password:
                parts.append(f"password={password}")

            self.conninfo = " ".join(parts)

        # Create connection pool
        try:
            self.pool = ConnectionPool(
                conninfo=self.conninfo,
                min_size=min_pool_size,
                max_size=max_pool_size,
                timeout=timeout,
                kwargs={"row_factory": dict_row},
            )
        except Exception as e:
            raise ConnectorError(f"Failed to create connection pool: {e}") from e

    def execute(
        self, request: ExecutionRequest, allowed_fields: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """
        Execute request against PostgreSQL.

        Args:
            request: Execution request
            allowed_fields: List of allowed fields

        Returns:
            Query results as list of dicts

        Raises:
            ConnectorError: If execution fails
            ValidationError: If operation not supported
        """
        if request.operation != Operation.READ:
            raise ValidationError(
                f"PostgreSQL connector currently only supports READ, got: {request.operation}"
            )

        # Build query
        query, params = self._build_query(request, allowed_fields)

        # Execute with connection from pool
        try:
            with self.pool.connection() as conn:
                with conn.cursor() as cur:
                    # Set statement timeout
                    cur.execute(f"SET statement_timeout = {int(self.timeout * 1000)}")

                    # Execute query with parameters (prepared statement)
                    cur.execute(query, params)

                    # Fetch results
                    results = cur.fetchall()

                    return results

        except psycopg.Error as e:
            raise ConnectorError(f"PostgreSQL query failed: {e}") from e
        except Exception as e:
            raise ConnectorError(f"Unexpected error: {e}") from e

    def describe(self, resource: str) -> dict[str, Any]:
        """
        Describe a PostgreSQL table.

        Args:
            resource: Table name (can include schema: schema.table)

        Returns:
            Table metadata including columns and row count

        Raises:
            ConnectorError: If table doesn't exist
        """
        try:
            with self.pool.connection() as conn:
                with conn.cursor() as cur:
                    # Parse schema and table
                    if "." in resource:
                        schema, table = resource.split(".", 1)
                    else:
                        schema = "public"
                        table = resource

                    # Get column information
                    cur.execute(
                        """
                        SELECT column_name, data_type, is_nullable
                        FROM information_schema.columns
                        WHERE table_schema = %s AND table_name = %s
                        ORDER BY ordinal_position
                        """,
                        (schema, table),
                    )

                    columns = cur.fetchall()

                    if not columns:
                        raise ConnectorError(
                            f"Table '{resource}' not found or no access"
                        )

                    # Get row count (approximate for large tables)
                    cur.execute(
                        """
                        SELECT reltuples::bigint AS estimate
                        FROM pg_class
                        WHERE oid = %s::regclass
                        """,
                        (f"{schema}.{table}",),
                    )

                    row_count_result = cur.fetchone()
                    row_count = (
                        row_count_result["estimate"] if row_count_result else 0
                    )

                    return {
                        "resource": resource,
                        "schema": schema,
                        "table": table,
                        "columns": [
                            {
                                "name": col["column_name"],
                                "type": col["data_type"],
                                "nullable": col["is_nullable"] == "YES",
                            }
                            for col in columns
                        ],
                        "fields": [col["column_name"] for col in columns],
                        "row_count_estimate": row_count,
                    }

        except psycopg.Error as e:
            raise ConnectorError(f"Failed to describe table '{resource}': {e}") from e

    def _build_query(
        self, request: ExecutionRequest, allowed_fields: list[str] | None
    ) -> tuple[str, list[Any]]:
        """
        Build safe parameterized query.

        Args:
            request: Execution request
            allowed_fields: Allowed fields from policy

        Returns:
            Tuple of (query, parameters)
        """
        # Determine fields to select
        if allowed_fields:
            fields = allowed_fields
        elif request.fields:
            fields = request.fields
        else:
            # Default to * but this should be controlled by policy
            fields = ["*"]

        # Build SELECT clause with proper quoting
        if fields == ["*"]:
            select_clause = "*"
        else:
            # Quote identifiers to prevent SQL injection
            quoted_fields = [self._quote_identifier(f) for f in fields]
            select_clause = ", ".join(quoted_fields)

        # Start query
        query = f"SELECT {select_clause} FROM {self._quote_identifier(request.resource)}"

        # Build WHERE clause with parameters
        params: list[Any] = []
        if request.filters:
            conditions = []
            for key, value in request.filters.items():
                conditions.append(f"{self._quote_identifier(key)} = %s")
                params.append(value)

            query += " WHERE " + " AND ".join(conditions)

        # Add LIMIT
        if request.limit:
            query += f" LIMIT {int(request.limit)}"

        return query, params

    def _quote_identifier(self, identifier: str) -> str:
        """
        Quote SQL identifier to prevent injection.

        Args:
            identifier: Column or table name

        Returns:
            Quoted identifier
        """
        # Simple quoting - escape double quotes and wrap
        escaped = identifier.replace('"', '""')
        return f'"{escaped}"'

    def close(self) -> None:
        """Close connection pool."""
        if self.pool:
            self.pool.close()

    def __del__(self) -> None:
        """Cleanup on deletion."""
        self.close()

    def __enter__(self) -> "PostgreSQLConnector":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
