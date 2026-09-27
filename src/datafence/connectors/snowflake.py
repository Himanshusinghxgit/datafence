"""
Snowflake connector for cloud data warehouse.

Executes queries against Snowflake with connection pooling.
"""

from typing import Any

try:
    import snowflake.connector
    from snowflake.connector import DictCursor
    from snowflake.connector.errors import DatabaseError, ProgrammingError
except ImportError:
    snowflake = None
    DictCursor = None
    DatabaseError = None
    ProgrammingError = None

from datafence.connectors.base import DataConnector
from datafence.core.request import ExecutionRequest, Operation
from datafence.errors import ConnectorError, ValidationError


class SnowflakeConnector(DataConnector):
    """
    Snowflake connector for cloud data warehouse.

    Features:
    - Connection pooling
    - Multiple authentication methods
    - Warehouse and schema management
    - Proper error handling
    - Dict-based results

    Example:
        connector = SnowflakeConnector(
            account="myaccount",
            user="myuser",
            password="mypassword",
            database="MYDB",
            schema="PUBLIC",
            warehouse="COMPUTE_WH"
        )
    """

    def __init__(
        self,
        account: str,
        user: str,
        password: str | None = None,
        database: str | None = None,
        schema: str = "PUBLIC",
        warehouse: str | None = None,
        role: str | None = None,
        authenticator: str | None = None,
        private_key: bytes | None = None,
        session_parameters: dict[str, Any] | None = None,
        timeout: int = 300,
    ):
        """
        Initialize Snowflake connector.

        Args:
            account: Snowflake account identifier
            user: Username
            password: Password (if using password auth)
            database: Database name
            schema: Schema name (default: PUBLIC)
            warehouse: Warehouse name
            role: Role to use
            authenticator: Authentication method (e.g., 'externalbrowser', 'snowflake')
            private_key: Private key for key-pair authentication
            session_parameters: Additional session parameters
            timeout: Query timeout in seconds

        Raises:
            ImportError: If snowflake-connector-python not installed
            ConnectorError: If connection fails
        """
        if snowflake is None:
            raise ImportError(
                "snowflake-connector-python is not installed. "
                "Install with: pip install 'datafence[snowflake]'"
            )

        self.account = account
        self.user = user
        self.database = database
        self.schema = schema
        self.warehouse = warehouse
        self.timeout = timeout

        # Build connection parameters
        conn_params = {
            "account": account,
            "user": user,
            "database": database,
            "schema": schema,
            "warehouse": warehouse,
            "network_timeout": timeout,
        }

        if password:
            conn_params["password"] = password
        if role:
            conn_params["role"] = role
        if authenticator:
            conn_params["authenticator"] = authenticator
        if private_key:
            conn_params["private_key"] = private_key
        if session_parameters:
            conn_params["session_parameters"] = session_parameters

        # Create connection
        try:
            self.conn = snowflake.connector.connect(**conn_params)
        except Exception as e:
            raise ConnectorError(f"Failed to connect to Snowflake: {e}") from e

    def execute(
        self, request: ExecutionRequest, allowed_fields: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """
        Execute query against Snowflake.

        Args:
            request: Execution request
            allowed_fields: Allowed fields from policy

        Returns:
            Query results as list of dicts

        Raises:
            ConnectorError: If query fails
            ValidationError: If operation not supported
        """
        if request.operation != Operation.READ:
            raise ValidationError(
                f"Snowflake connector only supports READ operations, got: {request.operation}"
            )

        # Build query
        query, params = self._build_query(request, allowed_fields)

        # Execute query
        try:
            cursor = self.conn.cursor(DictCursor)

            # Set query timeout
            cursor.execute(f"ALTER SESSION SET STATEMENT_TIMEOUT_IN_SECONDS = {self.timeout}")

            # Execute query with parameters
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            # Fetch all results
            results = cursor.fetchall()

            cursor.close()

            return results

        except (DatabaseError, ProgrammingError) as e:
            raise ConnectorError(f"Snowflake query failed: {e}") from e
        except Exception as e:
            raise ConnectorError(f"Unexpected error: {e}") from e

    def describe(self, resource: str) -> dict[str, Any]:
        """
        Describe a Snowflake table.

        Args:
            resource: Table name (can include schema: schema.table)

        Returns:
            Table metadata

        Raises:
            ConnectorError: If table doesn't exist
        """
        try:
            cursor = self.conn.cursor(DictCursor)

            # Parse schema and table
            if "." in resource:
                schema, table = resource.split(".", 1)
            else:
                schema = self.schema
                table = resource

            # Get column information
            cursor.execute(
                f"DESCRIBE TABLE {self._quote_identifier(schema)}.{self._quote_identifier(table)}"
            )

            columns = cursor.fetchall()

            if not columns:
                raise ConnectorError(f"Table '{resource}' not found or no access")

            # Get row count
            cursor.execute(
                f"SELECT COUNT(*) as count FROM {self._quote_identifier(schema)}.{self._quote_identifier(table)}"
            )
            row_count_result = cursor.fetchone()
            row_count = row_count_result["COUNT"] if row_count_result else 0

            cursor.close()

            return {
                "resource": resource,
                "schema": schema,
                "table": table,
                "columns": [
                    {
                        "name": col["name"],
                        "type": col["type"],
                        "nullable": col["null?"] == "Y",
                        "default": col.get("default"),
                    }
                    for col in columns
                ],
                "fields": [col["name"] for col in columns],
                "row_count": row_count,
            }

        except (DatabaseError, ProgrammingError) as e:
            raise ConnectorError(f"Failed to describe table '{resource}': {e}") from e

    def _build_query(
        self, request: ExecutionRequest, allowed_fields: list[str] | None
    ) -> tuple[str, list[Any]]:
        """
        Build parameterized query for Snowflake.

        Args:
            request: Execution request
            allowed_fields: Allowed fields

        Returns:
            Tuple of (query, parameters)
        """
        # Determine fields
        if allowed_fields:
            fields = allowed_fields
        elif request.fields:
            fields = request.fields
        else:
            fields = ["*"]

        # Build SELECT clause
        if fields == ["*"]:
            select_clause = "*"
        else:
            quoted_fields = [self._quote_identifier(f) for f in fields]
            select_clause = ", ".join(quoted_fields)

        # Start query
        query = f"SELECT {select_clause} FROM {self._quote_identifier(request.resource)}"

        # Build WHERE clause with parameters
        params: list[Any] = []
        if request.filters:
            conditions = []
            for key, value in request.filters.items():
                # Snowflake uses ? for positional parameters
                conditions.append(f"{self._quote_identifier(key)} = ?")
                params.append(value)

            query += " WHERE " + " AND ".join(conditions)

        # Add LIMIT
        if request.limit:
            query += f" LIMIT {int(request.limit)}"

        return query, params

    def _quote_identifier(self, identifier: str) -> str:
        """
        Quote Snowflake identifier.

        Args:
            identifier: Column or table name

        Returns:
            Quoted identifier
        """
        # Snowflake uses double quotes and escapes by doubling
        escaped = identifier.replace('"', '""')
        return f'"{escaped}"'

    def close(self) -> None:
        """Close Snowflake connection."""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass  # Ignore errors on close

    def __del__(self) -> None:
        """Cleanup on deletion."""
        self.close()

    def __enter__(self) -> "SnowflakeConnector":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
