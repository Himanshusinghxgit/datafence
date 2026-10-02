"""
Snowflake connector for DataFence (Phase 5).

Replaces the legacy snowflake.py which used the old ExecutionRequest interface.

SECURITY:
    - Accepts ONLY signed AuthorizedExecution capabilities
    - HMAC signature verified before any query is built
    - All identifiers validated (schema, table, column names)
    - Filter values parameterised via Snowflake %s placeholders
    - Never executes raw SQL from the LLM

Requires: snowflake-connector-python >= 3.0
    pip install 'datafence[snowflake]'

Usage::

    from datafence.connectors.snowflake_connector import SnowflakeConnector
    from datafence.core.boundary import DataFenceBoundary

    boundary = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=SnowflakeConnector,
        registry=policy_engine.registry,
        account="myaccount.us-east-1",
        user="datafence_service",
        password="...",
        warehouse="COMPUTE_WH",
        database="PROD_DB",
        schema="PUBLIC",
    )
"""

from __future__ import annotations

from typing import Any

from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.resources import validate_identifier
from datafence.core.types import Operation


class SnowflakeConnector:
    """
    Snowflake connector with cryptographic capability verification (Phase 5).

    Uses the official snowflake-connector-python library.
    Each connector instance owns one Snowflake connection.
    """

    def __init__(
        self,
        signing_key: bytes,
        account: str,
        user: str,
        database: str = "",
        schema: str = "PUBLIC",
        warehouse: str = "",
        role: str = "",
        **kwargs: Any,
    ) -> None:
        try:
            import snowflake.connector as snowflake_connector
        except ImportError as exc:
            raise ImportError(
                "snowflake-connector-python is required for Snowflake support. "
                "Install with: pip install 'datafence[snowflake]'"
            ) from exc

        self._signing_key = signing_key
        self._schema = schema
        self._database = database

        connect_params: dict[str, Any] = {
            "account": account,
            "user": user,
            **kwargs,
        }
        if database:
            connect_params["database"] = database
        if schema:
            connect_params["schema"] = schema
        if warehouse:
            connect_params["warehouse"] = warehouse
        if role:
            connect_params["role"] = role

        self._dict_cursor = snowflake_connector.DictCursor
        self._conn = snowflake_connector.connect(**connect_params)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """Execute a signed capability against Snowflake."""
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid capability signature for execution {capability.execution_id!r}."
            )
        if capability.is_expired():
            raise CapabilityVerificationError(
                f"Expired capability for execution {capability.execution_id!r}"
            )

        sql, params = self._compile(capability)

        cursor = self._conn.cursor(self._dict_cursor)
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        authorised = set(capability.selected_fields)
        return [{k: v for k, v in row.items() if k in authorised} for row in rows]

    # ------------------------------------------------------------------
    # SQL compiler
    # ------------------------------------------------------------------

    def _compile(self, capability: AuthorizedExecution) -> tuple[str, list[Any]]:
        if capability.operation == Operation.READ:
            return self._compile_select(capability)
        raise NotImplementedError(
            f"Operation {capability.operation!r} not supported in SnowflakeConnector"
        )

    def _compile_select(self, capability: AuthorizedExecution) -> tuple[str, list[Any]]:
        """
        Compile a parameterised SELECT for Snowflake.

        Identifiers are quoted with double-quotes (Snowflake convention).
        Values are parameterised with %s.
        """
        resource = validate_identifier(capability.resource, "resource name")
        fields_sql = ", ".join(
            f'"{validate_identifier(f, "field name")}"' for f in capability.selected_fields
        )

        # Qualify with database.schema if available
        if self._database:
            db = validate_identifier(self._database, "database name")
            sc = validate_identifier(self._schema, "schema name")
            table_ref = f'"{db}"."{sc}"."{resource}"'
        elif self._schema:
            sc = validate_identifier(self._schema, "schema name")
            table_ref = f'"{sc}"."{resource}"'
        else:
            table_ref = f'"{resource}"'

        sql = f"SELECT {fields_sql} FROM {table_ref}"
        params: list[Any] = []

        if capability.enforced_filters:
            conditions: list[str] = []
            for col, val in capability.enforced_filters.items():
                safe_col = validate_identifier(col, "filter column")
                conditions.append(f'"{safe_col}" = %s')
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

    def __enter__(self) -> SnowflakeConnector:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
