"""
Snowflake reference connector — for examples and demonstrations only.

This file is NOT part of DataFence core. DataFence does not own database connectors.

For production use, re-implement this pattern in your own codebase.

Requires: snowflake-connector-python >= 3.0
    pip install snowflake-connector-python
"""

from __future__ import annotations

from typing import Any

from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.resources import validate_identifier
from datafence.core.types import Operation


class SnowflakeConnector:
    """Snowflake reference connector demonstrating the DataFence capability contract."""

    def __init__(
        self,
        signing_key: bytes,
        account: str,
        user: str,
        database: str = "",
        schema: str = "PUBLIC",
        warehouse: str = "",
        role: str = "",
        expected_audience: str = "datafence",
        **kwargs: Any,
    ) -> None:
        try:
            import snowflake.connector as sf
        except ImportError as exc:
            raise ImportError("snowflake-connector-python required") from exc

        self._signing_key = signing_key
        self._expected_audience = expected_audience
        self._schema = schema
        self._database = database
        self._dict_cursor = sf.DictCursor

        params: dict[str, Any] = {"account": account, "user": user, **kwargs}
        for k, v in [
            ("database", database),
            ("schema", schema),
            ("warehouse", warehouse),
            ("role", role),
        ]:
            if v:
                params[k] = v
        self._conn = sf.connect(**params)

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """Execute a signed capability against Snowflake."""
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid signature on capability {capability.execution_id!r}"
            )
        if capability.is_expired():
            raise CapabilityVerificationError(f"Expired capability {capability.execution_id!r}")
        if capability.audience != self._expected_audience:
            raise CapabilityVerificationError("Capability audience mismatch")

        sql, params = self._compile(capability)
        cursor = self._conn.cursor(self._dict_cursor)
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        authorized = set(capability.selected_fields)
        return [{k: v for k, v in row.items() if k in authorized} for row in rows]

    def _compile(self, capability: AuthorizedExecution) -> tuple[str, list[Any]]:
        if capability.operation == Operation.READ:
            return self._compile_select(capability)
        raise NotImplementedError(f"Operation {capability.operation!r} not supported")

    def _compile_select(self, capability: AuthorizedExecution) -> tuple[str, list[Any]]:
        resource = validate_identifier(capability.resource, "resource name")
        fields_sql = ", ".join(
            f'"{validate_identifier(f, "field name")}"' for f in capability.selected_fields
        )
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
        constraints = capability.filter_constraints()
        if constraints:
            conditions: list[str] = []
            for constraint in constraints:
                col = validate_identifier(constraint["field"], "filter column")
                operator = constraint["operator"]
                val = constraint.get("value")
                if operator in {"IS NULL", "IS NOT NULL"}:
                    conditions.append(f'"{col}" {operator}')
                elif operator in {"IN", "NOT IN"}:
                    values = list(val) if isinstance(val, (list, tuple, set)) else [val]
                    placeholders = ", ".join("%s" for _ in values)
                    conditions.append(f'"{col}" {operator} ({placeholders})')
                    params.extend(values)
                else:
                    if operator not in {"=", "!=", "<", "<=", ">", ">="}:
                        raise ValueError(f"Unsupported operator: {operator!r}")
                    conditions.append(f'"{col}" {operator} %s')
                    params.append(val)
            sql += " WHERE " + " AND ".join(conditions)
        sql += f" LIMIT {int(capability.limit)}"
        return sql, params

    def close(self) -> None:
        if self._conn:
            self._conn.close()

    def __enter__(self) -> SnowflakeConnector:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
