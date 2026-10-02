"""
AWS Athena reference connector — for examples and demonstrations only.

This file is NOT part of DataFence core. DataFence does not own database connectors.

For production use, re-implement this pattern in your own codebase.

Requires: boto3 >= 1.28, pyathena >= 3.0
    pip install boto3 pyathena
"""

from __future__ import annotations

from typing import Any

from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.resources import validate_identifier
from datafence.core.types import Operation


class AthenaConnector:
    """Athena reference connector demonstrating the DataFence capability contract."""

    def __init__(
        self,
        signing_key: bytes,
        s3_staging_dir: str,
        region_name: str,
        schema_name: str = "default",
        expected_audience: str = "datafence",
        **kwargs: Any,
    ) -> None:
        try:
            import pyathena
        except ImportError as exc:
            raise ImportError("pyathena required: pip install pyathena") from exc

        self._signing_key = signing_key
        self._expected_audience = expected_audience
        self._schema_name = schema_name
        self._conn = pyathena.connect(
            s3_staging_dir=s3_staging_dir,
            region_name=region_name,
            schema_name=schema_name,
            **kwargs,
        )

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """Execute a signed capability against AWS Athena."""
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid signature on capability {capability.execution_id!r}"
            )
        if capability.is_expired():
            raise CapabilityVerificationError(f"Expired capability {capability.execution_id!r}")
        if capability.audience != self._expected_audience:
            raise CapabilityVerificationError("Capability audience mismatch")

        sql, params = self._compile(capability)
        cursor = self._conn.cursor()
        cursor.execute(sql, params)
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        authorized = set(capability.selected_fields)
        return [
            {col: val for col, val in zip(columns, row, strict=False) if col in authorized}
            for row in rows
        ]

    def _compile(self, capability: AuthorizedExecution) -> tuple[str, list[Any]]:
        if capability.operation == Operation.READ:
            return self._compile_select(capability)
        raise NotImplementedError(f"Operation {capability.operation!r} not supported")

    def _compile_select(self, capability: AuthorizedExecution) -> tuple[str, list[Any]]:
        resource = validate_identifier(capability.resource, "resource name")
        db = validate_identifier(self._schema_name, "schema name")
        fields_sql = ", ".join(
            validate_identifier(f, "field name") for f in capability.selected_fields
        )
        sql = f'SELECT {fields_sql} FROM "{db}"."{resource}"'
        params: list[Any] = []
        constraints = capability.filter_constraints()
        if constraints:
            conditions: list[str] = []
            for constraint in constraints:
                col = validate_identifier(constraint["field"], "filter column")
                operator = constraint["operator"]
                val = constraint.get("value")
                if operator in {"IS NULL", "IS NOT NULL"}:
                    conditions.append(f"{col} {operator}")
                elif operator in {"IN", "NOT IN"}:
                    values = list(val) if isinstance(val, (list, tuple, set)) else [val]
                    placeholders = ", ".join("?" for _ in values)
                    conditions.append(f"{col} {operator} ({placeholders})")
                    params.extend(values)
                else:
                    if operator not in {"=", "!=", "<", "<=", ">", ">="}:
                        raise ValueError(f"Unsupported operator: {operator!r}")
                    conditions.append(f"{col} {operator} ?")
                    params.append(val)
            sql += " WHERE " + " AND ".join(conditions)
        sql += f" LIMIT {int(capability.limit)}"
        return sql, params

    def close(self) -> None:
        if self._conn:
            self._conn.close()

    def __enter__(self) -> AthenaConnector:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
