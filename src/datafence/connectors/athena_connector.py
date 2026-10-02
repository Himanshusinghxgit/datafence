"""
AWS Athena connector for DataFence (Phase 5).

Replaces the legacy athena.py which used the old ExecutionRequest interface.

SECURITY:
    - Accepts ONLY signed AuthorizedExecution capabilities
    - HMAC signature verified before any query is built
    - All identifiers validated (database, table, column names)
    - Filter values parameterised via Athena prepared-statement syntax (?).
    - Never executes raw SQL from the LLM.

Requires: boto3 >= 1.28  and  pyathena >= 3.0
    pip install 'datafence[athena]'

Usage::

    from datafence.connectors.athena_connector import AthenaConnector
    from datafence.core.boundary import DataFenceBoundary

    boundary = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=AthenaConnector,
        registry=policy_engine.registry,
        s3_staging_dir="s3://my-bucket/athena-results/",
        region_name="us-east-1",
        schema_name="my_database",   # Glue catalog database
    )
"""

from __future__ import annotations

from typing import Any

from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.resources import validate_identifier
from datafence.core.types import Operation


class AthenaConnector:
    """
    AWS Athena connector with cryptographic capability verification (Phase 5).

    Uses PyAthena for query execution.  Queries are executed synchronously
    via the default cursor.

    Note: Athena uses ANSI-style parameterised queries with ? placeholders
    when using the PyAthena ParameterizedCursor.
    """

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
            raise ImportError(
                "pyathena is required for Athena support. "
                "Install with: pip install 'datafence[athena]'"
            ) from exc

        self._signing_key = signing_key
        self._expected_audience = expected_audience
        self._schema_name = schema_name
        self._conn = pyathena.connect(
            s3_staging_dir=s3_staging_dir,
            region_name=region_name,
            schema_name=schema_name,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """Execute a signed capability against AWS Athena."""
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid capability signature for execution {capability.execution_id!r}."
            )
        if capability.is_expired():
            raise CapabilityVerificationError(
                f"Expired capability for execution {capability.execution_id!r}"
            )
        if capability.audience != self._expected_audience:
            raise CapabilityVerificationError("Capability audience does not match connector")

        sql, params = self._compile(capability)

        cursor = self._conn.cursor()
        cursor.execute(sql, params)

        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()

        authorised = set(capability.selected_fields)
        return [
            {col: val for col, val in zip(columns, row, strict=False) if col in authorised}
            for row in rows
        ]

    # ------------------------------------------------------------------
    # SQL compiler
    # ------------------------------------------------------------------

    def _compile(self, capability: AuthorizedExecution) -> tuple[str, list[Any]]:
        if capability.operation == Operation.READ:
            return self._compile_select(capability)
        raise NotImplementedError(
            f"Operation {capability.operation!r} not supported in AthenaConnector"
        )

    def _compile_select(self, capability: AuthorizedExecution) -> tuple[str, list[Any]]:
        """
        Compile a parameterised SELECT for Athena.

        Identifiers validated, values parameterised with ? placeholders.
        """
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
                col = constraint["field"]
                operator = constraint["operator"]
                val = constraint.get("value")
                safe_col = validate_identifier(col, "filter column")
                if operator in {"IS NULL", "IS NOT NULL"}:
                    conditions.append(f"{safe_col} {operator}")
                elif operator in {"IN", "NOT IN"}:
                    values = list(val) if isinstance(val, (list, tuple, set)) else [val]
                    placeholders = ", ".join("?" for _ in values)
                    conditions.append(f"{safe_col} {operator} ({placeholders})")
                    params.extend(values)
                else:
                    if operator not in {"=", "!=", "<", "<=", ">", ">="}:
                        raise ValueError(f"Unsupported filter operator: {operator!r}")
                    conditions.append(f"{safe_col} {operator} ?")
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

    def __enter__(self) -> AthenaConnector:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
