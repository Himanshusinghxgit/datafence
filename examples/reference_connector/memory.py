"""
In-memory reference connector — for examples and tests only.

The simplest possible connector: stores data in a Python dict, applies
filter predicates in-memory, and returns authorized fields.

This demonstrates the full customer connector contract without any
database dependency:

    1. Receive AuthorizedExecution.
    2. Verify signature, expiry, audience.
    3. Apply typed predicates as in-memory filters.
    4. Return only the authorized fields.

For production, implement the connector in your own codebase using your
existing data-access layer.
"""

from __future__ import annotations

from typing import Any

from datafence.connectors.protocol import ConnectorResult
from datafence.core.capability import (
    AuthorizedExecution,
    CapabilityVerificationError,
)
from datafence.core.types import Operation


class InMemoryReferenceConnector:
    """
    Simple in-memory connector for tests and quickstart examples.

    This implementation is NOT part of the DataFence runtime package.
    It exists only as a reference implementation.
    """

    def __init__(
        self,
        data: dict[str, list[dict[str, Any]]],
        signing_key: bytes,
        expected_audience: str = "datafence",
    ) -> None:
        self._data = data
        self._signing_key = signing_key
        self._expected_audience = expected_audience

    def execute(self, capability: AuthorizedExecution) -> ConnectorResult:
        """Execute a signed capability against the in-memory store."""
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid signature on capability {capability.execution_id!r}"
            )

        if capability.is_expired():
            raise CapabilityVerificationError(f"Capability {capability.execution_id!r} has expired")

        if capability.audience != self._expected_audience:
            raise CapabilityVerificationError(
                f"Audience mismatch: got {capability.audience!r}, "
                f"expected {self._expected_audience!r}"
            )

        if capability.operation != Operation.READ:
            raise NotImplementedError(
                f"InMemoryReferenceConnector only supports READ, got {capability.operation!r}"
            )

        rows = self._data.get(capability.resource, [])
        rows = self._apply_filters(rows, capability)
        rows = rows[: capability.limit]

        result_rows = [
            {k: v for k, v in row.items() if k in capability.selected_fields} for row in rows
        ]

        return ConnectorResult(
            rows=result_rows,
            row_count=len(result_rows),
            execution_id=capability.execution_id,
        )

    def _apply_filters(
        self,
        rows: list[dict[str, Any]],
        capability: AuthorizedExecution,
    ) -> list[dict[str, Any]]:
        constraints = capability.filter_constraints()

        if not constraints:
            return rows

        return [
            row for row in rows if all(self._matches(row, constraint) for constraint in constraints)
        ]

    @staticmethod
    def _matches(
        row: dict[str, Any],
        constraint: dict[str, Any],
    ) -> bool:
        field = constraint["field"]
        operator = constraint["operator"]
        value = constraint.get("value")
        cell = row.get(field)

        if operator == "=":
            return cell == value
        if operator == "!=":
            return cell != value
        if operator == "<":
            return cell is not None and cell < value
        if operator == "<=":
            return cell is not None and cell <= value
        if operator == ">":
            return cell is not None and cell > value
        if operator == ">=":
            return cell is not None and cell >= value
        if operator == "IN":
            return cell in (value or [])
        if operator == "NOT IN":
            return cell not in (value or [])
        if operator == "IS NULL":
            return cell is None
        if operator == "IS NOT NULL":
            return cell is not None

        return False
