"""
InMemoryReferenceConnector — for tests and examples only.

This connector stores data in a Python dict and executes AuthorizedExecution
capabilities against it.  It demonstrates the full connector contract:

    1. Verify signature.
    2. Verify expiry.
    3. Verify audience.
    4. Translate typed IR → in-memory filter.
    5. Return only authorized fields.

Do NOT use this in production.  Use your existing database/API layer instead.
"""

from __future__ import annotations

from typing import Any

from datafence.connectors.protocol import ConnectorResult
from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.types import Operation


class InMemoryReferenceConnector:
    """
    Simple in-memory connector for tests and quickstart examples.

    Parameters
    ----------
    data : dict[str, list[dict]]
        A mapping of resource_name → list of row dicts.
    signing_key : bytes
        The same HMAC key used to create the boundary.
    expected_audience : str
        Must match the audience tag in the issued capabilities.
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
        """Execute a signed capability against the in-memory store.

        Raises:
            CapabilityVerificationError: If the capability is invalid.
            NotImplementedError:         If the operation is not READ.
        """
        # 1. Verify cryptographic signature.
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid signature on capability {capability.execution_id!r}"
            )
        # 2. Verify expiry.
        if capability.is_expired():
            raise CapabilityVerificationError(
                f"Capability {capability.execution_id!r} has expired"
            )
        # 3. Verify audience.
        if capability.audience != self._expected_audience:
            raise CapabilityVerificationError(
                f"Audience mismatch: got {capability.audience!r}, "
                f"expected {self._expected_audience!r}"
            )

        if capability.operation != Operation.READ:
            raise NotImplementedError(
                f"InMemoryReferenceConnector only supports READ, "
                f"got {capability.operation!r}"
            )

        rows = self._data.get(capability.resource, [])
        rows = self._apply_filters(rows, capability)
        rows = rows[: capability.limit]
        # Return only the authorized fields.
        result_rows = [
            {k: v for k, v in row.items() if k in capability.selected_fields}
            for row in rows
        ]
        return ConnectorResult(
            rows=result_rows,
            row_count=len(result_rows),
            execution_id=capability.execution_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_filters(
        self,
        rows: list[dict[str, Any]],
        capability: AuthorizedExecution,
    ) -> list[dict[str, Any]]:
        """Apply the capability's enforced predicates as an in-memory filter."""
        constraints = capability.filter_constraints()
        if not constraints:
            return rows

        result = []
        for row in rows:
            if all(self._matches(row, c) for c in constraints):
                result.append(row)
        return result

    @staticmethod
    def _matches(row: dict[str, Any], constraint: dict[str, Any]) -> bool:
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
