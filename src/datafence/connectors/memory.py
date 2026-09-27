"""
In-memory connector for testing and examples.
"""

from typing import Any

from datafence.connectors.base import DataConnector
from datafence.core.request import ExecutionRequest, Operation
from datafence.errors import ConnectorError, ValidationError


class MemoryConnector(DataConnector):
    """
    In-memory data connector.

    Stores data in Python dictionaries for testing.
    """

    def __init__(self, data: dict[str, list[dict[str, Any]]] | None = None):
        """
        Initialize memory connector.

        Args:
            data: Dictionary mapping resource names to lists of records
        """
        self.data = data or {}

    def execute(
        self, request: ExecutionRequest, allowed_fields: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """
        Execute request against in-memory data.

        Args:
            request: Execution request
            allowed_fields: List of allowed fields

        Returns:
            Filtered results

        Raises:
            ConnectorError: If resource doesn't exist
            ValidationError: If operation is not supported
        """
        if request.resource not in self.data:
            raise ConnectorError(f"Resource '{request.resource}' not found")

        if request.operation != Operation.READ:
            raise ValidationError(
                f"MemoryConnector only supports READ operations, got: {request.operation}"
            )

        # Get data
        records = self.data[request.resource]

        # Apply filters
        filtered = self._apply_filters(records, request.filters)

        # Project fields
        if allowed_fields or request.fields:
            fields = allowed_fields or request.fields or []
            filtered = self._project_fields(filtered, fields)

        # Apply limit
        if request.limit:
            filtered = filtered[: request.limit]

        return filtered

    def describe(self, resource: str) -> dict[str, Any]:
        """
        Describe a resource.

        Args:
            resource: Resource name

        Returns:
            Resource metadata
        """
        if resource not in self.data:
            raise ConnectorError(f"Resource '{resource}' not found")

        records = self.data[resource]
        if not records:
            return {"resource": resource, "fields": [], "row_count": 0}

        # Get fields from first record
        fields = list(records[0].keys())

        return {"resource": resource, "fields": fields, "row_count": len(records)}

    def _apply_filters(
        self, records: list[dict[str, Any]], filters: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Apply filters to records."""
        if not filters:
            return records

        result = []
        for record in records:
            match = True
            for key, value in filters.items():
                if key not in record or record[key] != value:
                    match = False
                    break
            if match:
                result.append(record)

        return result

    def _project_fields(
        self, records: list[dict[str, Any]], fields: list[str]
    ) -> list[dict[str, Any]]:
        """Project specific fields from records."""
        return [{k: v for k, v in record.items() if k in fields} for record in records]

    def add_data(self, resource: str, records: list[dict[str, Any]]) -> None:
        """
        Add data to a resource.

        Args:
            resource: Resource name
            records: List of records to add
        """
        if resource not in self.data:
            self.data[resource] = []
        self.data[resource].extend(records)
