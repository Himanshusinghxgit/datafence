"""
Base connector interface.

All data connectors must implement this interface.
"""

from abc import ABC, abstractmethod
from typing import Any

from datafence.core.request import ExecutionRequest


class DataConnector(ABC):
    """
    Abstract base class for data connectors.

    Connectors handle actual data access after policy enforcement.
    """

    @abstractmethod
    def execute(self, request: ExecutionRequest, allowed_fields: list[str] | None = None) -> Any:
        """
        Execute a request against the data source.

        Args:
            request: Validated execution request
            allowed_fields: List of allowed fields (None means all)

        Returns:
            Query result

        Raises:
            ConnectorError: If execution fails
        """
        pass

    @abstractmethod
    def describe(self, resource: str) -> dict[str, Any]:
        """
        Describe a resource (table schema, etc.).

        Args:
            resource: Resource name

        Returns:
            Resource metadata

        Raises:
            ConnectorError: If resource doesn't exist
        """
        pass

    def validate(self, request: ExecutionRequest) -> None:
        """
        Validate a request before execution (optional).

        Default implementation does nothing. Subclasses can override.

        Args:
            request: Execution request

        Raises:
            ValidationError: If request is invalid
        """
        # Default: no validation
        return None
