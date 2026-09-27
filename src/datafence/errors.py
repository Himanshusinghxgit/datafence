"""
DataFence exception hierarchy.

All exceptions inherit from DataFenceError for easy catching.
"""


class DataFenceError(Exception):
    """Base exception for all DataFence errors."""

    pass


class PolicyError(DataFenceError):
    """Raised when there's an issue with policy loading or validation."""

    pass


class PolicyDeniedError(DataFenceError):
    """Raised when a request is explicitly denied by policy."""

    def __init__(self, message: str, reasons: list[str] | None = None):
        super().__init__(message)
        self.reasons = reasons or []


class ValidationError(DataFenceError):
    """Raised when request or data validation fails."""

    pass


class ConnectorError(DataFenceError):
    """Raised when a connector operation fails."""

    pass


class ExecutionError(DataFenceError):
    """Raised when execution fails after authorization."""

    pass


class ConfigurationError(DataFenceError):
    """Raised when configuration is invalid."""

    pass
