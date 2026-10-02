"""
DataFence exception hierarchy.

All exceptions inherit from DataFenceError for easy catching.

Hierarchy
---------
DataFenceError
├── PolicyError          — policy loading or evaluation failed
├── PolicyDeniedError    — request explicitly denied by policy
├── ValidationError      — request or schema validation failed
└── ConfigurationError   — boundary or registry misconfiguration

Notes on ownership
------------------
DataFence does not execute enterprise data operations.
Execution errors (database failures, network timeouts, etc.) belong to
the customer's connector layer and should be raised as connector-specific
exceptions rather than DataFenceError subclasses.
"""


class DataFenceError(Exception):
    """Base exception for all DataFence errors."""
    pass


class PolicyError(DataFenceError):
    """Raised when policy loading or evaluation fails unexpectedly."""
    pass


class PolicyDeniedError(DataFenceError):
    """Raised when a request is explicitly denied by policy or registry."""

    def __init__(self, message: str, reasons: list[str] | None = None):
        super().__init__(message)
        self.reasons = reasons or []


class ValidationError(DataFenceError):
    """Raised when request or schema validation fails."""
    pass


class ConfigurationError(DataFenceError):
    """Raised when boundary or registry configuration is invalid."""
    pass
