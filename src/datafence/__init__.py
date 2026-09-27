"""
DataFence - A deterministic security boundary between AI agents and enterprise data.

The core principle: The model proposes. DataFence decides.
"""

from datafence.core.context import Actor, ActorType, RequestContext
from datafence.core.decision import Decision, DecisionStatus
from datafence.core.engine import DataFence
from datafence.core.request import ExecutionRequest, Operation
from datafence.core.result import ExecutionResult
from datafence.errors import (
    ConfigurationError,
    ConnectorError,
    DataFenceError,
    ExecutionError,
    PolicyDeniedError,
    PolicyError,
    ValidationError,
)

__version__ = "0.1.0"

__all__ = [
    # Core
    "DataFence",
    # Request/Response
    "ExecutionRequest",
    "ExecutionResult",
    "RequestContext",
    "Actor",
    "ActorType",
    "Operation",
    # Decision
    "Decision",
    "DecisionStatus",
    # Errors
    "DataFenceError",
    "PolicyError",
    "PolicyDeniedError",
    "ValidationError",
    "ConnectorError",
    "ExecutionError",
    "ConfigurationError",
]
