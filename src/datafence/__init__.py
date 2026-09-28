"""
DataFence - A deterministic security boundary between AI agents and enterprise data.

The core principle: The model proposes. DataFence decides.

Version 0.4.0 - Cryptographic Capability Model
-----------------------------------------------

v0.4 introduces cryptographically signed capabilities with HMAC-SHA256,
eliminating forgery attacks discovered in v0.3 security review.

RECOMMENDED API (v0.4):
    from datafence.core.boundary import DataFenceBoundary
    
    boundary = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=create_demo_database,
        database_path=db_path
    )
    
    result = boundary.execute(actor, intent)

LEGACY API (v0.1-v0.3, DEPRECATED):
    from datafence import DataFence  # OLD - Insecure
    
    The legacy DataFence engine lacks cryptographic signatures and is
    vulnerable to capability forgery attacks. Use DataFenceBoundary instead.
"""

# v0.4 API (RECOMMENDED)
from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import (
    Actor,
    AllowedRequest,
    Decision,
    DeniedRequest,
    Evidence,
    ExecutionPlan,
    ExecutionResult,
    Intent,
    Operation,
    Request,
)

# Legacy v0.1-v0.3 API (DEPRECATED)
from datafence.core.context import ActorType, RequestContext
from datafence.core.context import Actor as LegacyActor
from datafence.core.decision import DecisionStatus
from datafence.core.decision import Decision as LegacyDecision
from datafence.core.engine import DataFence  # DEPRECATED
from datafence.core.request import ExecutionRequest
from datafence.core.result import ExecutionResult as LegacyExecutionResult

# Errors
from datafence.errors import (
    ConfigurationError,
    ConnectorError,
    DataFenceError,
    ExecutionError,
    PolicyDeniedError,
    PolicyError,
    ValidationError,
)

__version__ = "0.4.0"

__all__ = [
    # ===== v0.4 API (RECOMMENDED) =====
    "DataFenceBoundary",
    "Actor",
    "Intent",
    "Request",
    "ExecutionPlan",
    "AllowedRequest",
    "DeniedRequest",
    "ExecutionResult",
    "Evidence",
    "Decision",
    "Operation",
    
    # ===== Legacy API (DEPRECATED) =====
    "DataFence",  # DEPRECATED: Use DataFenceBoundary
    "ExecutionRequest",
    "LegacyExecutionResult",
    "RequestContext",
    "LegacyActor",
    "ActorType",
    "LegacyDecision",
    "DecisionStatus",
    
    # ===== Errors =====
    "DataFenceError",
    "PolicyError",
    "PolicyDeniedError",
    "ValidationError",
    "ConnectorError",
    "ExecutionError",
    "ConfigurationError",
]
