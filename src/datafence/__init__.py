"""
DataFence — Policy-Enforced Data Execution for AI.

The core principle: The model proposes. DataFence decides.

Version 0.5.0 — Unified architecture
--------------------------------------

What's new in v0.5:
  - Typed Resource/Execution IR (ResourceRef, FieldRef, Predicate, Filter)
  - Identifier validation — no f-string interpolation of SQL identifiers
  - Enhanced policy model (DataFencePolicyEngine, YAML loader, Obligations)
  - Policy INJECTS row filters; the LLM cannot bypass or override them
  - PostgreSQL, Athena, Snowflake connectors on the new capability interface
  - MCP server + tool (Phase 6)
  - OpenAI, Anthropic, LangChain thin adapters (Phase 7)
  - ExecutionPlan clearly marked as audit/evidence only (not executable)

Recommended usage::

    from datafence import DataFenceBoundary, Actor, Intent, Operation
    from datafence.core.policy import create_banking_policy
    from datafence.connectors.sqlite_connector import create_demo_database

    boundary = DataFenceBoundary.create(
        policy_engine=create_banking_policy(),
        connector_factory=create_demo_database,
        database_path="/path/to/db.sqlite",
    )

    principal = Actor(id="agent:finance", tenant_id="acme-corp")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant", "amount"],
    )

    result = boundary.execute(principal, intent)

LEGACY API (v0.1–v0.4, deprecated)::

    from datafence import DataFence  # old engine, insecure
"""

# ---------------------------------------------------------------------------
# v0.5 core API
# ---------------------------------------------------------------------------

from datafence.core.boundary import DataFenceBoundary

from datafence.core.types import (
    Actor,
    AllowedRequest,
    AuditEvent,
    Decision,
    DeniedRequest,
    Evidence,
    ExecutionPlan,
    ExecutionResult,
    Intent,
    Operation,
    PolicyDecision,
    Request,
)

# Typed IR
from datafence.core.resources import (
    FieldRef,
    Filter,
    Predicate,
    PredicateOperator,
    Projection,
    ResourceRef,
    RowLimit,
)

# Enhanced policy model
from datafence.core.policy import (
    ActionDecision,
    DataFencePolicy,
    DataFencePolicyEngine,
    PolicyEffect,
    ResourcePolicy,
    RowRule,
    YAMLPolicyLoader,
    create_banking_policy,
)

# Resource Registry
from datafence.core.registry import (
    DataClassification,
    FieldDefinition,
    ResourceDefinition,
    ResourceRegistry,
    create_banking_registry,
)

# Capability — INTERNAL, not for application code
# AuthorizedExecution is created only by DataFenceBoundary.
# Applications should never construct or inspect capabilities directly.
# Exported here for testing and advanced integration use ONLY.
from datafence.core.capability import CapabilityVerificationError

# ---------------------------------------------------------------------------
# Legacy v0.1–v0.4 API (deprecated — kept for backward compatibility)
# ---------------------------------------------------------------------------

from datafence.core.context import ActorType, RequestContext
from datafence.core.context import Actor as LegacyActor
from datafence.core.decision import DecisionStatus
from datafence.core.decision import Decision as LegacyDecision
from datafence.core.engine import DataFence          # DEPRECATED
from datafence.core.request import ExecutionRequest
from datafence.core.result import ExecutionResult as LegacyExecutionResult

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

from datafence.errors import (
    ConfigurationError,
    ConnectorError,
    DataFenceError,
    ExecutionError,
    PolicyDeniedError,
    PolicyError,
    ValidationError,
)

__version__ = "0.5.0"

__all__ = [
    # ===== Core v0.5 API =====
    "DataFenceBoundary",

    # Types
    "Actor",
    "Intent",
    "Request",
    "Operation",
    "Decision",
    "PolicyDecision",
    "ExecutionPlan",
    "ExecutionResult",
    "AllowedRequest",
    "DeniedRequest",
    "Evidence",
    "AuditEvent",

    # Typed IR
    "ResourceRef",
    "FieldRef",
    "Predicate",
    "PredicateOperator",
    "Filter",
    "Projection",
    "RowLimit",

    # Policy
    "DataFencePolicyEngine",
    "DataFencePolicy",
    "ResourcePolicy",
    "RowRule",
    "ActionDecision",
    "PolicyEffect",
    "YAMLPolicyLoader",
    "create_banking_policy",

    # Resource Registry
    "ResourceRegistry",
    "ResourceDefinition",
    "FieldDefinition",
    "DataClassification",
    "create_banking_registry",

    # Capability (error only — AuthorizedExecution is internal)
    "CapabilityVerificationError",

    # ===== Legacy API (deprecated) =====
    "DataFence",
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
