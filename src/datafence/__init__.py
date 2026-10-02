"""
DataFence — Policy-Enforced Data Execution for AI.

The core principle: The model proposes. DataFence decides.

Version 1.0.0 — Capability-gated authorization and execution boundary
------------------------------------------
All legacy v0.1–v0.4 code has been moved to datafence._legacy/.
The public API exposes only the v1.0 capability-based architecture.

Single execution path:
    Intent (untrusted)
        ↓  Resource Registry validates identifiers
        ↓  Policy Engine evaluates + injects row filters
        ↓  AuthorizedExecution (HMAC-signed capability)
        ↓  Connector (verifies signature, compiles safe SQL)
        ↓  Result Validator
        → AllowedRequest + Evidence

There is no alternate path. No ExecutionRequest. No raw SQL from agents.

Quick start::

    from datafence import DataFenceBoundary, Actor, Intent, Operation
    from datafence import create_banking_policy
    from datafence.connectors.sqlite_connector import create_demo_database

    policy_engine = create_banking_policy()
    boundary = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=create_demo_database,
        registry=policy_engine.registry,
        database_path="data.db",
    )

    result = boundary.execute(
        Actor(id="agent:finance", tenant_id="acme"),
        Intent(resource="transactions", operation=Operation.READ,
               fields=["id", "merchant", "amount"]),
    )
"""

# ---------------------------------------------------------------------------
# Core boundary
# ---------------------------------------------------------------------------
from datafence.core.boundary import DataFenceBoundary

# ---------------------------------------------------------------------------
# Capability error (for exception handling)
# Note: AuthorizedExecution itself is NOT exported — it is internal to
# DataFenceBoundary. Application code should never construct capabilities.
# ---------------------------------------------------------------------------
from datafence.core.capability import CapabilityVerificationError

# ---------------------------------------------------------------------------
# Policy engine (v1.0)
# ---------------------------------------------------------------------------
from datafence.core.policy import (
    ActionDecision,
    DataFencePolicy,
    DataFencePolicyEngine,
    PolicyDecision,
    PolicyEffect,
    ResourcePolicy,
    RowRule,
    YAMLPolicyLoader,
    create_banking_policy,
)

# ---------------------------------------------------------------------------
# Resource Registry
# ---------------------------------------------------------------------------
from datafence.core.registry import (
    DataClassification,
    FieldDefinition,
    ResourceDefinition,
    ResourceRegistry,
    create_banking_registry,
)

# ---------------------------------------------------------------------------
# Typed execution IR
# ---------------------------------------------------------------------------
from datafence.core.resources import (
    FieldRef,
    Filter,
    Predicate,
    PredicateOperator,
    Projection,
    ResourceRef,
    RowLimit,
)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------
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
    Request,
)

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

__version__ = "1.0.0"

__all__ = [
    # ── Core ─────────────────────────────────────────────────────────────
    "DataFenceBoundary",
    # ── Types ─────────────────────────────────────────────────────────────
    "Actor",
    "Intent",
    "Request",
    "Operation",
    "Decision",
    "PolicyDecision",
    "ExecutionPlan",  # audit / evidence only — not executable
    "ExecutionResult",
    "AllowedRequest",
    "DeniedRequest",
    "Evidence",
    "AuditEvent",
    # ── Typed IR ──────────────────────────────────────────────────────────
    "ResourceRef",
    "FieldRef",
    "Predicate",
    "PredicateOperator",
    "Filter",
    "Projection",
    "RowLimit",
    # ── Policy ────────────────────────────────────────────────────────────
    "DataFencePolicyEngine",
    "DataFencePolicy",
    "ResourcePolicy",
    "RowRule",
    "ActionDecision",
    "PolicyEffect",
    "YAMLPolicyLoader",
    "create_banking_policy",
    # ── Registry ──────────────────────────────────────────────────────────
    "ResourceRegistry",
    "ResourceDefinition",
    "FieldDefinition",
    "DataClassification",
    "create_banking_registry",
    # ── Errors ────────────────────────────────────────────────────────────
    "CapabilityVerificationError",
    "DataFenceError",
    "PolicyError",
    "PolicyDeniedError",
    "ValidationError",
    "ConnectorError",
    "ExecutionError",
    "ConfigurationError",
]
