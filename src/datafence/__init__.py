"""
DataFence — Deterministic authorization boundary for AI agents accessing enterprise data.

Core principle: **The model proposes. DataFence decides. The customer's backend executes.**

Security invariant
------------------
An untrusted AI agent must never be able to cause an enterprise data connector to
execute an operation that DataFence has not explicitly authorized.

Canonical flow::

    Principal (from application auth layer)
        +
    Intent (from AI agent — untrusted)
        |
        v
    DataFenceBoundary.authorize()
        |
        ├─ ResourceRegistry.validate_intent()
        ├─ DataFencePolicyEngine.evaluate()
        └─ AuthorizedExecution (HMAC-signed)
                |
                v
        customer_connector.execute(authorized)   ← customer-owned
                |
                v
        Enterprise data

Quick start::

    from secrets import token_bytes
    from datafence import (
        Actor, DataFenceBoundary, Intent, Operation,
        DataFencePolicyEngine, DataFencePolicy, ResourcePolicy, ActionDecision,
        ResourceRegistry, ResourceDefinition, FieldDefinition,
        CapabilityVerifier,
    )

    # 1. Build the registry (WHAT exists and its schema contract)
    registry = ResourceRegistry()
    registry.register(ResourceDefinition("orders", fields={
        "id":        FieldDefinition("id", "integer"),
        "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
        "total":     FieldDefinition("total", "decimal"),
        "status":    FieldDefinition("status", "string"),
    }))

    # 2. Define the policy (WHO can do WHAT)
    from datafence.core.resources import PredicateOperator
    from datafence.core.policy import RowRule
    policy = DataFencePolicy("orders-v1", "1.0", {
        "orders": ResourcePolicy(
            "orders",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "total", "status"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=100,
        )
    })
    engine = DataFencePolicyEngine(policy, registry=registry)

    # 3. Create the boundary
    key = token_bytes(32)   # keep this secret
    fence = DataFenceBoundary.create(engine, registry, key)

    # 4. Authorize (DataFence decides)
    authorized = fence.authorize(
        Actor("user:alice", "tenant-acme"),
        Intent("orders", Operation.READ, fields=["id", "total", "status"]),
    )

    # 5. Pass to customer-owned connector (customer executes)
    CapabilityVerifier(key).verify(authorized)
    result = my_connector.execute(authorized)   # your code, your database

DataFence does NOT own the connector, the database, credentials, or
execution.  See ``examples/basic/`` for a fully runnable neutral example
and ``docs/architecture.md`` for the security model.
"""

# ---------------------------------------------------------------------------
# Core boundary
# ---------------------------------------------------------------------------
from datafence.core.boundary import DataFenceBoundary

# ---------------------------------------------------------------------------
# Capability contract and customer-side verifier
# ---------------------------------------------------------------------------
from datafence.core.capability import (
    AuthorizedExecution,
    CapabilityVerificationError,
    CapabilityVerifier,
)

# ---------------------------------------------------------------------------
# Policy engine (v1)
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
)

# ---------------------------------------------------------------------------
# Principal (richer alias for Actor with roles + attributes)
# ---------------------------------------------------------------------------
from datafence.core.principal import Principal

# ---------------------------------------------------------------------------
# Resource Registry
# ---------------------------------------------------------------------------
from datafence.core.registry import (
    DataClassification,
    FieldDefinition,
    ResourceDefinition,
    ResourceRegistry,
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
# Core types
# ---------------------------------------------------------------------------
from datafence.core.types import (
    Actor,
    Decision,
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
    # ── Core boundary ────────────────────────────────────────────────────
    "DataFenceBoundary",
    # ── Capability ───────────────────────────────────────────────────────
    "AuthorizedExecution",
    "CapabilityVerifier",
    "CapabilityVerificationError",
    # ── Types ────────────────────────────────────────────────────────────
    "Actor",
    "Principal",
    "Intent",
    "Request",
    "Operation",
    "Decision",
    # ── Typed IR ─────────────────────────────────────────────────────────
    "ResourceRef",
    "FieldRef",
    "Predicate",
    "PredicateOperator",
    "Filter",
    "Projection",
    "RowLimit",
    # ── Policy ───────────────────────────────────────────────────────────
    "PolicyDecision",
    "PolicyEffect",
    "DataFencePolicyEngine",
    "DataFencePolicy",
    "ResourcePolicy",
    "RowRule",
    "ActionDecision",
    "YAMLPolicyLoader",
    # ── Registry ─────────────────────────────────────────────────────────
    "ResourceRegistry",
    "ResourceDefinition",
    "FieldDefinition",
    "DataClassification",
    # ── Errors ───────────────────────────────────────────────────────────
    "DataFenceError",
    "PolicyError",
    "PolicyDeniedError",
    "ValidationError",
    "ConnectorError",
    "ExecutionError",
    "ConfigurationError",
]
