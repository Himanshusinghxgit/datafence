"""
DataFence — Deterministic authorization boundary for AI/agent access to enterprise data.

Core principle: **The AI proposes. DataFence decides. The customer's application executes.**

The problem
-----------
AI systems are probabilistic and potentially untrusted.
Enterprise authorization cannot be probabilistic.
DataFence is the deterministic boundary between them.

Canonical flow::

    Authentication (app-owned)
          ↓
    Principal (trusted identity)
          +
    Intent (untrusted AI request)
          ↓
    DataFenceBoundary.authorize()
          ├─ ResourceRegistry.validate_intent()  — schema check
          ├─ PolicyEngine.evaluate()             — who can do what
          └─ AuthorizedExecution (HMAC-signed)   — the authorization artifact
                    ↓
          CapabilityToken.encode(authorized)       ← portable signed token
                    ↓
          transport to customer connector
                    ↓
          CapabilityVerifier.verify_token(token)   ← connector verifies
                    ↓
          customer_connector.execute(authorized)  ← customer-owned
                    ↓
          Enterprise data

DataFence does NOT own:
  - the connector
  - the database
  - credentials
  - query execution
  - result rows

Quick start::

    from secrets import token_bytes
    from datafence import (
        Principal, DataFenceBoundary, Intent, Operation,
        DataFencePolicyEngine, DataFencePolicy, ResourcePolicy, ActionDecision,
        ResourceRegistry, ResourceDefinition, FieldDefinition,
        CapabilityToken, CapabilityVerifier,
    )
    from datafence.core.policy import RowRule
    from datafence.core.resources import PredicateOperator

    # 1. Build the registry — WHAT resources exist and their schema
    registry = ResourceRegistry()
    registry.register(ResourceDefinition("orders", fields={
        "id":        FieldDefinition("id", "integer"),
        "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
        "total":     FieldDefinition("total", "decimal"),
        "status":    FieldDefinition("status", "string"),
    }))

    # 2. Define the policy — WHO can do WHAT
    policy = DataFencePolicy("orders-v1", "1.0", {
        "orders": ResourcePolicy(
            "orders",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "total", "status"],
            filterable_fields=["status", "tenant_id"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=100,
        )
    })
    engine = DataFencePolicyEngine(policy, registry=registry)

    # 3. Create the authorization boundary (validates policy against registry)
    key = token_bytes(32)   # keep this secret — minimum 32 bytes
    fence = DataFenceBoundary.create(engine, registry, key)

    # 4. Authorize — DataFence decides
    authorized = fence.authorize(
        Principal("user:alice", "tenant-acme"),
        Intent("orders", Operation.READ, fields=["id", "total", "status"]),
    )

    # 5. Transport — encode to a portable signed token
    token = CapabilityToken.encode(authorized)

    # 6. Verify and execute — customer decides how to run it
    #    (no DataFence runtime needed on the connector side)
    verified = CapabilityVerifier(key, expected_audience="datafence").verify_token(token)
    result = my_connector.execute(verified)   # your code, your database

See ``examples/basic/`` for a fully runnable example.
See ``docs/architecture.md`` for the security model.
"""

# ---------------------------------------------------------------------------
# Core authorization boundary
# ---------------------------------------------------------------------------
from datafence.core.boundary import DataFenceBoundary

# ---------------------------------------------------------------------------
# Capability, portable token, and customer-side verifier
# ---------------------------------------------------------------------------
from datafence.core.capability import (
    MIN_KEY_BYTES,
    AuthorizedExecution,
    CapabilityToken,
    CapabilityVerificationError,
    CapabilityVerifier,
)

# ---------------------------------------------------------------------------
# Policy engine
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
# Principal — the trusted authenticated identity
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
# Typed predicate / filter IR
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
    Intent,
    Operation,
)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
from datafence.errors import (
    ConfigurationError,
    DataFenceError,
    PolicyDeniedError,
    PolicyError,
    ValidationError,
)

__version__ = "1.0.0"

__all__ = [
    # ── Core boundary ────────────────────────────────────────────────────
    "DataFenceBoundary",
    # ── Capability and portable token ────────────────────────────────────
    "AuthorizedExecution",
    "CapabilityToken",
    "CapabilityVerifier",
    "CapabilityVerificationError",
    "MIN_KEY_BYTES",
    # ── Principal / identity ─────────────────────────────────────────────
    "Principal",
    # ── Intent and operation ─────────────────────────────────────────────
    "Intent",
    "Operation",
    # ── Typed predicate IR ───────────────────────────────────────────────
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
    "ConfigurationError",
]
