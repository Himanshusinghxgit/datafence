"""The DataFence authorization boundary.

DataFence owns: resource registry validation, policy evaluation, and
capability issuance (HMAC-signed AuthorizedExecution).

DataFence deliberately does NOT own: connectors, credentials, database
connections, SQL compilation, or result execution. Those belong to the
customer's existing backend/data-access layer.

Canonical flow
--------------

    Principal (from app auth layer)
        +
    Intent (from AI agent — untrusted)
        |
        v
    DataFenceBoundary.authorize()
        |
        ├─ ResourceRegistry.validate_intent()  — schema/identifier check
        ├─ PolicyEngine.evaluate()             — who can do what
        └─ AuthorizedExecution (HMAC-signed)
                |
                v
        Customer-owned connector
                |
                v
        Enterprise data
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from uuid import uuid4

from datafence.core.capability import AuthorizedExecution
from datafence.core.policy import PolicyDecision as EnginePolicyDecision
from datafence.core.policy import PolicyEffect
from datafence.core.principal import Principal as Actor
from datafence.core.registry import ResourceRegistry
from datafence.core.resources import Filter
from datafence.core.types import Intent, Request
from datafence.errors import PolicyDeniedError, PolicyError


class PolicyEngine(Protocol):
    """Minimal generic policy contract required by DataFenceBoundary."""

    def evaluate(self, principal: Actor, intent: Intent) -> EnginePolicyDecision: ...


_SENTINEL = object()  # used to gate direct construction


class DataFenceBoundary:
    """Deterministic authorization and capability-issuance boundary.

    Always construct via :meth:`create` — direct instantiation is blocked.

    Parameters (via ``create``)
    ---------------------------
    policy_engine       : Object implementing the PolicyEngine protocol.
    registry            : Frozen ResourceRegistry.
    signing_key         : 32-byte HMAC key. Keep it secret; never log it.
    capability_ttl_seconds : How long issued capabilities are valid (default 300 s).
    capability_audience : Audience tag embedded in every capability (default "datafence").
    """

    # Typed instance attributes — declared here so mypy can see them.
    policy_engine: PolicyEngine
    _registry: ResourceRegistry
    _signing_key: bytes
    _capability_ttl_seconds: int
    _capability_audience: str

    def __init__(self, _guard: Any = None) -> None:
        if _guard is not _SENTINEL:
            raise TypeError(
                "Do not instantiate DataFenceBoundary directly. "
                "Use DataFenceBoundary.create()."
            )

    @classmethod
    def create(
        cls,
        policy_engine: PolicyEngine,
        registry: ResourceRegistry,
        signing_key: bytes,
        capability_ttl_seconds: int = 300,
        capability_audience: str = "datafence",
    ) -> DataFenceBoundary:
        """Create a boundary using customer-managed capability key material.

        Args:
            policy_engine          : Configured policy engine (DataFencePolicyEngine or custom).
            registry               : Populated ResourceRegistry; will be frozen here.
            signing_key            : Secret HMAC key (≥ 32 bytes recommended).
            capability_ttl_seconds : Validity window for issued capabilities.
            capability_audience    : Audience tag verified by the customer connector.

        Raises:
            ValueError: If any argument is invalid.
        """
        if not signing_key:
            raise ValueError("signing_key cannot be empty")
        if capability_ttl_seconds <= 0:
            raise ValueError("capability_ttl_seconds must be positive")
        if not capability_audience:
            raise ValueError("capability_audience cannot be empty")
        policy_registry = getattr(policy_engine, "registry", None)
        if policy_registry is not registry:
            raise ValueError(
                "policy_engine.registry must be the same object as the registry "
                "passed to DataFenceBoundary.create()"
            )
        registry.freeze()
        boundary = cls(_SENTINEL)
        boundary.policy_engine = policy_engine
        boundary._registry = registry
        boundary._signing_key = signing_key
        boundary._capability_ttl_seconds = capability_ttl_seconds
        boundary._capability_audience = capability_audience
        return boundary

    # ------------------------------------------------------------------
    # Public API — the only execution path
    # ------------------------------------------------------------------

    def authorize(self, principal: Actor, intent: Intent) -> AuthorizedExecution:
        """Authorize an intent and return a signed authorization capability.

        This is the *only* public method on DataFenceBoundary.
        No connector is constructed or invoked here. DataFence does not
        execute enterprise data operations.

        The returned AuthorizedExecution must be passed to the customer's
        own backend connector, which verifies the signature before executing
        the operation against the customer's data source.

        Args:
            principal : Authenticated principal from the application auth layer.
                        The LLM/agent must never be able to choose or modify this.
            intent    : Untrusted request from an AI agent or application.

        Returns:
            Signed AuthorizedExecution capability.

        Raises:
            PolicyDeniedError : If the request is denied by registry or policy.
            PolicyError       : If policy evaluation fails unexpectedly.
        """
        request = Request.create(principal, intent)

        # 1. Registry validation — fast-fail on unknown resources/fields/ops.
        try:
            self._registry.validate_intent(intent)
        except ValueError as exc:
            raise PolicyDeniedError(str(exc)) from exc

        # 2. Policy evaluation — must not raise; any unexpected exception → error.
        try:
            decision = self.policy_engine.evaluate(principal=principal, intent=intent)
        except Exception as exc:
            raise PolicyError("Policy evaluation failed unexpectedly") from exc

        # 3. Structural validation — malformed decision fails closed.
        if not isinstance(decision, EnginePolicyDecision):
            raise PolicyError(
                f"Policy engine returned unexpected type: {type(decision).__name__!r}"
            )
        if not hasattr(decision, "effect") or decision.effect not in (
            PolicyEffect.ALLOW,
            PolicyEffect.DENY,
        ):
            raise PolicyError("Policy decision has invalid or missing effect — failing closed")

        # 4. Deny path.
        if decision.effect == PolicyEffect.DENY:
            raise PolicyDeniedError("; ".join(decision.reasons))

        # 5. Build and return the signed capability.
        return self._build_capability(request, decision)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_capability(
        self, request: Request, decision: EnginePolicyDecision
    ) -> AuthorizedExecution:
        """Construct and sign an AuthorizedExecution from a policy ALLOW."""
        # Intersect policy-allowed fields with agent-requested fields.
        selected_fields = list(decision.allowed_fields)
        if request.intent.fields:
            selected_fields = [f for f in request.intent.fields if f in selected_fields]
        if not selected_fields:
            raise PolicyDeniedError("No authorized fields available for this request")

        # Merge policy-enforced filters with agent-requested filters.
        # Policy filter takes priority over agent-supplied filters on the same field.
        resolved_filter = decision.enforced_filter.merge(
            Filter.from_dict(request.intent.filters)
        ).resolve(request.actor)

        # Row limit: policy is the ceiling; agent may request fewer.
        limit = decision.row_limit.value
        if request.intent.limit is not None:
            limit = min(request.intent.limit, limit)

        return AuthorizedExecution._create_signed(
            execution_id=f"exec_{uuid4().hex[:16]}",
            actor=request.actor,
            resource=request.intent.resource,
            operation=request.intent.operation,
            selected_fields=selected_fields,
            enforced_filters=resolved_filter.to_dict(),
            enforced_predicates=resolved_filter.to_constraints(),
            limit=limit,
            policy_version=decision.policy_version,
            policy_decisions=list(decision.matched_rules),
            signing_key=self._signing_key,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=self._capability_ttl_seconds),
            audience=self._capability_audience,
        )

    # ------------------------------------------------------------------
    # Read-only introspection
    # ------------------------------------------------------------------

    @property
    def registry(self) -> ResourceRegistry:
        """Return the frozen registry used for authorization."""
        return self._registry
