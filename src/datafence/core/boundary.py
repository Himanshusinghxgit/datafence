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

Compile-time validation
-----------------------
``DataFenceBoundary.create()`` performs **compile-time** validation of the
policy against the registry BEFORE serving any authorization requests:

    - Every policy resource must exist in the registry.
    - Every allowed/denied/row-rule field must exist on its resource.
    - Every action named in the policy must be a valid operation for the resource.
    - Tenant-scoped resources MUST have a tenant-bound row rule in the policy, or
      be explicitly declared cross-tenant — otherwise creation is rejected.

This ensures the boundary NEVER silently serves a misconfigured policy.

Policy immutability
-------------------
After ``create()`` returns, the policy is **frozen** via an internal snapshot.
Mutations to the original ``DataFencePolicy`` or ``ResourcePolicy`` objects
have no effect on an already-created boundary.

Signing key requirements
------------------------
Minimum 32 bytes (256 bits) for HMAC-SHA256, enforced at construction.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from uuid import uuid4

from datafence.core.capability import MIN_KEY_BYTES, AuthorizedExecution
from datafence.core.policy import (
    DataFencePolicy,
    DataFencePolicyEngine,
    PolicyEffect,
    ResourcePolicy,
)
from datafence.core.policy import (
    PolicyDecision as EnginePolicyDecision,
)
from datafence.core.principal import Principal
from datafence.core.registry import ResourceRegistry
from datafence.core.resources import Filter
from datafence.core.types import Intent, Request
from datafence.errors import ConfigurationError, PolicyDeniedError, PolicyError


class PolicyEngine(Protocol):
    """Minimal generic policy contract required by DataFenceBoundary."""

    def evaluate(self, principal: Principal, intent: Intent) -> EnginePolicyDecision: ...


_SENTINEL = object()  # used to gate direct construction


# ---------------------------------------------------------------------------
# Compile-time policy + registry validator
# ---------------------------------------------------------------------------


def _validate_policy_against_registry(
    policy: DataFencePolicy,
    registry: ResourceRegistry,
) -> None:
    """
    Validate the policy against the registry at boundary creation time.

    Raises:
        ConfigurationError: If any policy reference is invalid.
    """
    errors: list[str] = []

    for res_name, rp in policy.resources.items():
        # Resource must exist in registry
        res_def = registry.get(res_name)
        if res_def is None:
            errors.append(
                f"Policy references resource {res_name!r} which is not registered."
            )
            continue  # can't validate fields without the resource

        valid_fields = set(res_def.field_names())
        valid_ops = set(res_def.supported_operations)

        # Validate actions reference valid operations
        for action in rp.actions:
            if action.lower() not in valid_ops:
                errors.append(
                    f"Policy for {res_name!r} references unsupported operation "
                    f"{action!r}. Supported: {sorted(valid_ops)}"
                )

        # Validate allowed_fields
        for f in rp.allowed_fields:
            if f not in valid_fields:
                errors.append(
                    f"Policy for {res_name!r} references unknown allowed_field {f!r}."
                )

        # Validate denied_fields
        for f in rp.denied_fields:
            if f not in valid_fields:
                errors.append(
                    f"Policy for {res_name!r} references unknown denied_field {f!r}."
                )

        # Validate row-rule fields
        for rule in rp.row_rules:
            if rule.field not in valid_fields:
                errors.append(
                    f"Policy for {res_name!r} row-rule references unknown field {rule.field!r}."
                )

        # Validate max_rows is positive
        if rp.max_rows <= 0:
            errors.append(
                f"Policy for {res_name!r} has invalid max_rows={rp.max_rows} "
                "(must be positive)."
            )

        # Tenant isolation check: if a resource has a tenant key,
        # an allow-capable policy MUST include a tenant-bound row rule.
        tenant_key = res_def.tenant_key()

        # Only check if there's at least one ALLOW action
        from datafence.core.policy import ActionDecision
        has_allow_action = any(
            v == ActionDecision.ALLOW for v in rp.actions.values()
        )

        if tenant_key and has_allow_action:
            # Check that a row rule exists that enforces tenant isolation
            tenant_rules = [
                r for r in rp.row_rules
                if r.field == tenant_key and _is_tenant_bound_value(r.value)
            ]
            if not tenant_rules:
                errors.append(
                    f"Policy for {res_name!r} allows access to a tenant-scoped resource "
                    f"(tenant key: {tenant_key!r}) but has no mandatory tenant isolation "
                    "row rule (e.g. RowRule(tenant_key, EQ, ':actor_tenant_id')). "
                    "Add a tenant row rule or mark the resource as global by removing "
                    "is_tenant_key=True from its tenant field."
                )

    if errors:
        raise ConfigurationError(
            "Policy validation failed:\n" + "\n".join(f"  • {e}" for e in errors)
        )


def _is_tenant_bound_value(value: Any) -> bool:
    """Return True if the row-rule value is a principal-bound tenant reference."""
    return isinstance(value, str) and value in (
        ":actor_tenant_id",
        ":actor.tenant_id",
    )


# ---------------------------------------------------------------------------
# DataFenceBoundary
# ---------------------------------------------------------------------------


class DataFenceBoundary:
    """Deterministic authorization and capability-issuance boundary.

    Always construct via :meth:`create` — direct instantiation is blocked.

    Parameters (via ``create``)
    ---------------------------
    policy_engine       : Object implementing the PolicyEngine protocol.
    registry            : Populated ResourceRegistry; frozen at create() time.
    signing_key         : HMAC key — minimum 32 bytes.  Keep it secret.
    capability_ttl_seconds : How long issued capabilities are valid (default 300 s).
    capability_audience : Audience tag embedded in every capability (default ``"datafence"``).
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
        """Create and validate a boundary.

        Performs compile-time validation of:
        - Signing key minimum length (32 bytes).
        - policy_engine/registry identity match.
        - Every policy resource exists in the registry.
        - Every policy field reference is valid.
        - Every policy operation reference is valid.
        - Tenant-scoped resources have a mandatory tenant isolation row rule.
        - The policy is deep-copied and frozen so post-create mutations have no effect.

        Raises:
            ValueError: For invalid primitive arguments.
            ConfigurationError: For policy/registry consistency failures.
        """
        if len(signing_key) < MIN_KEY_BYTES:
            raise ValueError(
                f"signing_key must be at least {MIN_KEY_BYTES} bytes "
                f"(got {len(signing_key)}) — use secrets.token_bytes(32) or larger"
            )
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

        # Compile-time policy + registry validation (Phases 5, 7)
        raw_policy = getattr(policy_engine, "_policy", None)
        if isinstance(raw_policy, DataFencePolicy):
            _validate_policy_against_registry(raw_policy, registry)

        # Freeze the registry — no new resources after this point
        registry.freeze()

        # Freeze the policy by deep-copying it into the engine so that
        # mutations to the caller's DataFencePolicy have no effect (Phase 6)
        if isinstance(policy_engine, DataFencePolicyEngine) and isinstance(raw_policy, DataFencePolicy):
            frozen_policy = _deep_freeze_policy(raw_policy)
            object.__setattr__(policy_engine, "_policy", frozen_policy)

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

    def authorize(self, principal: Principal, intent: Intent) -> AuthorizedExecution:
        """Authorize an intent and return a signed authorization capability.

        This is the *only* public method on DataFenceBoundary.
        No connector is constructed or invoked here. DataFence does not
        execute enterprise data operations.

        Args:
            principal : Authenticated principal from the application auth layer.
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
            enforced_predicates=resolved_filter.to_constraints(),
            limit=limit,
            policy_version=decision.policy_version,
            policy_decisions=list(decision.matched_rules),
            signing_key=self._signing_key,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=self._capability_ttl_seconds),
            audience=self._capability_audience,
            obligations=dict(decision.obligations or {}),
        )

    # ------------------------------------------------------------------
    # Read-only introspection
    # ------------------------------------------------------------------

    @property
    def registry(self) -> ResourceRegistry:
        """Return the frozen registry used for authorization."""
        return self._registry


# ---------------------------------------------------------------------------
# Policy deep-freeze helper (Phase 6)
# ---------------------------------------------------------------------------


def _deep_freeze_policy(policy: DataFencePolicy) -> DataFencePolicy:
    """
    Return a deep-copied, immutable snapshot of *policy*.

    After ``DataFenceBoundary.create()`` the boundary always evaluates
    against this snapshot — mutations to the caller's original objects
    have no effect.
    """
    frozen_resources: dict[str, ResourcePolicy] = {}
    for name, rp in policy.resources.items():
        frozen_resources[name] = ResourcePolicy(
            resource=rp.resource,
            actions=dict(rp.actions),
            allowed_fields=list(rp.allowed_fields),
            denied_fields=list(rp.denied_fields),
            filterable_fields=list(rp.filterable_fields),
            row_rules=list(rp.row_rules),
            max_rows=rp.max_rows,
            obligations=copy.deepcopy(rp.obligations),
        )
    return DataFencePolicy(
        name=policy.name,
        version=policy.version,
        resources=frozen_resources,
    )
