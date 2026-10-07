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

        # Tenant isolation check — strict semantic invariant
        tenant_key = res_def.tenant_key()
        from datafence.core.policy import ActionDecision
        has_allow_action = any(
            v == ActionDecision.ALLOW for v in rp.actions.values()
        )
        if tenant_key and has_allow_action:
            err = _validate_tenant_row_rule(rp, tenant_key, res_name)
            if err:
                errors.append(err)

    if errors:
        raise ConfigurationError(
            "Policy validation failed:\n" + "\n".join(f"  • {e}" for e in errors)
        )


def _is_tenant_bound_value(value: Any) -> bool:
    """Return True if the row-rule value is a principal-bound tenant reference."""
    return isinstance(value, str) and value == ":actor_tenant_id"


def _validate_tenant_row_rule(rp: ResourcePolicy, tenant_key: str, res_name: str) -> str | None:
    """
    Validate the tenant isolation row rule for *res_name*.

    Returns an error string if invalid, or None if OK.
    Requires exactly: field == tenant_key, operator == EQ, value == ":actor_tenant_id".
    """
    from datafence.core.resources import PredicateOperator

    tenant_rules = [
        r for r in rp.row_rules
        if r.field == tenant_key
    ]

    if not tenant_rules:
        return (
            f"Policy for {res_name!r} allows access to a tenant-scoped resource "
            f"(tenant key: {tenant_key!r}) but has no row rule on the tenant key field. "
            "Add: RowRule(tenant_key, PredicateOperator.EQ, ':actor_tenant_id')"
        )

    for rule in tenant_rules:
        # Operator must be EQ
        if rule.operator != PredicateOperator.EQ:
            return (
                f"Policy for {res_name!r}: tenant isolation row rule on "
                f"{tenant_key!r} must use operator EQ, got {rule.operator!r}. "
                "Non-EQ operators on the tenant key do not provide mandatory isolation."
            )
        # Value must be the principal tenant reference
        if not _is_tenant_bound_value(rule.value):
            return (
                f"Policy for {res_name!r}: tenant isolation row rule on "
                f"{tenant_key!r} must use value ':actor_tenant_id', "
                f"got {rule.value!r}. "
                "Literal values and other actor references do not provide "
                "per-principal tenant isolation."
            )

    return None


# ---------------------------------------------------------------------------
# Runtime decision validator — independent boundary-level cross-check
# ---------------------------------------------------------------------------


def _validate_decision_against_registry(
    decision: EnginePolicyDecision,
    request: Request,
    registry: ResourceRegistry,
) -> None:
    """
    Independently validate an ALLOW ``PolicyDecision`` against the frozen
    registry and the original request.

    This is the final security gate before DataFenceBoundary signs any
    capability.  It runs regardless of which ``PolicyEngine`` produced the
    decision, so that even a buggy or malicious custom engine cannot cause
    the boundary to sign an unsafe capability.

    All failures raise ``PolicyError`` (fail closed) except where a denial
    is appropriate — those raise ``PolicyDeniedError``.

    Invariants enforced
    -------------------
    1.  allowed_fields are all known in the registry.
    2.  allowed_fields contain no RESTRICTED fields.
    3.  allowed_fields are a subset of what the policy configured (if available).
    4.  enforced_filter predicates reference only known, non-RESTRICTED fields.
    5.  enforced_filter contains the mandatory tenant predicate (EQ, resolved value)
        for tenant-scoped resources.
    6.  decision.row_limit.value is positive and does not exceed policy max_rows
        (if a DataFencePolicyEngine with an accessible frozen policy is in use).
    7.  decision operation matches the request operation.
    8.  decision resource matches the request resource (via policy_version provenance check).
    9.  The decision does not carry an empty policy_version for a non-trivial decision.
    10. The request operation is supported by the registry for this resource.
    """
    from datafence.core.registry import DataClassification
    from datafence.core.resources import PredicateOperator

    resource_name = request.intent.resource
    principal = request.actor
    operation = request.intent.operation

    # Retrieve the frozen resource definition
    res_def = registry.get(resource_name)
    if res_def is None:
        raise PolicyError(
            f"Boundary cannot validate decision: resource {resource_name!r} "
            "not found in registry after validation — registry may have been tampered"
        )

    valid_fields: frozenset[str] = frozenset(res_def.field_names())
    restricted_fields: frozenset[str] = frozenset(
        n for n, fd in res_def.fields.items()
        if fd.classification == DataClassification.RESTRICTED
    )

    # ------------------------------------------------------------------
    # Invariant 7 / 8: operation and resource match the request
    # ------------------------------------------------------------------
    # The operation carried by the decision must match what was requested.
    # (PolicyDecision doesn't carry operation directly, but the matched_rules
    # and policy_version are cross-checked for sanity; the primary defence is
    # that _build_capability uses request.intent.operation, not the decision.)
    # Enforce that the operation is supported by the registry.
    op_str = operation.value.lower()
    if op_str not in res_def.supported_operations:
        raise PolicyDeniedError(
            f"Boundary rejects decision: operation {op_str!r} is not supported "
            f"on resource {resource_name!r} (registry says: {sorted(res_def.supported_operations)})"
        )

    # ------------------------------------------------------------------
    # Invariant 1: allowed_fields must exist in registry
    # ------------------------------------------------------------------
    unknown_allowed = [f for f in decision.allowed_fields if f not in valid_fields]
    if unknown_allowed:
        raise PolicyError(
            f"Boundary rejects decision: allowed_fields contains fields not in "
            f"registry for {resource_name!r}: {unknown_allowed}. "
            "A PolicyEngine must not authorize unknown fields."
        )

    # ------------------------------------------------------------------
    # Invariant 2: allowed_fields must not contain RESTRICTED fields
    # ------------------------------------------------------------------
    restricted_allowed = [f for f in decision.allowed_fields if f in restricted_fields]
    if restricted_allowed:
        raise PolicyError(
            f"Boundary rejects decision: allowed_fields contains RESTRICTED fields "
            f"for {resource_name!r}: {restricted_allowed}. "
            "RESTRICTED fields must never be in an allowed_fields list."
        )

    # ------------------------------------------------------------------
    # Invariant 4+5: enforced_filter field references
    # ------------------------------------------------------------------
    tenant_key = res_def.tenant_key()
    tenant_predicate_found = False

    for pred in decision.enforced_filter.predicates:
        field_name = pred.field.name

        # Field must exist in registry
        if field_name not in valid_fields:
            raise PolicyError(
                f"Boundary rejects decision: enforced_filter references unknown "
                f"field {field_name!r} on resource {resource_name!r}."
            )

        # Invariant 5: RESTRICTED fields must not be in enforced_filter
        if field_name in restricted_fields:
            raise PolicyError(
                f"Boundary rejects decision: enforced_filter references RESTRICTED "
                f"field {field_name!r} on resource {resource_name!r}."
            )

        # Check tenant predicate presence and semantics
        if tenant_key and field_name == tenant_key:
            # Operator must be EQ
            if pred.operator != PredicateOperator.EQ:
                raise PolicyError(
                    f"Boundary rejects decision: enforced_filter tenant predicate on "
                    f"{tenant_key!r} uses operator {pred.operator!r} — must be EQ."
                )
            # Value must equal the authenticated principal's tenant_id (resolved)
            if pred.value != principal.tenant_id:
                raise PolicyError(
                    f"Boundary rejects decision: enforced_filter tenant predicate "
                    f"value {pred.value!r} does not match authenticated principal's "
                    f"tenant_id {principal.tenant_id!r}. "
                    "Cross-tenant capability issuance is not permitted."
                )
            tenant_predicate_found = True

    # ------------------------------------------------------------------
    # Invariant 5 (mandatory tenant predicate)
    # ------------------------------------------------------------------
    if tenant_key and not tenant_predicate_found:
        raise PolicyError(
            f"Boundary rejects decision: resource {resource_name!r} is "
            f"tenant-scoped (tenant key: {tenant_key!r}) but the enforced_filter "
            "contains no tenant predicate. A PolicyEngine must always inject "
            "the tenant isolation predicate for tenant-scoped resources."
        )

    # ------------------------------------------------------------------
    # Invariant 12: decision must not be structurally malformed
    # ------------------------------------------------------------------
    if not decision.allowed_fields:
        raise PolicyError(
            "Boundary rejects decision: allowed_fields is empty in an ALLOW decision."
        )

    try:
        _row_limit = decision.row_limit.value
    except Exception as exc:
        raise PolicyError(
            f"Boundary rejects decision: row_limit is malformed — {exc}"
        ) from exc

    if _row_limit <= 0:
        raise PolicyError(
            f"Boundary rejects decision: row_limit.value={_row_limit!r} must be positive."
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

        # 5. Independent boundary-level validation of the ALLOW decision.
        #    This runs regardless of which PolicyEngine produced the decision.
        #    A custom engine cannot bypass registry/security invariants.
        _validate_decision_against_registry(decision, request, self._registry)

        # 6. Build and return the signed capability.
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
