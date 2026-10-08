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
        ├─ _validate_decision()                — boundary-owned invariants
        └─ AuthorizedExecution (HMAC-signed)
                |
                v
        Customer-owned connector
                |
                v
        Enterprise data

Authoritative policy ownership
-------------------------------
``DataFenceBoundary`` holds its own deep-frozen ``DataFencePolicy`` snapshot
(``_frozen_policy``) that is independent of the ``PolicyEngine`` implementation.
Every ``PolicyDecision`` — from the built-in engine or any custom engine — is
validated against this frozen policy before a capability is signed.

This means:
- A custom ``PolicyEngine`` CANNOT authorize fields outside ``allowed_fields``.
- A custom ``PolicyEngine`` CANNOT authorize more rows than ``max_rows``.
- Decision provenance (resource, operation, policy name/version) is ALWAYS
  cross-checked against the frozen policy and the request.

There is no lenient bypass path.  An ALLOW decision with incomplete or
mismatched provenance is REJECTED.

Compile-time validation
-----------------------
``DataFenceBoundary.create()`` performs **compile-time** validation of the
policy against the registry BEFORE serving any authorization requests.

Policy immutability
-------------------
After ``create()`` returns, the policy snapshot is deep-frozen and stored
on the boundary itself.  Mutations to the original objects have no effect.

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
    """Validate the policy against the registry at boundary creation time."""
    errors: list[str] = []

    for res_name, rp in policy.resources.items():
        res_def = registry.get(res_name)
        if res_def is None:
            errors.append(
                f"Policy references resource {res_name!r} which is not registered."
            )
            continue

        valid_fields = set(res_def.field_names())
        valid_ops = set(res_def.supported_operations)

        for action in rp.actions:
            if action.lower() not in valid_ops:
                errors.append(
                    f"Policy for {res_name!r} references unsupported operation "
                    f"{action!r}. Supported: {sorted(valid_ops)}"
                )

        for f in rp.allowed_fields:
            if f not in valid_fields:
                errors.append(
                    f"Policy for {res_name!r} references unknown allowed_field {f!r}."
                )

        for f in rp.denied_fields:
            if f not in valid_fields:
                errors.append(
                    f"Policy for {res_name!r} references unknown denied_field {f!r}."
                )

        for rule in rp.row_rules:
            if rule.field not in valid_fields:
                errors.append(
                    f"Policy for {res_name!r} row-rule references unknown field {rule.field!r}."
                )

        if rp.max_rows <= 0:
            errors.append(
                f"Policy for {res_name!r} has invalid max_rows={rp.max_rows} "
                "(must be positive)."
            )

        tenant_key = res_def.tenant_key()
        from datafence.core.policy import ActionDecision
        has_allow_action = any(v == ActionDecision.ALLOW for v in rp.actions.values())
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
    """Validate tenant isolation row rule. Returns error string or None."""
    from datafence.core.resources import PredicateOperator

    tenant_rules = [r for r in rp.row_rules if r.field == tenant_key]

    if not tenant_rules:
        return (
            f"Policy for {res_name!r} allows access to a tenant-scoped resource "
            f"(tenant key: {tenant_key!r}) but has no row rule on the tenant key field. "
            "Add: RowRule(tenant_key, PredicateOperator.EQ, ':actor_tenant_id')"
        )

    for rule in tenant_rules:
        if rule.operator != PredicateOperator.EQ:
            return (
                f"Policy for {res_name!r}: tenant isolation row rule on "
                f"{tenant_key!r} must use operator EQ, got {rule.operator!r}."
            )
        if not _is_tenant_bound_value(rule.value):
            return (
                f"Policy for {res_name!r}: tenant isolation row rule on "
                f"{tenant_key!r} must use value ':actor_tenant_id', "
                f"got {rule.value!r}."
            )

    return None


# ---------------------------------------------------------------------------
# Runtime decision validator — boundary-owned, always executes
# ---------------------------------------------------------------------------


def _validate_decision(
    decision: EnginePolicyDecision,
    request: Request,
    registry: ResourceRegistry,
    frozen_policy: DataFencePolicy,
) -> None:
    """
    Independently validate an ALLOW ``PolicyDecision`` against the frozen
    registry and frozen policy.

    This is the final security gate before DataFenceBoundary signs any
    capability.  It executes unconditionally regardless of which
    ``PolicyEngine`` produced the decision.

    The ``frozen_policy`` is owned by the boundary and cannot be mutated
    or replaced by the engine.

    Invariants enforced
    -------------------
    1.  allowed_fields are all known in the registry.
    2.  allowed_fields contain no RESTRICTED fields.
    3.  allowed_fields ⊆ frozen policy ceiling (allowed minus denied/restricted).
    4.  enforced_filter fields are known and non-RESTRICTED.
    5.  Tenant-scoped resources have a mandatory EQ tenant predicate matching
        the authenticated principal's tenant_id (resolved value).
    6.  row_limit.value is positive AND ≤ policy max_rows.
    7.  decision_resource is present and matches request.intent.resource.
    8.  decision_operation is present and matches request operation.
    9.  decision.policy_name matches frozen_policy.name.
    10. decision.policy_version matches frozen_policy.version.
    11. allowed_fields is non-empty.
    """
    from datafence.core.registry import DataClassification
    from datafence.core.resources import PredicateOperator

    resource_name = request.intent.resource
    principal = request.actor
    op_str = request.intent.operation.value.lower()

    # ---- Resource definition ----
    res_def = registry.get(resource_name)
    if res_def is None:
        raise PolicyError(
            f"Boundary: resource {resource_name!r} disappeared from registry — "
            "registry integrity violation."
        )

    valid_fields: frozenset[str] = frozenset(res_def.field_names())
    restricted_fields: frozenset[str] = frozenset(
        n for n, fd in res_def.fields.items()
        if fd.classification == DataClassification.RESTRICTED
    )

    # ---- Invariant 11 ----
    if not decision.allowed_fields:
        raise PolicyError(
            "Boundary rejects decision: allowed_fields is empty in an ALLOW decision."
        )

    # ---- Invariant 6 (row_limit structural) ----
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

    # ---- Invariant 7 (operation supported) ----
    if op_str not in res_def.supported_operations:
        raise PolicyDeniedError(
            f"Boundary rejects decision: operation {op_str!r} not supported "
            f"on resource {resource_name!r}."
        )

    # ---- Invariant 1 (unknown fields) ----
    unknown_allowed = [f for f in decision.allowed_fields if f not in valid_fields]
    if unknown_allowed:
        raise PolicyError(
            f"Boundary rejects decision: allowed_fields contains fields not in "
            f"registry for {resource_name!r}: {unknown_allowed}."
        )

    # ---- Invariant 2 (RESTRICTED fields) ----
    restricted_allowed = [f for f in decision.allowed_fields if f in restricted_fields]
    if restricted_allowed:
        raise PolicyError(
            f"Boundary rejects decision: allowed_fields contains RESTRICTED fields "
            f"for {resource_name!r}: {restricted_allowed}."
        )

    # ---- Invariant 3 (policy field ceiling) ----
    rp = frozen_policy.resource_policy(resource_name)
    if rp is not None:
        effective_ceiling = frozenset(
            f for f in rp.allowed_fields
            if f not in rp.denied_fields and f not in restricted_fields
        )
        policy_unauthorized = [
            f for f in decision.allowed_fields if f not in effective_ceiling
        ]
        if policy_unauthorized:
            raise PolicyError(
                f"Boundary rejects decision: allowed_fields contains fields outside "
                f"the policy ceiling for {resource_name!r}: {policy_unauthorized}. "
                "A PolicyEngine must not authorize fields beyond the frozen policy."
            )

        # ---- Invariant 6 (row-limit ceiling) ----
        if _row_limit > rp.max_rows:
            raise PolicyError(
                f"Boundary rejects decision: row_limit.value={_row_limit} exceeds "
                f"policy max_rows={rp.max_rows} for {resource_name!r}."
            )

    # ---- Invariants 4 + 5 (enforced_filter fields and tenant predicate) ----
    tenant_key = res_def.tenant_key()
    tenant_predicate_found = False

    for pred in decision.enforced_filter.predicates:
        field_name = pred.field.name

        if field_name not in valid_fields:
            raise PolicyError(
                f"Boundary rejects decision: enforced_filter references unknown "
                f"field {field_name!r} on resource {resource_name!r}."
            )

        if field_name in restricted_fields:
            raise PolicyError(
                f"Boundary rejects decision: enforced_filter references RESTRICTED "
                f"field {field_name!r} on resource {resource_name!r}."
            )

        if tenant_key and field_name == tenant_key:
            if pred.operator != PredicateOperator.EQ:
                raise PolicyError(
                    f"Boundary rejects decision: enforced_filter tenant predicate on "
                    f"{tenant_key!r} uses operator {pred.operator!r} — must be EQ."
                )
            if pred.value != principal.tenant_id:
                raise PolicyError(
                    f"Boundary rejects decision: enforced_filter tenant predicate "
                    f"value {pred.value!r} does not match principal tenant_id "
                    f"{principal.tenant_id!r} — cross-tenant capability not permitted."
                )
            tenant_predicate_found = True

    if tenant_key and not tenant_predicate_found:
        raise PolicyError(
            f"Boundary rejects decision: resource {resource_name!r} is tenant-scoped "
            f"(tenant key: {tenant_key!r}) but enforced_filter has no tenant predicate."
        )

    # ---- Invariant 7 (decision_resource provenance) ----
    if not decision.decision_resource:
        raise PolicyError(
            "Boundary rejects decision: decision_resource is missing or empty. "
            "A PolicyEngine must set decision_resource on every ALLOW decision."
        )
    if decision.decision_resource != resource_name:
        raise PolicyError(
            f"Boundary rejects decision: decision_resource={decision.decision_resource!r} "
            f"does not match request resource {resource_name!r}."
        )

    # ---- Invariant 8 (decision_operation provenance) ----
    if not decision.decision_operation:
        raise PolicyError(
            "Boundary rejects decision: decision_operation is missing or empty. "
            "A PolicyEngine must set decision_operation on every ALLOW decision."
        )
    if decision.decision_operation != op_str:
        raise PolicyError(
            f"Boundary rejects decision: decision_operation={decision.decision_operation!r} "
            f"does not match request operation {op_str!r}."
        )

    # ---- Invariants 9 + 10 (policy name/version provenance) ----
    if not decision.policy_name or decision.policy_name == "unknown":
        raise PolicyError(
            "Boundary rejects decision: policy_name is missing or 'unknown'. "
            "A PolicyEngine must set policy_name on every ALLOW decision."
        )
    if decision.policy_name != frozen_policy.name:
        raise PolicyError(
            f"Boundary rejects decision: decision.policy_name={decision.policy_name!r} "
            f"does not match frozen policy name {frozen_policy.name!r}."
        )

    if not decision.policy_version or decision.policy_version == "unknown":
        raise PolicyError(
            "Boundary rejects decision: policy_version is missing or 'unknown'. "
            "A PolicyEngine must set policy_version on every ALLOW decision."
        )
    if decision.policy_version != frozen_policy.version:
        raise PolicyError(
            f"Boundary rejects decision: decision.policy_version={decision.policy_version!r} "
            f"does not match frozen policy version {frozen_policy.version!r}."
        )


# ---------------------------------------------------------------------------
# DataFenceBoundary
# ---------------------------------------------------------------------------


class DataFenceBoundary:
    """Deterministic authorization and capability-issuance boundary.

    Always construct via :meth:`create` — direct instantiation is blocked.

    The boundary owns a deep-frozen ``DataFencePolicy`` snapshot that is
    used to validate every ``PolicyDecision`` before signing.  No custom
    ``PolicyEngine`` can bypass field-ceiling, row-limit, or provenance
    invariants.

    Parameters (via ``create``)
    ---------------------------
    policy_engine        : Object implementing the PolicyEngine protocol.
                           Must expose ``._policy`` or supply
                           ``authoritative_policy`` explicitly.
    registry             : Populated ResourceRegistry; frozen at create() time.
    signing_key          : HMAC key — minimum 32 bytes.
    authoritative_policy : Explicit ``DataFencePolicy`` for custom engines
                           that do not expose ``._policy``.  Must match the
                           same registry.  Required when the engine does not
                           expose ``._policy``.
    capability_ttl_seconds : How long issued capabilities are valid (default 300 s).
    capability_audience  : Audience tag embedded in every capability.
    """

    policy_engine: PolicyEngine
    _registry: ResourceRegistry
    _frozen_policy: DataFencePolicy   # authoritative — boundary-owned, immutable
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
        authoritative_policy: DataFencePolicy | None = None,
    ) -> "DataFenceBoundary":
        """Create and validate a boundary.

        Raises:
            ValueError: For invalid primitive arguments or missing policy.
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

        # ------------------------------------------------------------------
        # Resolve the authoritative policy (boundary-owned)
        # ------------------------------------------------------------------
        # Priority: explicit authoritative_policy argument > engine._policy
        raw_policy: DataFencePolicy | None = authoritative_policy
        if raw_policy is None:
            candidate = getattr(policy_engine, "_policy", None)
            if isinstance(candidate, DataFencePolicy):
                raw_policy = candidate

        if raw_policy is None:
            raise ValueError(
                "DataFenceBoundary.create() requires an authoritative DataFencePolicy. "
                "Either use DataFencePolicyEngine (which exposes ._policy automatically) "
                "or pass authoritative_policy=<your_policy> explicitly for custom engines."
            )

        # ------------------------------------------------------------------
        # Compile-time validation
        # ------------------------------------------------------------------
        _validate_policy_against_registry(raw_policy, registry)

        # ------------------------------------------------------------------
        # Freeze everything
        # ------------------------------------------------------------------
        registry.freeze()
        frozen_policy = _deep_freeze_policy(raw_policy)

        # Push the frozen snapshot back into built-in engines so they also
        # evaluate against the frozen state.
        if isinstance(policy_engine, DataFencePolicyEngine):
            object.__setattr__(policy_engine, "_policy", frozen_policy)

        boundary = cls(_SENTINEL)
        boundary.policy_engine = policy_engine
        boundary._registry = registry
        boundary._frozen_policy = frozen_policy          # boundary-owned, immutable
        boundary._signing_key = signing_key
        boundary._capability_ttl_seconds = capability_ttl_seconds
        boundary._capability_audience = capability_audience
        return boundary

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def authorize(self, principal: Principal, intent: Intent) -> AuthorizedExecution:
        """Authorize an intent and return a signed authorization capability."""
        request = Request.create(principal, intent)

        # 1. Registry validation
        try:
            self._registry.validate_intent(intent)
        except ValueError as exc:
            raise PolicyDeniedError(str(exc)) from exc

        # 2. Policy evaluation
        try:
            decision = self.policy_engine.evaluate(principal=principal, intent=intent)
        except Exception as exc:
            raise PolicyError("Policy evaluation failed unexpectedly") from exc

        # 3. Structural validation
        if not isinstance(decision, EnginePolicyDecision):
            raise PolicyError(
                f"Policy engine returned unexpected type: {type(decision).__name__!r}"
            )
        if not hasattr(decision, "effect") or decision.effect not in (
            PolicyEffect.ALLOW,
            PolicyEffect.DENY,
        ):
            raise PolicyError("Policy decision has invalid or missing effect — failing closed")

        # 4. Deny path
        if decision.effect == PolicyEffect.DENY:
            raise PolicyDeniedError("; ".join(decision.reasons))

        # 5. Independent boundary-level validation — ALWAYS runs, uses boundary-owned policy
        _validate_decision(decision, request, self._registry, self._frozen_policy)

        # 6. Build and sign capability
        return self._build_capability(request, decision)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_capability(
        self, request: Request, decision: EnginePolicyDecision
    ) -> AuthorizedExecution:
        selected_fields = list(decision.allowed_fields)
        if request.intent.fields:
            selected_fields = [f for f in request.intent.fields if f in selected_fields]
        if not selected_fields:
            raise PolicyDeniedError("No authorized fields available for this request")

        resolved_filter = decision.enforced_filter.merge(
            Filter.from_dict(request.intent.filters)
        ).resolve(request.actor)

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

    @property
    def frozen_policy(self) -> DataFencePolicy:
        """Return the boundary-owned frozen policy snapshot."""
        return self._frozen_policy


# ---------------------------------------------------------------------------
# Policy deep-freeze helper
# ---------------------------------------------------------------------------


def _deep_freeze_policy(policy: DataFencePolicy) -> DataFencePolicy:
    """Return a deep-copied, immutable snapshot of *policy*."""
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
