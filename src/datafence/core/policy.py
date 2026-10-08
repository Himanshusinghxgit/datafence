"""
DataFence enhanced policy model.

Design goals:
  - Policy INJECTS mandatory constraints; it does NOT require the LLM to supply them.
  - One YAML policy file can define the complete authorization model for a resource.
  - PolicyDecision carries all information needed to build AuthorizedExecution.
  - Principal attributes can be referenced in row-filters (:actor_tenant_id, etc.).
  - Filter authorization: only explicitly authorised fields may be used as filters.
  - DataClassification: RESTRICTED fields are automatically denied by the policy engine.
  - v1 is READ-only at the adapter layer; the Operation enum still supports future writes
    but YAML policies should only expose "read" in the initial release.

Policy evaluation flow::

    Principal + Intent
          ↓
      PolicyEngine.evaluate()
          ↓
      PolicyDecision (ALLOW | DENY)
          ↓  (if ALLOW)
      AuthorizedExecution (via boundary)

YAML schema understood by YAMLPolicyLoader::

    resources:
      transactions:
        actions:
          read: allow
        fields:
          allow:
            - id
            - merchant
            - amount
          deny:
            - card_number
          filterable:           # NEW: explicit filter authorization
            - merchant
            - tenant_id
        rows:
          - field: tenant_id
            operator: equals
            value: ":actor_tenant_id"
        limits:
          rows: 100
        obligations:
          audit: true
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from datafence.core.resources import (
    FieldRef,
    Filter,
    Predicate,
    PredicateOperator,
    Projection,
    RowLimit,
    validate_identifier,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ActionDecision(Enum):
    """Whether an action is allowed or denied."""

    ALLOW = "allow"
    DENY = "deny"


class PolicyEffect(Enum):
    """Final policy evaluation effect."""

    ALLOW = "allow"
    DENY = "deny"


# ---------------------------------------------------------------------------
# Policy data model
# ---------------------------------------------------------------------------


@dataclass
class RowRule:
    """
    A row-level filter rule injected by policy.

    field:    column to filter on
    operator: comparison operator (default EQ)
    value:    literal or actor-attribute reference (e.g. ":actor_tenant_id")
    """

    field: str
    operator: PredicateOperator = PredicateOperator.EQ
    value: Any = None

    def to_predicate(self) -> Predicate:
        return Predicate(
            field=FieldRef(name=self.field),
            operator=self.operator,
            value=self.value,
        )


@dataclass
class ResourcePolicy:
    """
    Policy rules for a single resource.

    filterable_fields controls which fields the agent may use as filters.
    If empty, the policy inherits allowed_fields as the filterable set.
    Fields classified RESTRICTED in the registry are always denied regardless
    of the filterable_fields list.
    """

    resource: str

    # Operation-level rules  {operation_name: ActionDecision}
    actions: dict[str, ActionDecision] = field(default_factory=dict)

    # Field-level rules
    allowed_fields: list[str] = field(default_factory=list)
    denied_fields: list[str] = field(default_factory=list)

    # Filter authorization (Phase 8): fields the agent may use as intent filters.
    # Empty means: inherit allowed_fields (minus denied_fields).
    filterable_fields: list[str] = field(default_factory=list)

    # Row-level rules — policy INJECTS these, LLM cannot override
    row_rules: list[RowRule] = field(default_factory=list)

    # Limits
    max_rows: int = 100

    # Obligations — carried forward into AuthorizedExecution metadata
    obligations: dict[str, Any] = field(default_factory=dict)

    def action_decision(self, action: str) -> ActionDecision:
        """Return the decision for *action*.

        Precedence: explicit deny > explicit allow > implicit deny.
        """
        decision = self.actions.get(action.lower())
        if decision is None:
            return ActionDecision.DENY  # implicit deny
        return decision

    def enforced_filter(self) -> Filter:
        """Return a Filter built from the row_rules."""
        return Filter(predicates=tuple(r.to_predicate() for r in self.row_rules))

    def projection(self, requested: list[str] | None = None) -> Projection:
        """Return the Projection for a request.

        If *requested* is provided, intersect with allowed_fields and ensure
        no denied field leaks through.
        """
        if requested:
            safe = [
                f for f in requested if f in self.allowed_fields and f not in self.denied_fields
            ]
        else:
            safe = [f for f in self.allowed_fields if f not in self.denied_fields]
        return Projection.from_strings(safe)

    def effective_filterable_fields(self) -> frozenset[str]:
        """Return the effective set of fields the agent may filter on."""
        if self.filterable_fields:
            # Use explicit list, minus denied fields
            return frozenset(f for f in self.filterable_fields if f not in self.denied_fields)
        # Fall back to allowed_fields minus denied_fields
        return frozenset(f for f in self.allowed_fields if f not in self.denied_fields)


@dataclass
class DataFencePolicy:
    """A complete policy document covering one or more resources."""

    name: str
    version: str
    resources: dict[str, ResourcePolicy] = field(default_factory=dict)

    def resource_policy(self, resource: str) -> ResourcePolicy | None:
        return self.resources.get(resource)


# ---------------------------------------------------------------------------
# PolicyDecision — carries the full authorization decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyDecision:
    """
    Result of evaluating a policy for one request.

    obligations is carried into AuthorizedExecution as audit metadata.

    Provenance fields (resource, operation) allow the boundary to verify
    that the decision was produced for the exact request it is being
    applied to.  They are optional (default to empty string / None) for
    backward-compatibility with custom PolicyEngine implementations, but
    the built-in DataFencePolicyEngine always populates them.
    """

    effect: PolicyEffect
    reasons: tuple[str, ...] = ()
    policy_name: str = "unknown"
    policy_version: str = "unknown"

    # Provenance — which resource/operation this decision was produced for.
    # Empty string means "not provided by this engine" (treated leniently).
    decision_resource: str = ""
    decision_operation: str = ""

    # Populated only for ALLOW
    allowed_fields: tuple[str, ...] = ()
    enforced_filter: Filter = field(default_factory=Filter.empty)
    row_limit: RowLimit = field(default_factory=RowLimit.default)
    matched_rules: tuple[str, ...] = ()
    obligations: dict[str, Any] = field(default_factory=dict)

    @property
    def is_allow(self) -> bool:
        return self.effect == PolicyEffect.ALLOW

    @property
    def is_deny(self) -> bool:
        return self.effect == PolicyEffect.DENY

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def deny(
        cls, reasons: list[str], policy_name: str = "unknown", policy_version: str = "unknown"
    ) -> PolicyDecision:
        return cls(
            effect=PolicyEffect.DENY,
            reasons=tuple(reasons),
            policy_name=policy_name,
            policy_version=policy_version,
        )

    @classmethod
    def allow(
        cls,
        allowed_fields: list[str],
        enforced_filter: Filter,
        row_limit: RowLimit,
        policy_name: str = "unknown",
        policy_version: str = "unknown",
        matched_rules: list[str] | None = None,
        obligations: dict[str, Any] | None = None,
        decision_resource: str = "",
        decision_operation: str = "",
    ) -> PolicyDecision:
        return cls(
            effect=PolicyEffect.ALLOW,
            policy_name=policy_name,
            policy_version=policy_version,
            decision_resource=decision_resource,
            decision_operation=decision_operation,
            allowed_fields=tuple(allowed_fields),
            enforced_filter=enforced_filter,
            row_limit=row_limit,
            matched_rules=tuple(matched_rules or []),
            obligations=obligations or {},
        )


# ---------------------------------------------------------------------------
# PolicyEngine protocol + concrete implementation
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Protocol / base for policy engines."""

    def evaluate(self, principal: Any, intent: Any) -> PolicyDecision:
        raise NotImplementedError

    @property
    def policy_name(self) -> str:
        return "unknown"

    @property
    def policy_version(self) -> str:
        return "unknown"


class DataFencePolicyEngine(PolicyEngine):
    """
    Full policy engine for DataFence.

    Phases implemented:
    - Phase 8: Filter authorization — only explicitly filterable fields
      (or allowed_fields if filterable_fields not set) may be used in intent
      filters.  RESTRICTED fields are always denied as filters.
    - Phase 9: DataClassification — RESTRICTED fields are automatically denied
      in allowed_fields even if the policy lists them explicitly.
    """

    def __init__(self, policy: DataFencePolicy, registry: Any) -> None:
        if registry is None:
            raise ValueError("DataFencePolicyEngine requires a ResourceRegistry")
        self._policy = policy
        self._registry = registry

    @property
    def policy_name(self) -> str:
        return self._policy.name

    @property
    def policy_version(self) -> str:
        return self._policy.version

    @property
    def registry(self) -> Any:
        """The registry used by this engine."""
        return self._registry

    def evaluate(self, principal: Any, intent: Any) -> PolicyDecision:
        """Evaluate one untrusted intent for one trusted principal."""
        from datafence.core.registry import DataClassification

        resource = intent.resource
        operation = intent.operation
        requested_fields: list[str] = intent.fields or []
        requested_filters: dict[str, Any] = dict(intent.filters) if intent.filters else {}

        # Normalise operation to lowercase string
        if hasattr(operation, "value"):
            action = operation.value.lower()
        else:
            action = str(operation).lower()

        rp = self._policy.resource_policy(resource)
        if rp is None:
            return PolicyDecision.deny(
                reasons=[f"No policy defined for resource: {resource!r}"],
                policy_name=self._policy.name,
                policy_version=self._policy.version,
            )

        # 0. Registry validation
        if not self._registry.exists(resource):
            return PolicyDecision.deny(
                reasons=[f"Resource {resource!r} is not registered"],
                policy_name=self._policy.name,
                policy_version=self._policy.version,
            )

        res_def = self._registry.get(resource)

        if requested_fields:
            try:
                self._registry.validate_fields(resource, requested_fields)
            except ValueError as exc:
                return PolicyDecision.deny(
                    reasons=[str(exc)],
                    policy_name=self._policy.name,
                    policy_version=self._policy.version,
                )

        # 1. Action check
        action_decision = rp.action_decision(action)
        if action_decision == ActionDecision.DENY:
            return PolicyDecision.deny(
                reasons=[f"Operation {action!r} is denied on resource {resource!r}"],
                policy_name=self._policy.name,
                policy_version=self._policy.version,
            )

        # 2. Field check — deny if any requested field is in denied_fields
        if requested_fields:
            denied = [f for f in requested_fields if f in rp.denied_fields]
            if denied:
                return PolicyDecision.deny(
                    reasons=[f"Requested fields are denied: {', '.join(denied)}"],
                    policy_name=self._policy.name,
                    policy_version=self._policy.version,
                )
            unauthorized = [f for f in requested_fields if f not in rp.allowed_fields]
            if unauthorized:
                return PolicyDecision.deny(
                    reasons=[f"Fields not authorized: {', '.join(unauthorized)}"],
                    policy_name=self._policy.name,
                    policy_version=self._policy.version,
                )

        # Phase 9: Automatically strip RESTRICTED fields from allowed_fields
        # even if the policy explicitly lists them.
        effective_allowed = list(rp.allowed_fields)
        if res_def is not None:
            effective_allowed = [
                f
                for f in effective_allowed
                if res_def.fields.get(f) is None
                or res_def.fields[f].classification != DataClassification.RESTRICTED
            ]

        # 3. Build projection (using classification-filtered allowed set)
        if requested_fields:
            safe = [
                f for f in requested_fields if f in effective_allowed and f not in rp.denied_fields
            ]
        else:
            safe = [f for f in effective_allowed if f not in rp.denied_fields]

        if not safe:
            return PolicyDecision.deny(
                reasons=["No authorized fields available for this request"],
                policy_name=self._policy.name,
                policy_version=self._policy.version,
            )

        projection = Projection.from_strings(safe)

        # Phase 8: Filter authorization
        # Agent-supplied intent filters must only use filterable fields.
        if requested_filters:
            filterable = rp.effective_filterable_fields()
            for filter_field in requested_filters:
                if filter_field not in filterable:
                    return PolicyDecision.deny(
                        reasons=[
                            f"Field {filter_field!r} is not authorized for filtering on "
                            f"resource {resource!r}. Filterable fields: "
                            f"{sorted(filterable) or 'none'}"
                        ],
                        policy_name=self._policy.name,
                        policy_version=self._policy.version,
                    )
                # Double-check RESTRICTED fields are never filterable
                if res_def is not None:
                    field_def = res_def.fields.get(filter_field)
                    if (
                        field_def is not None
                        and field_def.classification == DataClassification.RESTRICTED
                    ):
                        return PolicyDecision.deny(
                            reasons=[
                                f"Filtering on RESTRICTED field {filter_field!r} is not permitted"
                            ],
                            policy_name=self._policy.name,
                            policy_version=self._policy.version,
                        )

        # 4. Resolve enforced filter using principal attributes
        enforced_filter = rp.enforced_filter().resolve(principal)

        matched = [
            f"{resource}.action.{action}",
            f"{resource}.fields.allowed",
        ]
        if enforced_filter:
            matched.append(f"{resource}.rows.enforced")

        return PolicyDecision.allow(
            allowed_fields=projection.field_names(),
            enforced_filter=enforced_filter,
            row_limit=RowLimit(value=rp.max_rows),
            policy_name=self._policy.name,
            policy_version=self._policy.version,
            matched_rules=matched,
            obligations=rp.obligations,
            decision_resource=resource,
            decision_operation=action,
        )


# ---------------------------------------------------------------------------
# YAML policy loader
# ---------------------------------------------------------------------------

_OP_MAP: dict[str, PredicateOperator] = {
    "equals": PredicateOperator.EQ,
    "eq": PredicateOperator.EQ,
    "=": PredicateOperator.EQ,
    "neq": PredicateOperator.NEQ,
    "!=": PredicateOperator.NEQ,
    "lt": PredicateOperator.LT,
    "<": PredicateOperator.LT,
    "lte": PredicateOperator.LTE,
    "<=": PredicateOperator.LTE,
    "gt": PredicateOperator.GT,
    ">": PredicateOperator.GT,
    "gte": PredicateOperator.GTE,
    ">=": PredicateOperator.GTE,
    "in": PredicateOperator.IN,
    "not_in": PredicateOperator.NOT_IN,
    "is_null": PredicateOperator.IS_NULL,
    "is_not_null": PredicateOperator.IS_NOT_NULL,
}


class YAMLPolicyLoader:
    """
    Load a DataFencePolicy from a YAML file or dict.

    Supports the ``filterable`` field key for explicit filter authorization.
    """

    @classmethod
    def load(cls, path: str | Path) -> DataFencePolicy:
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required for YAML policy loading: pip install pyyaml"
            ) from exc

        with open(path) as fh:
            data = yaml.safe_load(fh)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> DataFencePolicy:
        name = data.get("name", "unnamed")
        version = str(data.get("version", "0.0"))
        resources: dict[str, ResourcePolicy] = {}

        for res_name, res_data in (data.get("resources") or {}).items():
            validate_identifier(res_name, context="resource name")
            resources[res_name] = cls._parse_resource(res_name, res_data or {})

        return DataFencePolicy(name=name, version=version, resources=resources)

    @classmethod
    def _parse_resource(cls, name: str, data: dict) -> ResourcePolicy:
        # Actions
        actions: dict[str, ActionDecision] = {}
        for action_name, decision_str in (data.get("actions") or {}).items():
            decision = ActionDecision(decision_str.lower())
            actions[action_name.lower()] = decision

        # Fields
        fields_data = data.get("fields") or {}
        allowed_fields: list[str] = fields_data.get("allow") or []
        denied_fields: list[str] = fields_data.get("deny") or []
        filterable_fields: list[str] = fields_data.get("filterable") or []

        # Validate all field identifiers
        for f in allowed_fields + denied_fields + filterable_fields:
            validate_identifier(f, context="field name")

        # Row rules
        row_rules: list[RowRule] = []
        for rule in data.get("rows") or []:
            op_str = rule.get("operator", "equals").lower()
            try:
                op = _OP_MAP[op_str]
            except KeyError as exc:
                raise ValueError(
                    f"Unknown row-filter operator {op_str!r} for resource {name!r}"
                ) from exc
            row_rules.append(
                RowRule(
                    field=rule["field"],
                    operator=op,
                    value=rule["value"],
                )
            )

        # Limits
        limits_data = data.get("limits") or {}
        max_rows = int(limits_data.get("rows", 100))

        # Obligations
        obligations = data.get("obligations") or {}

        return ResourcePolicy(
            resource=name,
            actions=actions,
            allowed_fields=allowed_fields,
            denied_fields=denied_fields,
            filterable_fields=filterable_fields,
            row_rules=row_rules,
            max_rows=max_rows,
            obligations=obligations,
        )
