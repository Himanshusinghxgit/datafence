"""
DataFence enhanced policy model (Phase 3).

This module replaces both:
  - the legacy policy/models.py (Pydantic-based Policy / ResourcePolicy)
  - core/policy_engine.py (SimplePolicyEngine)

Design goals (from the architectural analysis):
  - Policy INJECTS mandatory constraints; it does NOT require the LLM to supply them.
  - One YAML policy file can define the complete authorization model for a resource.
  - PolicyDecision carries all information needed to build AuthorizedExecution.
  - Principal attributes can be referenced in row-filters (:actor_tenant_id, etc.).

Policy evaluation flow:

    Principal + Intent
          ↓
      PolicyEngine.evaluate()
          ↓
      PolicyDecision (ALLOW | DENY)
          ↓  (if ALLOW)
      AuthorizedExecution (via boundary)

The YAML schema understood by YAMLPolicyLoader is:

    resources:
      transactions:
        actions:
          read: allow
          insert: deny
          update: deny
          delete: deny
        fields:
          allow:
            - id
            - merchant
            - amount
            - timestamp
          deny:
            - card_number
            - account_number
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

    This is the richer replacement for the old SimplePolicyEngine ResourcePolicy.
    """

    resource: str

    # Operation-level rules  {operation_name: ActionDecision}
    actions: dict[str, ActionDecision] = field(default_factory=dict)

    # Field-level rules
    allowed_fields: list[str] = field(default_factory=list)
    denied_fields: list[str] = field(default_factory=list)

    # Row-level rules — policy INJECTS these, LLM cannot override
    row_rules: list[RowRule] = field(default_factory=list)

    # Limits
    max_rows: int = 100

    # Obligations
    obligations: dict[str, Any] = field(default_factory=dict)

    def action_decision(self, action: str) -> ActionDecision:
        """
        Return the decision for *action*.

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
        """
        Return the Projection for a request.

        If *requested* is provided, intersect with allowed_fields and ensure
        no denied field leaks through.  If *requested* is None, return all
        allowed fields.
        """
        if requested:
            safe = [
                f for f in requested if f in self.allowed_fields and f not in self.denied_fields
            ]
        else:
            safe = [f for f in self.allowed_fields if f not in self.denied_fields]
        return Projection.from_strings(safe)


@dataclass
class DataFencePolicy:
    """
    A complete policy document covering one or more resources.
    """

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

    effect:          ALLOW or DENY
    reasons:         human-readable explanation (always present for DENY)
    policy_name:     name of the policy that produced this decision
    policy_version:  version string for audit provenance
    allowed_fields:  (ALLOW only) fields the principal may access
    enforced_filter: (ALLOW only) Filter the connector MUST apply
    row_limit:       (ALLOW only) maximum rows to return
    matched_rules:   list of rule identifiers that fired
    obligations:     post-execution requirements (e.g. {"audit": True})
    """

    effect: PolicyEffect
    reasons: tuple[str, ...] = ()
    policy_name: str = "unknown"
    policy_version: str = "unknown"

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
    ) -> PolicyDecision:
        return cls(
            effect=PolicyEffect.ALLOW,
            policy_name=policy_name,
            policy_version=policy_version,
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
    """
    Protocol / base for policy engines.

    Subclass this or use DataFencePolicyEngine.
    """

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
    Full policy engine for DataFence (Phase 3).

    Replaces SimplePolicyEngine with:
    - Richer action rules (explicit allow/deny, implicit deny)
    - Typed row filters (injected by policy, not required from LLM)
    - Field allow/deny lists
    - Obligations support
    - Named policy versioning

    Usage::

        from datafence.core.policy import DataFencePolicyEngine, DataFencePolicy
        from datafence.core.policy import YAMLPolicyLoader
        from datafence.core.types import Intent, Operation
        from datafence.core.registry import create_banking_registry

        policy = YAMLPolicyLoader.load("policies/banking.yaml")
        engine = DataFencePolicyEngine(policy, create_banking_registry())
        decision = engine.evaluate(
            principal,
            Intent("transactions", Operation.READ, ["id", "merchant", "amount"]),
        )
    """

    def __init__(self, policy: DataFencePolicy, registry: Any = None) -> None:
        self._policy = policy
        self._registry = registry  # Registry is supplied by the boundary.

    @property
    def policy_name(self) -> str:
        return self._policy.name

    @property
    def policy_version(self) -> str:
        return self._policy.version

    @property
    def registry(self) -> Any:
        """The immutable-at-construction schema registry used by this engine."""
        return self._registry

    def evaluate(
        self,
        principal: Any,
        intent: Any,
    ) -> PolicyDecision:
        """
        Evaluate one untrusted intent for one trusted principal.

        If a ResourceRegistry was provided at construction, validates fields
        against the registry schema before checking policy rules.
        """
        resource = intent.resource
        operation = intent.operation
        requested_fields = intent.fields or []

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

        # 0. Registry validation (if registry provided)
        if self._registry is not None:
            if not self._registry.exists(resource):
                return PolicyDecision.deny(
                    reasons=[f"Resource {resource!r} is not registered"],
                    policy_name=self._policy.name,
                    policy_version=self._policy.version,
                )
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
                reasons=[f"Action {action!r} is denied on resource {resource!r}"],
                policy_name=self._policy.name,
                policy_version=self._policy.version,
            )

        # 2. Field check (if specific fields requested)
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

        # 3. Build projection
        projection = rp.projection(requested_fields)
        if not projection:
            return PolicyDecision.deny(
                reasons=["No authorized fields available for this request"],
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

    Expected YAML structure::

        name: banking-v1
        version: "1.0"
        resources:
          transactions:
            actions:
              read: allow
              insert: deny
              update: deny
              delete: deny
            fields:
              allow: [id, merchant, amount, timestamp]
              deny: [card_number, account_number]
            rows:
              - field: tenant_id
                operator: equals
                value: ":actor_tenant_id"
            limits:
              rows: 100
            obligations:
              audit: true
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

        # Validate all field identifiers
        for f in allowed_fields + denied_fields:
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
            row_rules=row_rules,
            max_rows=max_rows,
            obligations=obligations,
        )


def create_banking_policy() -> DataFencePolicyEngine:
    """
    Create the banking demo policy using the Phase-3 model.

    This is the v2 replacement for create_banking_demo_policy() in policy_engine.py.

    The banking registry is mandatory for the returned policy engine.
    """
    from datafence.core.policy import (
        ActionDecision,
        DataFencePolicy,
        DataFencePolicyEngine,
        ResourcePolicy,
        RowRule,
    )
    from datafence.core.resources import PredicateOperator

    policy = DataFencePolicy(
        name="banking-demo-v1",
        version="1.0",
        resources={
            "transactions": ResourcePolicy(
                resource="transactions",
                actions={
                    "read": ActionDecision.ALLOW,
                    "insert": ActionDecision.DENY,
                    "update": ActionDecision.DENY,
                    "delete": ActionDecision.DENY,
                },
                allowed_fields=["id", "merchant", "amount", "timestamp"],
                denied_fields=["card_number", "account_number"],
                row_rules=[
                    RowRule(
                        field="tenant_id",
                        operator=PredicateOperator.EQ,
                        value=":actor_tenant_id",
                    )
                ],
                max_rows=100,
                obligations={"audit": True},
            ),
            "customers": ResourcePolicy(
                resource="customers",
                actions={
                    "read": ActionDecision.ALLOW,
                    "insert": ActionDecision.DENY,
                    "update": ActionDecision.DENY,
                    "delete": ActionDecision.DENY,
                },
                allowed_fields=["id", "name", "email"],
                denied_fields=["ssn", "account_number"],
                row_rules=[
                    RowRule(
                        field="tenant_id",
                        operator=PredicateOperator.EQ,
                        value=":actor_tenant_id",
                    )
                ],
                max_rows=100,
            ),
            "accounts": ResourcePolicy(
                resource="accounts",
                actions={
                    "read": ActionDecision.DENY,
                    "insert": ActionDecision.DENY,
                    "update": ActionDecision.DENY,
                    "delete": ActionDecision.DENY,
                },
                allowed_fields=[],
                denied_fields=["account_number", "balance"],
                max_rows=0,
            ),
        },
    )
    from datafence.core.registry import create_banking_registry

    registry = create_banking_registry()
    return DataFencePolicyEngine(policy, registry=registry)
