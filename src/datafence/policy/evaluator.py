"""
Policy evaluation engine.

Deterministic evaluation of requests against policies.
"""

import re
from typing import Any

from datafence.core.context import RequestContext
from datafence.core.decision import Decision, DecisionStatus, PolicyCheck
from datafence.core.request import ExecutionRequest, Operation
from datafence.errors import PolicyError
from datafence.policy.models import Policy, ResourcePolicy


class PolicyEvaluator:
    """
    Evaluates requests against policies.

    All evaluation must be deterministic and explainable.
    """

    def __init__(self, policy: Policy):
        """
        Initialize evaluator with a policy.

        Args:
            policy: Policy to enforce
        """
        self.policy = policy

    def evaluate(self, request: ExecutionRequest, context: RequestContext) -> Decision:
        """
        Evaluate a request against the policy.

        Args:
            request: Execution request
            context: Request context

        Returns:
            Decision (ALLOW, DENY, etc.)
        """
        checks: list[PolicyCheck] = []

        # 1. Check resource exists in policy
        resource_policy = self.policy.get_resource_policy(request.resource)
        if resource_policy is None:
            return Decision(
                status=DecisionStatus.DENY,
                reasons=[f"resource '{request.resource}' not found in policy"],
                policy_name=self.policy.name,
                policy_version=self.policy.version,
                checks=checks,
            )

        checks.append(
            PolicyCheck(name="resource_exists", passed=True, reason="Resource found in policy")
        )

        # 2. Check operation
        op_check = self._check_operation(request.operation, resource_policy)
        checks.append(op_check)
        if not op_check.passed:
            return Decision(
                status=DecisionStatus.DENY,
                reasons=[op_check.reason or "Operation denied"],
                policy_name=self.policy.name,
                policy_version=self.policy.version,
                checks=checks,
            )

        # 3. Check fields
        if request.fields:
            field_check = self._check_fields(request.fields, resource_policy)
            checks.append(field_check)
            if not field_check.passed:
                return Decision(
                    status=DecisionStatus.DENY,
                    reasons=[field_check.reason or "Field access denied"],
                    policy_name=self.policy.name,
                    policy_version=self.policy.version,
                    checks=checks,
                )

        # 4. Check row filters
        row_check = self._check_row_filters(request, context, resource_policy)
        checks.append(row_check)
        if not row_check.passed:
            return Decision(
                status=DecisionStatus.DENY,
                reasons=[row_check.reason or "Row filter validation failed"],
                policy_name=self.policy.name,
                policy_version=self.policy.version,
                checks=checks,
            )

        # 5. Check limits
        limit_check = self._check_limits(request, resource_policy)
        checks.append(limit_check)
        if not limit_check.passed:
            return Decision(
                status=DecisionStatus.DENY,
                reasons=[limit_check.reason or "Limit exceeded"],
                policy_name=self.policy.name,
                policy_version=self.policy.version,
                checks=checks,
            )

        # All checks passed
        return Decision(
            status=DecisionStatus.ALLOW,
            reasons=[],
            policy_name=self.policy.name,
            policy_version=self.policy.version,
            checks=checks,
        )

    def _check_operation(
        self, operation: Operation, resource_policy: ResourcePolicy
    ) -> PolicyCheck:
        """Check if operation is allowed."""
        ops = resource_policy.operations

        # Get operation value (handle both enum and string)
        op_value = operation.value if isinstance(operation, Operation) else operation

        # Explicit deny takes precedence
        if ops.deny and operation in ops.deny:
            return PolicyCheck(
                name="operation",
                passed=False,
                reason=f"operation '{op_value}' is explicitly denied",
            )

        # Check allow list
        if ops.allow:
            if operation in ops.allow:
                return PolicyCheck(
                    name="operation",
                    passed=True,
                    reason=f"operation '{op_value}' is allowed",
                )
            else:
                return PolicyCheck(
                    name="operation",
                    passed=False,
                    reason=f"operation '{op_value}' is not in allow list",
                )

        # No allow list means everything is allowed (except denies)
        return PolicyCheck(
            name="operation", passed=True, reason="Operation allowed (no restrictions)"
        )

    def _check_fields(self, fields: list[str], resource_policy: ResourcePolicy) -> PolicyCheck:
        """Check if requested fields are allowed."""
        field_policy = resource_policy.fields

        # Check deny list first
        if field_policy.deny:
            denied_fields = set(fields) & set(field_policy.deny)
            if denied_fields:
                return PolicyCheck(
                    name="fields",
                    passed=False,
                    reason=f"fields {denied_fields} are explicitly denied",
                )

        # Check allow list
        if field_policy.allow:
            disallowed_fields = set(fields) - set(field_policy.allow)
            if disallowed_fields:
                return PolicyCheck(
                    name="fields",
                    passed=False,
                    reason=f"fields {disallowed_fields} are not in allow list",
                )

        return PolicyCheck(name="fields", passed=True, reason="All fields allowed")

    def _check_row_filters(
        self, request: ExecutionRequest, context: RequestContext, resource_policy: ResourcePolicy
    ) -> PolicyCheck:
        """
        Check row-level filters.

        Row filters enforce tenant isolation and data scoping.
        """
        policy_filters = resource_policy.row_filters

        if not policy_filters:
            return PolicyCheck(name="row_filters", passed=True, reason="No row filters required")

        # Validate required filters are present in request
        for filter_key, template in policy_filters.items():
            # Resolve template variables
            resolved_value = self._resolve_template(template, context)

            # Check if filter is present in request
            if filter_key not in request.filters:
                return PolicyCheck(
                    name="row_filters",
                    passed=False,
                    reason=f"required filter '{filter_key}' missing from request",
                )

            # Check if filter value matches policy requirement
            request_value = request.filters[filter_key]
            if str(request_value) != str(resolved_value):
                return PolicyCheck(
                    name="row_filters",
                    passed=False,
                    reason=f"filter '{filter_key}' value mismatch (expected: {resolved_value}, got: {request_value})",
                )

        return PolicyCheck(name="row_filters", passed=True, reason="Row filters validated")

    def _check_limits(
        self, request: ExecutionRequest, resource_policy: ResourcePolicy
    ) -> PolicyCheck:
        """Check query limits."""
        limits = resource_policy.limits

        if limits.max_rows and request.limit:
            if request.limit > limits.max_rows:
                return PolicyCheck(
                    name="limits",
                    passed=False,
                    reason=f"requested limit {request.limit} exceeds max_rows {limits.max_rows}",
                )

        return PolicyCheck(name="limits", passed=True, reason="Limits validated")

    def _resolve_template(self, template: str, context: RequestContext) -> Any:
        """
        Resolve template variables in policy.

        Supports: {{ actor.customer_id }}, {{ actor.region }}, {{ tenant_id }}
        """
        # Simple template resolution
        template = template.strip()

        # Extract template variable
        match = re.match(r"\{\{\s*(.+?)\s*\}\}", template)
        if not match:
            return template

        var_path = match.group(1)
        parts = var_path.split(".")

        if parts[0] == "actor":
            if len(parts) == 1:
                return str(context.actor)
            elif len(parts) == 2:
                attr_name = parts[1]
                if attr_name == "id":
                    return context.actor.id
                elif attr_name == "type":
                    return context.actor.type.value
                else:
                    return context.actor.attributes.get(attr_name)

        elif parts[0] == "tenant_id":
            return context.tenant_id

        raise PolicyError(f"Unknown template variable: {var_path}")

    def get_allowed_fields(self, resource: str) -> list[str] | None:
        """
        Get list of allowed fields for a resource.

        Returns None if all fields are allowed.
        """
        resource_policy = self.policy.get_resource_policy(resource)
        if resource_policy is None:
            return None

        if resource_policy.fields.allow:
            return resource_policy.fields.allow

        return None
