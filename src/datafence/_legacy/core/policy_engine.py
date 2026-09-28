"""
Simple policy engine for killer demo.

This is a minimal implementation to prove the security boundary.
"""

from dataclasses import dataclass
from typing import Any

from datafence.core.types import Actor, Decision, Operation, PolicyDecision


@dataclass
class ResourcePolicy:
    """Policy for a resource."""

    resource: str
    allowed_operations: list[Operation]
    denied_operations: list[Operation]
    allowed_fields: list[str]
    denied_fields: list[str]
    enforced_filters: dict[str, str]  # e.g., {"tenant_id": ":actor_tenant_id"}
    max_limit: int


class SimplePolicyEngine:
    """
    Simple policy engine.
    
    For the killer demo, this implements:
    - Field-level access control
    - Tenant isolation
    - Operation restrictions
    """

    def __init__(self, policies: dict[str, ResourcePolicy]):
        self.policies = policies
        self.version = "banking-demo-v1"

    def evaluate(
        self,
        actor: Actor,
        resource: str,
        operation: Operation,
        requested_fields: list[str],
    ) -> PolicyDecision:
        """
        Evaluate policy.
        
        Returns ALLOW or DENY.
        """
        # Get policy for resource
        policy = self.policies.get(resource)
        if not policy:
            return PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"No policy defined for resource: {resource}"],
                policy_version=self.version,
            )

        # Check operation
        if operation in policy.denied_operations:
            return PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"Operation {operation.value} is explicitly denied"],
                policy_version=self.version,
                matched_policies=[f"{resource}.deny.{operation.value}"],
            )

        if operation not in policy.allowed_operations:
            return PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"Operation {operation.value} is not allowed"],
                policy_version=self.version,
            )

        # Check fields (if specific fields requested)
        if requested_fields:
            denied_fields = [f for f in requested_fields if f in policy.denied_fields]
            if denied_fields:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reasons=[
                        f"Requested fields are denied: {', '.join(denied_fields)}"
                    ],
                    policy_version=self.version,
                    matched_policies=[f"{resource}.deny.fields"],
                )

            unauthorized_fields = [
                f for f in requested_fields if f not in policy.allowed_fields
            ]
            if unauthorized_fields:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reasons=[
                        f"Requested fields are not authorized: {', '.join(unauthorized_fields)}"
                    ],
                    policy_version=self.version,
                )

        # Allow
        return PolicyDecision(
            decision=Decision.ALLOW,
            reasons=[],
            policy_version=self.version,
            matched_policies=[
                f"{resource}.allow.{operation.value}",
                f"{resource}.fields.allowed",
            ],
        )

    def get_allowed_fields(self, actor: Actor, resource: str) -> list[str]:
        """Get allowed fields for a resource."""
        policy = self.policies.get(resource)
        if not policy:
            return []
        return policy.allowed_fields

    def get_enforced_filters(self, actor: Actor, resource: str) -> dict[str, str]:
        """Get enforced filters (e.g., tenant_id)."""
        policy = self.policies.get(resource)
        if not policy:
            return {}
        return policy.enforced_filters

    def get_max_limit(self, actor: Actor, resource: str) -> int:
        """Get maximum limit."""
        policy = self.policies.get(resource)
        if not policy:
            return 100
        return policy.max_limit

    def get_policy_version(self) -> str:
        """Get policy version."""
        return self.version


def create_banking_demo_policy() -> SimplePolicyEngine:
    """
    Create the policy for the killer demo.
    
    This policy allows agent:finance to:
    - READ transactions
    - Access fields: id, merchant, amount, timestamp
    - DENY: card_number, account_number
    - Enforce tenant isolation
    - Max 100 rows
    """
    policies = {
        "transactions": ResourcePolicy(
            resource="transactions",
            allowed_operations=[Operation.READ],
            denied_operations=[Operation.INSERT, Operation.UPDATE, Operation.DELETE],
            allowed_fields=["id", "merchant", "amount", "timestamp"],
            denied_fields=["card_number", "account_number"],
            enforced_filters={"tenant_id": ":actor_tenant_id"},
            max_limit=100,
        ),
        "customers": ResourcePolicy(
            resource="customers",
            allowed_operations=[Operation.READ],
            denied_operations=[Operation.INSERT, Operation.UPDATE, Operation.DELETE],
            allowed_fields=["id", "name", "email"],
            denied_fields=["ssn", "account_number"],
            enforced_filters={"tenant_id": ":actor_tenant_id"},
            max_limit=100,
        ),
        "accounts": ResourcePolicy(
            resource="accounts",
            allowed_operations=[],  # No operations allowed
            denied_operations=[
                Operation.READ,
                Operation.INSERT,
                Operation.UPDATE,
                Operation.DELETE,
            ],
            allowed_fields=[],
            denied_fields=["account_number", "balance"],
            enforced_filters={},
            max_limit=0,
        ),
    }

    return SimplePolicyEngine(policies)
