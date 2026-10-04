"""
Generic policy for the basic DataFence authorization example.

The Policy answers:
  WHO (which principal roles/attributes) can do WHAT?
  ON WHICH resource?
  WHICH fields are accessible?
  WHICH rows (enforced tenant isolation)?
  WITH WHAT row limits?

This example grants read-only access to orders and documents with
mandatory tenant isolation. SSN and internal_notes fields are excluded.

NOTE: This imports the registry from registry.py in the same directory.
When running standalone (python examples/basic/application.py) the
current directory must be examples/basic/, or use the package-level
import path.
"""

from datafence import (
    ActionDecision,
    DataFencePolicy,
    DataFencePolicyEngine,
    ResourcePolicy,
    RowRule,
)
from datafence.core.resources import PredicateOperator
from examples.basic.registry import create_registry  # package-level import


def create_policy() -> DataFencePolicyEngine:
    """Build and return a configured DataFencePolicyEngine."""
    registry = create_registry()

    policy = DataFencePolicy(
        name="generic-enterprise",
        version="1.0",
        resources={
            "orders": ResourcePolicy(
                resource="orders",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "customer_id", "total", "status", "created_at"],
                denied_fields=[],
                filterable_fields=["id", "tenant_id", "status", "customer_id"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=100,
                obligations={"audit": True},
            ),
            "documents": ResourcePolicy(
                resource="documents",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "title", "status", "created_at"],
                denied_fields=["internal_notes"],  # explicitly excluded
                filterable_fields=["id", "tenant_id", "status"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=50,
            ),
            "customers": ResourcePolicy(
                resource="customers",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "name", "email"],
                denied_fields=["ssn"],  # RESTRICTED — never accessible
                filterable_fields=["id", "tenant_id"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=200,
            ),
        },
    )

    return DataFencePolicyEngine(policy, registry=registry)
