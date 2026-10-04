"""
Banking domain policy.

This is an APPLICATION-LEVEL construct built on top of DataFence core.
BankPolicy is NOT part of DataFence itself.

It shows how a banking team configures the generic DataFencePolicyEngine
for their domain: denying card_number/account_number/ssn/balance, enforcing
tenant isolation, and locking down writes.
"""

from datafence import (
    ActionDecision,
    DataFencePolicy,
    DataFencePolicyEngine,
    ResourcePolicy,
    RowRule,
)
from datafence.core.resources import PredicateOperator
from examples.bank.registry import create_bank_registry


def create_bank_policy() -> DataFencePolicyEngine:
    """
    Create a policy engine for the banking example.

    Enforces:
    - Read-only access to transactions and customers.
    - No access to accounts (all operations denied).
    - Tenant isolation on all resources.
    - card_number, ssn, account_number, balance always denied.
    """
    registry = create_bank_registry()

    policy = DataFencePolicy(
        name="banking-demo",
        version="1.0",
        resources={
            "transactions": ResourcePolicy(
                resource="transactions",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "customer_id", "merchant", "amount", "timestamp"],
                denied_fields=["card_number", "account_number"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=100,
                obligations={"audit": True},
            ),
            "customers": ResourcePolicy(
                resource="customers",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "name", "email"],
                denied_fields=["ssn", "account_number"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=100,
            ),
            "accounts": ResourcePolicy(
                resource="accounts",
                actions={},  # no operations allowed — implicit deny
                allowed_fields=[],
                denied_fields=["account_number", "balance"],
                row_rules=[],
                max_rows=0,
            ),
        },
    )

    return DataFencePolicyEngine(policy, registry=registry)
