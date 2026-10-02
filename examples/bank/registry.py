"""
Banking domain resource registry.

This is an APPLICATION-LEVEL construct built on top of DataFence core.
BankRegistry is NOT part of DataFence itself — it is a domain-specific
example showing how a banking application might configure the generic
ResourceRegistry.

DataFence core exports: ResourceRegistry, ResourceDefinition, FieldDefinition.
This file shows how a banking team would use those generic building blocks.
"""

from datafence import DataClassification, FieldDefinition, ResourceDefinition, ResourceRegistry


def create_bank_registry() -> ResourceRegistry:
    """
    Create a ResourceRegistry for a banking application.

    Resources: transactions, customers, accounts
    """
    registry = ResourceRegistry()

    registry.register(
        ResourceDefinition(
            name="transactions",
            description="Financial transaction records.",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id", "string", DataClassification.INTERNAL, is_tenant_key=True
                ),
                "customer_id": FieldDefinition("customer_id", "integer", DataClassification.INTERNAL),
                "merchant": FieldDefinition("merchant", "string", DataClassification.PUBLIC),
                "amount": FieldDefinition("amount", "decimal", DataClassification.CONFIDENTIAL),
                "timestamp": FieldDefinition("timestamp", "datetime", DataClassification.INTERNAL),
                # Sensitive — policy should deny access to these
                "card_number": FieldDefinition("card_number", "string", DataClassification.RESTRICTED),
                "account_number": FieldDefinition("account_number", "string", DataClassification.RESTRICTED),
            },
            supported_operations=("read",),
        )
    )

    registry.register(
        ResourceDefinition(
            name="customers",
            description="Bank customer master data.",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id", "string", DataClassification.INTERNAL, is_tenant_key=True
                ),
                "name": FieldDefinition("name", "string", DataClassification.INTERNAL),
                "email": FieldDefinition("email", "string", DataClassification.CONFIDENTIAL),
                "ssn": FieldDefinition("ssn", "string", DataClassification.RESTRICTED),
                "account_number": FieldDefinition("account_number", "string", DataClassification.RESTRICTED),
            },
            supported_operations=("read",),
        )
    )

    registry.register(
        ResourceDefinition(
            name="accounts",
            description="Bank account records.",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id", "string", DataClassification.INTERNAL, is_tenant_key=True
                ),
                "customer_id": FieldDefinition("customer_id", "integer", DataClassification.INTERNAL),
                "account_number": FieldDefinition("account_number", "string", DataClassification.RESTRICTED),
                "balance": FieldDefinition("balance", "decimal", DataClassification.RESTRICTED),
            },
            supported_operations=("read",),
        )
    )

    return registry
