"""
Customer-owned generic resource registry for the basic DataFence example.

The ResourceRegistry answers:
  WHAT resources exist?
  WHAT fields do they have?
  WHAT is the data classification of each field?
  WHAT operations are supported?

It does NOT answer WHO can access them — that is the Policy's job.

This example uses neutral, domain-independent resources:
  orders, documents, customers
"""

from datafence import DataClassification, FieldDefinition, ResourceDefinition, ResourceRegistry
from datafence.core.resources import PredicateOperator  # noqa: F401 — re-exported for convenience


def create_registry() -> ResourceRegistry:
    """Build and return a populated (unfrozen) ResourceRegistry."""
    registry = ResourceRegistry()

    registry.register(
        ResourceDefinition(
            name="orders",
            description="Customer purchase orders.",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id",
                    "string",
                    DataClassification.INTERNAL,
                    is_tenant_key=True,
                ),
                "customer_id": FieldDefinition(
                    "customer_id", "integer", DataClassification.INTERNAL
                ),
                "total": FieldDefinition("total", "decimal", DataClassification.CONFIDENTIAL),
                "status": FieldDefinition("status", "string", DataClassification.INTERNAL),
                "created_at": FieldDefinition(
                    "created_at", "datetime", DataClassification.INTERNAL
                ),
            },
            supported_operations=("read",),
        )
    )

    registry.register(
        ResourceDefinition(
            name="documents",
            description="Internal documents and records.",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id",
                    "string",
                    DataClassification.INTERNAL,
                    is_tenant_key=True,
                ),
                "title": FieldDefinition("title", "string", DataClassification.INTERNAL),
                "status": FieldDefinition("status", "string", DataClassification.INTERNAL),
                "created_at": FieldDefinition(
                    "created_at", "datetime", DataClassification.INTERNAL
                ),
                "internal_notes": FieldDefinition(
                    "internal_notes", "string", DataClassification.CONFIDENTIAL
                ),
            },
            supported_operations=("read",),
        )
    )

    registry.register(
        ResourceDefinition(
            name="customers",
            description="Customer master records.",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id",
                    "string",
                    DataClassification.INTERNAL,
                    is_tenant_key=True,
                ),
                "name": FieldDefinition("name", "string", DataClassification.INTERNAL),
                "email": FieldDefinition("email", "string", DataClassification.CONFIDENTIAL),
                "ssn": FieldDefinition("ssn", "string", DataClassification.RESTRICTED),
            },
            supported_operations=("read",),
        )
    )

    return registry
