"""
DataFence Resource Registry (v0.6.0).

The Registry answers:
  - Does this resource exist?
  - Are these fields valid for this resource?
  - What is the data classification of each field?
  - Which field is the tenant key?
  - What operations are supported?

This sits between Intent and Policy evaluation:

    Intent
      ↓
    Resource Registry      ← Does resource/fields exist? Are they valid?
      ↓
    Policy Engine          ← Is this principal allowed to access them?
      ↓
    AuthorizedExecution

Without a registry, a policy engine must blindly trust that "transactions"
and "card_number" are real fields.  The registry makes that explicit.

Data classifications (ordered by sensitivity)
---------------------------------------------
PUBLIC      — non-sensitive, freely shareable
INTERNAL    — internal use only, not for external parties
CONFIDENTIAL — requires explicit authorization (e.g., personal data)
RESTRICTED  — highly sensitive (card numbers, SSNs, credentials)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from datafence.core.resources import validate_identifier


class DataClassification(Enum):
    """Sensitivity classification for a field."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    def is_more_sensitive_than(self, other: DataClassification) -> bool:
        _rank = {
            DataClassification.PUBLIC: 0,
            DataClassification.INTERNAL: 1,
            DataClassification.CONFIDENTIAL: 2,
            DataClassification.RESTRICTED: 3,
        }
        return _rank[self] > _rank[other]


@dataclass(frozen=True)
class FieldDefinition:
    """
    Definition of a single field in a resource.

    Attributes
    ----------
    name           : Column/attribute name.
    data_type      : Logical data type hint ("string", "integer", "decimal", etc.).
    classification : Sensitivity level.
    is_tenant_key  : True if this field is the tenant isolation column.
    nullable       : Whether the field can be NULL.
    description    : Human-readable description.
    """

    name: str
    data_type: str = "string"
    classification: DataClassification = DataClassification.INTERNAL
    is_tenant_key: bool = False
    nullable: bool = True
    description: str = ""


@dataclass(frozen=True)
class ResourceDefinition:
    """
    Definition of a data resource (table, view, collection).

    Attributes
    ----------
    name        : Resource name (must match identifier rules).
    fields      : Ordered dict of field_name → FieldDefinition.
    description : Human-readable description.
    tags        : Arbitrary string tags for grouping/filtering.
    """

    name: str
    fields: Mapping[str, FieldDefinition] = field(default_factory=dict)
    description: str = ""
    tags: Sequence[str] = ()
    supported_operations: tuple[str, ...] = ("read", "insert", "update", "delete")

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))
        object.__setattr__(self, "tags", tuple(self.tags))
        object.__setattr__(self, "supported_operations", tuple(self.supported_operations))
        validate_identifier(self.name, context="resource name")
        for field_name in self.fields:
            validate_identifier(field_name, context="field name")
        if not self.supported_operations:
            raise ValueError("A resource must support at least one operation")
        for operation in self.supported_operations:
            if operation not in {"read", "insert", "update", "delete"}:
                raise ValueError(f"Unsupported resource operation: {operation!r}")

    def field_names(self) -> list[str]:
        return list(self.fields.keys())

    def tenant_key(self) -> str | None:
        """Return the name of the tenant isolation field, if defined."""
        for f in self.fields.values():
            if f.is_tenant_key:
                return f.name
        return None

    def fields_by_classification(self, classification: DataClassification) -> list[str]:
        return [n for n, f in self.fields.items() if f.classification == classification]

    def sensitive_fields(self) -> list[str]:
        """Return fields classified as CONFIDENTIAL or RESTRICTED."""
        return [
            n
            for n, f in self.fields.items()
            if f.classification
            in (
                DataClassification.CONFIDENTIAL,
                DataClassification.RESTRICTED,
            )
        ]


class ResourceRegistry:
    """
    Registry of known data resources and their field definitions.

    The registry is the authoritative source of truth about what resources
    and fields exist.  Policy evaluation can use it to validate requests
    and auto-derive deny lists based on data classification.

    Usage::

        registry = ResourceRegistry()
        registry.register(ResourceDefinition(
            name="transactions",
            fields={
                "id":          FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "merchant":    FieldDefinition("merchant", "string", DataClassification.PUBLIC),
                "amount":      FieldDefinition("amount", "decimal", DataClassification.CONFIDENTIAL),
                "tenant_id":   FieldDefinition("tenant_id", "string",
                                               DataClassification.INTERNAL, is_tenant_key=True),
                "card_number": FieldDefinition("card_number", "string",
                                               DataClassification.RESTRICTED),
            }
        ))

        resource = registry.get("transactions")
        registry.validate_fields("transactions", ["id", "merchant"])  # OK
        registry.validate_fields("transactions", ["card_number"])      # raises
    """

    def __init__(self) -> None:
        self._resources: dict[str, ResourceDefinition] = {}
        self._frozen = False

    def register(self, resource: ResourceDefinition) -> None:
        """Register a resource definition."""
        if self._frozen:
            raise RuntimeError("ResourceRegistry is frozen")
        self._resources[resource.name] = resource

    def freeze(self) -> None:
        """Freeze schema metadata before a boundary begins serving requests."""
        self._frozen = True

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def get(self, name: str) -> ResourceDefinition | None:
        """Return the ResourceDefinition for *name*, or None."""
        return self._resources.get(name)

    def exists(self, name: str) -> bool:
        return name in self._resources

    def validate_fields(self, resource_name: str, fields: list[str]) -> None:
        """
        Raise ValueError if any field is not defined on the resource.

        Args:
            resource_name : Resource to look up.
            fields        : List of field names to validate.

        Raises:
            ValueError: If the resource is unknown or a field is undefined.
        """
        resource = self._resources.get(resource_name)
        if resource is None:
            raise ValueError(f"Unknown resource: {resource_name!r}")
        unknown = [f for f in fields if f not in resource.fields]
        if unknown:
            raise ValueError(
                f"Unknown fields on {resource_name!r}: {unknown}. "
                f"Valid fields: {resource.field_names()}"
            )

    def validate_intent(self, intent: Any) -> None:
        """Validate the descriptive/schema part of an intent.

        This deliberately does not authorize the principal.  It only ensures
        that the boundary never sends an unknown resource, field, or operation
        to policy evaluation or a connector.
        """
        validate_identifier(intent.resource, context="resource name")
        resource = self._resources.get(intent.resource)
        if resource is None:
            raise ValueError(f"Unknown resource: {intent.resource!r}")
        operation = getattr(intent.operation, "value", intent.operation)
        if str(operation).lower() not in resource.supported_operations:
            raise ValueError(
                f"Operation {operation!r} is not supported on resource {intent.resource!r}"
            )
        fields = intent.fields or []
        self.validate_fields(intent.resource, fields)
        for field_name in intent.filters:
            validate_identifier(field_name, context="filter field name")
            field = resource.fields.get(field_name)
            if field is None:
                raise ValueError(f"Unknown filter field on {intent.resource!r}: {field_name!r}")
            if field.classification == DataClassification.RESTRICTED:
                raise ValueError(f"Filtering on restricted field is not allowed: {field_name!r}")
        if intent.limit is not None and intent.limit <= 0:
            raise ValueError("Intent limit must be positive")

    def all_resources(self) -> list[str]:
        return list(self._resources.keys())


# ---------------------------------------------------------------------------
# Banking demo registry — mirrors the demo database schema
# ---------------------------------------------------------------------------


def create_banking_registry() -> ResourceRegistry:
    """
    Create the resource registry for the banking demo.

    Mirrors the schema created by create_demo_database().
    """
    registry = ResourceRegistry()

    registry.register(
        ResourceDefinition(
            name="transactions",
            description="Financial transaction ledger",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id", "string", DataClassification.INTERNAL, is_tenant_key=True
                ),
                "customer_id": FieldDefinition(
                    "customer_id", "integer", DataClassification.INTERNAL
                ),
                "merchant": FieldDefinition("merchant", "string", DataClassification.PUBLIC),
                "amount": FieldDefinition("amount", "decimal", DataClassification.CONFIDENTIAL),
                "timestamp": FieldDefinition("timestamp", "string", DataClassification.INTERNAL),
                "card_number": FieldDefinition(
                    "card_number",
                    "string",
                    DataClassification.RESTRICTED,
                    description="Primary account number — PCI DSS restricted",
                ),
            },
            tags=["financial", "pci"],
        )
    )

    registry.register(
        ResourceDefinition(
            name="customers",
            description="Customer identity records",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id", "string", DataClassification.INTERNAL, is_tenant_key=True
                ),
                "name": FieldDefinition("name", "string", DataClassification.CONFIDENTIAL),
                "email": FieldDefinition("email", "string", DataClassification.CONFIDENTIAL),
                "ssn": FieldDefinition(
                    "ssn",
                    "string",
                    DataClassification.RESTRICTED,
                    description="Social Security Number — PII restricted",
                ),
                "account_number": FieldDefinition(
                    "account_number", "string", DataClassification.RESTRICTED
                ),
            },
            tags=["pii", "gdpr"],
        )
    )

    registry.register(
        ResourceDefinition(
            name="accounts",
            description="Financial account records",
            fields={
                "id": FieldDefinition("id", "integer", DataClassification.INTERNAL),
                "tenant_id": FieldDefinition(
                    "tenant_id", "string", DataClassification.INTERNAL, is_tenant_key=True
                ),
                "customer_id": FieldDefinition(
                    "customer_id", "integer", DataClassification.INTERNAL
                ),
                "account_number": FieldDefinition(
                    "account_number", "string", DataClassification.RESTRICTED
                ),
                "balance": FieldDefinition("balance", "decimal", DataClassification.RESTRICTED),
            },
            tags=["financial"],
        )
    )

    return registry
