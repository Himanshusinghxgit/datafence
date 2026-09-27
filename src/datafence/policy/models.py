"""
Policy models.

Policies are deterministic rules defining what is allowed.
"""

from typing import Any

from pydantic import BaseModel, Field

from datafence.core.request import Operation


class FieldPolicy(BaseModel):
    """Field-level access control."""

    allow: list[str] = Field(default_factory=list, description="Explicitly allowed fields")
    deny: list[str] = Field(default_factory=list, description="Explicitly denied fields")


class OperationPolicy(BaseModel):
    """Operation-level access control."""

    allow: list[Operation] = Field(
        default_factory=list, description="Explicitly allowed operations"
    )
    deny: list[Operation] = Field(default_factory=list, description="Explicitly denied operations")


class Limits(BaseModel):
    """Query and result limits."""

    max_rows: int | None = Field(default=None, description="Maximum rows to return")
    max_date_range_days: int | None = Field(default=None, description="Maximum date range in days")
    timeout_seconds: int | None = Field(default=None, description="Query timeout in seconds")


class ResourcePolicy(BaseModel):
    """
    Policy for a specific resource.

    Defines operations, fields, row filters, and limits.
    """

    operations: OperationPolicy = Field(
        default_factory=OperationPolicy, description="Allowed/denied operations"
    )
    fields: FieldPolicy = Field(
        default_factory=FieldPolicy, description="Field-level access control"
    )
    row_filters: dict[str, str] = Field(
        default_factory=dict,
        description="Row-level filters (supports template variables like {{ actor.customer_id }})",
    )
    limits: Limits = Field(default_factory=Limits, description="Query and result limits")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional resource metadata"
    )


class Policy(BaseModel):
    """
    Complete DataFence policy.

    Defines security rules for resources, operations, and actors.
    """

    version: str = Field(..., description="Policy version")
    name: str = Field(..., description="Policy name")
    resources: dict[str, ResourcePolicy] = Field(
        ..., description="Resource-specific policies (keyed by resource name)"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional policy metadata")

    def get_resource_policy(self, resource: str) -> ResourcePolicy | None:
        """
        Get policy for a specific resource.

        Args:
            resource: Resource name

        Returns:
            ResourcePolicy if found, None otherwise
        """
        return self.resources.get(resource)
