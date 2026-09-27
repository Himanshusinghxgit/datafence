"""
Request models for DataFence operations.

All requests must be structured and typed - no raw natural language.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from datafence.core.context import Actor


class Operation(str, Enum):
    """Supported operations."""

    READ = "read"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    CREATE = "create"
    DROP = "drop"
    ALTER = "alter"
    TRUNCATE = "truncate"


class ExecutionRequest(BaseModel):
    """
    A structured request for data access or manipulation.

    This is the primary interface between AI systems and DataFence.
    The LLM/agent converts natural language into this structured format.
    """

    actor: Actor = Field(..., description="Actor making the request")
    operation: Operation = Field(..., description="Operation to perform")
    resource: str = Field(..., description="Resource identifier (table, dataset, etc.)")
    tenant_id: str | None = Field(default=None, description="Tenant identifier")

    # Field-level access
    fields: list[str] | None = Field(
        default=None, description="Specific fields to access (None means all allowed by policy)"
    )

    # Row-level filtering
    filters: dict[str, Any] = Field(
        default_factory=dict, description="Filters to apply (e.g., customer_id, date ranges)"
    )

    # Limits
    limit: int | None = Field(default=None, description="Maximum rows to return")

    # Raw query (optional, will be validated)
    raw_query: str | None = Field(
        default=None, description="Raw SQL query (will be parsed and validated)"
    )

    # Additional parameters
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="Additional operation parameters"
    )

    model_config = {"use_enum_values": True}
