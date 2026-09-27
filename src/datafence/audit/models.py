"""
Audit event models.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from datafence.core.decision import DecisionStatus


class AuditEvent(BaseModel):
    """
    Audit event for a DataFence request.

    Records all security-relevant information without leaking sensitive data.
    """

    # Identifiers
    event_id: str = Field(..., description="Unique event identifier")
    request_id: str | None = Field(default=None, description="Request identifier")
    session_id: str | None = Field(default=None, description="Session identifier")

    # Timestamp
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")

    # Actor
    actor_id: str = Field(..., description="Actor identifier")
    actor_type: str = Field(..., description="Actor type")
    tenant_id: str | None = Field(default=None, description="Tenant identifier")

    # Request
    operation: str = Field(..., description="Operation attempted")
    resource: str = Field(..., description="Resource accessed")

    # Decision
    decision: DecisionStatus = Field(..., description="Policy decision")
    policy_name: str | None = Field(default=None, description="Policy name")
    policy_version: str | None = Field(default=None, description="Policy version")

    # Outcome
    reason: str | None = Field(default=None, description="Reason for denial (if denied)")
    row_count: int = Field(default=0, description="Number of rows returned")

    # Metadata (must not contain sensitive data)
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional event metadata")
