"""
Request context and actor models.

These define WHO is making a request and under what context.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ActorType(str, Enum):
    """Type of actor making the request."""

    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"
    APPLICATION = "application"


class Actor(BaseModel):
    """
    Represents the entity making a request.

    Examples:
        - human:user_123
        - agent:finance_assistant
        - service:risk_engine
    """

    id: str = Field(..., description="Unique actor identifier")
    type: ActorType = Field(default=ActorType.AGENT, description="Type of actor")
    attributes: dict[str, Any] = Field(
        default_factory=dict, description="Additional actor attributes for policy evaluation"
    )

    def __str__(self) -> str:
        return f"{self.type.value}:{self.id}"


class RequestContext(BaseModel):
    """
    Complete context for a request.

    Includes actor information and tenant isolation.
    """

    actor: Actor = Field(..., description="Actor making the request")
    tenant_id: str | None = Field(default=None, description="Tenant identifier for multi-tenancy")
    session_id: str | None = Field(default=None, description="Session identifier for tracking")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional context metadata"
    )

    @property
    def customer_id(self) -> str | None:
        """Convenience accessor for customer_id from actor attributes."""
        return self.actor.attributes.get("customer_id")

    @property
    def region(self) -> str | None:
        """Convenience accessor for region from actor attributes."""
        return self.actor.attributes.get("region")
