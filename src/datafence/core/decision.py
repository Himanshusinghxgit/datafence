"""
Decision models for policy evaluation.

Every request results in an explicit decision.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DecisionStatus(str, Enum):
    """Possible decision outcomes."""

    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"


class PolicyCheck(BaseModel):
    """Individual policy check result."""

    name: str = Field(..., description="Name of the check")
    passed: bool = Field(..., description="Whether the check passed")
    reason: str | None = Field(default=None, description="Reason if failed")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional check metadata")


class Decision(BaseModel):
    """
    Result of policy evaluation.

    Every decision must be explainable and auditable.
    """

    status: DecisionStatus = Field(..., description="Decision outcome")
    reasons: list[str] = Field(default_factory=list, description="Reasons for the decision")
    policy_name: str | None = Field(default=None, description="Policy that was evaluated")
    policy_version: str | None = Field(default=None, description="Version of the policy")
    checks: list[PolicyCheck] = Field(
        default_factory=list, description="Individual policy checks performed"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional decision metadata"
    )

    def is_allowed(self) -> bool:
        """Check if the decision allows the operation."""
        return self.status == DecisionStatus.ALLOW

    def __str__(self) -> str:
        """Human-readable decision summary."""
        if self.is_allowed():
            return f"ALLOW (policy: {self.policy_name})"
        reasons_str = "; ".join(self.reasons) if self.reasons else "no specific reason"
        return f"{self.status.value.upper()}: {reasons_str}"
