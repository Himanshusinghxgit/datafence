"""
Result models for DataFence executions.

Results include data, provenance, evidence, and audit information.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from datafence.core.decision import Decision
from datafence.provenance.models import Evidence, Provenance


class ExecutionResult(BaseModel):
    """
    Result of a DataFence execution.

    Includes data, decision, provenance, and evidence.
    """

    # Core result
    data: Any = Field(default=None, description="Actual data returned (if allowed)")
    row_count: int = Field(default=0, description="Number of rows returned")

    # Decision
    decision: Decision = Field(..., description="Policy decision for this request")

    # Verification
    verified: bool = Field(..., description="Whether this result passed all security checks")

    # Provenance
    provenance: Provenance | None = Field(default=None, description="Data provenance information")

    # Evidence
    evidence: Evidence | None = Field(
        default=None, description="Cryptographic evidence of policy compliance"
    )

    # Audit
    request_id: str | None = Field(default=None, description="Unique request identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Execution timestamp")

    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional result metadata")

    @property
    def denied(self) -> bool:
        """Check if the request was denied."""
        return not self.verified

    def __str__(self) -> str:
        """Human-readable result summary."""
        if self.verified:
            return f"✓ Success: {self.row_count} rows (request_id: {self.request_id})"
        return f"✗ Denied: {self.decision}"
