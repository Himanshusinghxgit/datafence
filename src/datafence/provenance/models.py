"""
Provenance and evidence models.

Provenance tracks where data came from.
Evidence provides cryptographic proof of policy compliance.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Provenance(BaseModel):
    """
    Data provenance information.

    Tracks the source and lineage of returned data.
    """

    source: str = Field(..., description="Source system (e.g., postgres, athena, s3)")
    resource: str = Field(..., description="Specific resource (table, file, etc.)")
    policy_name: str | None = Field(default=None, description="Policy that governed access")
    policy_version: str | None = Field(default=None, description="Version of the policy")
    query_hash: str | None = Field(default=None, description="SHA-256 hash of normalized query")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Access timestamp")
    actor: str | None = Field(default=None, description="Actor who accessed the data")
    tenant_id: str | None = Field(default=None, description="Tenant identifier")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional provenance metadata"
    )


class Evidence(BaseModel):
    """
    Cryptographic evidence of policy-compliant execution.

    This is NOT proof that the LLM is correct.
    This IS proof that the result was produced through a controlled, policy-compliant path.
    """

    verified: bool = Field(..., description="Whether all checks passed")
    request_id: str = Field(..., description="Unique request identifier")
    policy_name: str | None = Field(default=None, description="Policy that was enforced")
    policy_version: str | None = Field(default=None, description="Version of the policy")

    # Hashes for verification
    request_hash: str | None = Field(default=None, description="SHA-256 hash of normalized request")
    query_hash: str | None = Field(default=None, description="SHA-256 hash of executed query")
    result_hash: str | None = Field(default=None, description="SHA-256 hash of result metadata")

    # Checks performed
    checks: list[str] = Field(
        default_factory=list,
        description="List of security checks performed (e.g., identity, authorization, fields)",
    )

    # Timestamps
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Evidence timestamp")

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional evidence metadata"
    )
