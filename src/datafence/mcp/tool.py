"""
DataFence MCP Tool.

Returns a portable CapabilityToken so the caller's connector can verify the
authorization independently without holding a DataFence runtime object.

Security invariants:
    - The Principal is resolved by the MCP server from authenticated transport
      context, never from the agent's tool call arguments.
    - The agent controls: resource, fields, filters (all treated as untrusted Intent).
    - The policy controls: authorized fields, enforced row filters, row limits.
    - DataFence does not execute database operations; it only authorizes.
    - principal_resolver is required on DataFenceMCPServer; no fallback exists.
    - v0.1 supports READ only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.capability import CapabilityToken
from datafence.core.principal import Principal
from datafence.core.types import Intent, Operation
from datafence.errors import DataFenceError


@dataclass
class ToolResult:
    """Result returned to the MCP client / agent."""

    allowed: bool
    capability: dict[str, Any] | None
    token: str | None  # portable signed CapabilityToken
    denial_reasons: list[str]
    request_id: str  # correlation ID (execution_id on success)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "capability": self.capability,
            "token": self.token,
            "denial_reasons": self.denial_reasons,
            "request_id": self.request_id,
        }


class DataFenceQueryTool:
    """
    MCP tool wrapper around DataFenceBoundary.

    Exposes a single ``datafence_query`` tool that authorizes READ requests
    and returns a signed CapabilityToken.
    """

    def __init__(
        self,
        boundary: DataFenceBoundary,
        tool_name: str = "datafence_query",
        description: str = (
            "Request read access to a data resource through the DataFence authorization "
            "boundary. Returns a signed authorization token for the caller's connector. "
            "Only authorized fields and rows are permitted. DataFence does not return data."
        ),
    ) -> None:
        self.boundary = boundary
        self.tool_name = tool_name
        self.description = description

    def schema(self) -> dict[str, Any]:
        """Return the JSON schema for this tool's input parameters."""
        return {
            "name": self.tool_name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "resource": {
                        "type": "string",
                        "description": "The data resource to access (e.g. 'orders').",
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Fields to return. Leave empty for all authorised fields.",
                    },
                    "filters": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Optional key=value row filters.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum rows (capped by policy).",
                        "default": 10,
                    },
                    # operation intentionally omitted from schema — v0.1 is READ-only
                },
                "required": ["resource"],
            },
        }

    def call(
        self,
        principal: Principal,
        params: dict[str, Any],
    ) -> ToolResult:
        """
        Execute a tool call on behalf of *principal*.

        Args:
            principal : Authenticated Principal from the MCP server's transport context.
            params    : Tool call parameters from the agent (untrusted Intent).

        Returns:
            ToolResult with the CapabilityToken or denial reasons.
        """
        # v0.1: READ-only
        intent = Intent(
            resource=str(params.get("resource", "")),
            operation=Operation.READ,
            fields=params.get("fields") or None,
            filters=params.get("filters") or {},
            limit=int(params.get("limit") or 10),
        )

        try:
            capability = self.boundary.authorize(principal, intent)
        except DataFenceError as exc:
            return ToolResult(
                allowed=False,
                capability=None,
                token=None,
                denial_reasons=[str(exc)],
                request_id="",
            )

        token = CapabilityToken.encode(capability)
        return ToolResult(
            allowed=True,
            capability={
                "execution_id": capability.execution_id,
                "resource": capability.resource,
                "operation": capability.operation.value,
                "selected_fields": list(capability.selected_fields),
                "predicates": capability.filter_constraints(),
                "limit": capability.limit,
                "policy_version": capability.policy_version,
                "expires_at": (
                    capability.expires_at.isoformat() if capability.expires_at else None
                ),
                "audience": capability.audience,
                "obligations": dict(capability.obligations or {}),
            },
            token=token,
            denial_reasons=[],
            request_id=capability.execution_id,
        )
