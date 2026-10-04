"""
DataFence MCP Tool.

Exposes a DataFenceBoundary as an MCP tool so AI agents can request
data access through a properly authorized execution boundary.

Architecture::

    AI Agent
        │  MCP tool call: {"resource": "orders", "fields": [...], ...}
        ▼
    DataFenceQueryTool.call(principal, params)
        │  constructs Intent from agent params (untrusted)
        ▼
    DataFenceBoundary.authorize(principal, intent)
        │  Registry → Policy → AuthorizedExecution
        ▼
    ToolResult  — returns the signed capability to the caller
                  (the caller's connector executes it, not DataFence)

Security invariants:
    - The Principal is resolved by the MCP server from authenticated transport
      context, never from the agent's tool call arguments.
    - The agent controls: resource, fields, filters (all treated as untrusted Intent).
    - The policy controls: authorized fields, enforced row filters, row limits.
    - The agent cannot escalate beyond what the policy allows.
    - DataFence does not execute database operations; it only authorizes.
    - principal_resolver is required on DataFenceMCPServer; no fallback exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.principal import Principal
from datafence.core.types import Intent, Operation
from datafence.errors import DataFenceError


@dataclass
class ToolResult:
    """Result returned to the MCP client / agent."""

    allowed: bool
    capability: dict[str, Any] | None
    denial_reasons: list[str]
    request_id: str
    evidence_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "capability": self.capability,
            "denial_reasons": self.denial_reasons,
            "request_id": self.request_id,
            "evidence_id": self.evidence_id,
        }


class DataFenceQueryTool:
    """
    MCP tool wrapper around DataFenceBoundary.

    Designed to be used with any MCP server implementation.

    Parameters
    ----------
    boundary : DataFenceBoundary
        A fully-configured boundary (created via DataFenceBoundary.create()).
    tool_name : str
        The name exposed to the MCP client (default: "datafence_query").
    description : str
        Human-readable description shown to the agent.
    """

    def __init__(
        self,
        boundary: DataFenceBoundary,
        tool_name: str = "datafence_query",
        description: str = (
            "Query data through the DataFence authorization boundary. "
            "The boundary enforces field-level and row-level security policies. "
            "You cannot access fields or rows outside your authorization."
        ),
    ) -> None:
        self.boundary = boundary
        self.tool_name = tool_name
        self.description = description

    # ------------------------------------------------------------------
    # Tool schema (for MCP tool registration)
    # ------------------------------------------------------------------

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
                        "description": "The data resource to query (e.g. 'transactions').",
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Fields to return. Leave empty to get all authorised fields."
                        ),
                    },
                    "filters": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": 'Optional key=value filters (e.g. {"merchant": "Amazon"}).',
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum rows to return (capped by policy).",
                        "default": 10,
                    },
                    "operation": {
                        "type": "string",
                        "enum": ["read"],
                        "description": "Operation type (currently only 'read' is supported).",
                        "default": "read",
                    },
                },
                "required": ["resource"],
            },
        }

    # ------------------------------------------------------------------
    # Call interface
    # ------------------------------------------------------------------

    def call(
        self,
        principal: Principal,
        params: dict[str, Any],
    ) -> ToolResult:
        """
        Execute a tool call on behalf of *principal*.

        Args:
            principal : Authenticated Principal from the MCP server.
                        The MCP server is responsible for resolving this
                        from transport-level authentication context.
            params    : Tool call parameters from the agent (untrusted Intent).

        Returns:
            ToolResult with data or denial reasons.
        """
        # Parse operation
        op_str = params.get("operation", "read").lower()
        op_map = {
            "read": Operation.READ,
            "insert": Operation.INSERT,
            "update": Operation.UPDATE,
            "delete": Operation.DELETE,
        }
        operation = op_map.get(op_str, Operation.READ)

        # Build Intent from agent-provided params (untrusted)
        intent = Intent(
            resource=str(params.get("resource", "")),
            operation=operation,
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
                denial_reasons=[str(exc)],
                request_id="",
                evidence_id="",
            )
        return ToolResult(
            allowed=True,
            capability={
                "execution_id": capability.execution_id,
                "resource": capability.resource,
                "operation": capability.operation.value,
                "selected_fields": capability.selected_fields,
                "predicates": capability.filter_constraints(),
                "limit": capability.limit,
                "policy_version": capability.policy_version,
                "expires_at": capability.expires_at.isoformat() if capability.expires_at else None,
                "audience": capability.audience,
            },
            denial_reasons=[],
            request_id=capability.execution_id,
            evidence_id=capability.execution_id,
        )
