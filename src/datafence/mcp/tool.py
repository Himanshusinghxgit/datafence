"""
DataFence MCP Tool (Phase 6).

Exposes a DataFenceBoundary as an MCP tool so AI agents can query
data through a properly authorized execution boundary.

Architecture::

    AI Agent
        │  MCP tool call: {"resource": "transactions", "fields": [...], ...}
        ▼
    DataFenceQueryTool.call()
        │  constructs Intent
        ▼
    DataFenceBoundary.execute(principal, intent)
        │  policy → signed capability → connector → validation
        ▼
    ToolResult (rows | denial reason)

The tool NEVER passes raw SQL to the boundary.  It converts the tool
call parameters into a typed Intent.

Security invariants:
    - The Principal is provided by the MCP server (not the agent).
    - The agent controls: resource, fields, filters (untrusted — Intent).
    - The policy controls: authorised fields, enforced row filters, limits.
    - The agent cannot escalate beyond what the policy allows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import Actor, AllowedRequest, Intent, Operation


@dataclass
class ToolResult:
    """Result returned to the MCP client / agent."""

    allowed: bool
    data: list[dict[str, Any]]
    row_count: int
    denial_reasons: list[str]
    request_id: str
    evidence_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "data": self.data,
            "row_count": self.row_count,
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
        principal: Actor,
        params: dict[str, Any],
    ) -> ToolResult:
        """
        Execute a tool call on behalf of *principal*.

        Args:
            principal : Authenticated principal from the MCP server.
                        The MCP server is responsible for authenticating
                        the principal before calling this method.
            params    : Tool call parameters from the agent.

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

        # Execute through boundary
        result = self.boundary.execute(principal, intent)

        if isinstance(result, AllowedRequest):
            return ToolResult(
                allowed=True,
                data=result.execution_result.data,
                row_count=result.execution_result.row_count,
                denial_reasons=[],
                request_id=result.request_id,
                evidence_id=result.evidence.execution_id,
            )
        else:
            return ToolResult(
                allowed=False,
                data=[],
                row_count=0,
                denial_reasons=list(result.decision.reasons),
                request_id=result.request_id,
                evidence_id=result.evidence.execution_id,
            )
