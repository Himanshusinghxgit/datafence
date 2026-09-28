"""
DataFence Anthropic/Claude tool-use adapter (Phase 7).

Exposes a DataFenceBoundary as a Claude tool so Claude models can query
data through a properly authorized execution boundary.

Architecture::

    Claude model
        │  tool_use block: {"name": "datafence_query", "input": {...}}
        ▼
    DataFenceAnthropicTool.handle_call(principal, tool_input)
        │  constructs Intent
        ▼
    DataFenceBoundary.execute(principal, intent)
        │  policy → capability → connector → validation
        ▼
    tool_result block (str JSON)

Usage::

    from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
    import anthropic

    boundary = DataFenceBoundary.create(...)
    tool = DataFenceAnthropicTool(boundary)

    client = anthropic.Anthropic()

    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        tools=[tool.anthropic_tool_spec()],
        messages=[{"role": "user", "content": "Show me recent transactions"}],
    )

    # Handle tool use in response
    for block in response.content:
        if block.type == "tool_use":
            result = tool.handle_call(principal, block.input)
            # Continue conversation with tool_result...
"""

from __future__ import annotations

import json
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import Actor, AllowedRequest, Intent, Operation


class DataFenceAnthropicTool:
    """Anthropic/Claude tool-use adapter for DataFence."""

    def __init__(
        self,
        boundary: DataFenceBoundary,
        tool_name: str = "datafence_query",
    ) -> None:
        self.boundary = boundary
        self.tool_name = tool_name

    def anthropic_tool_spec(self) -> dict[str, Any]:
        """Return the tool spec for the Anthropic ``tools=`` parameter."""
        return {
            "name": self.tool_name,
            "description": (
                "Query data through the DataFence authorization boundary. "
                "Only authorized fields and rows are returned. "
                "Sensitive fields (card numbers, SSNs) are never accessible."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "resource": {
                        "type": "string",
                        "description": "Data resource to query (e.g. 'transactions').",
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Fields to return. Omit for all authorised fields.",
                    },
                    "filters": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Key=value filters to apply.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum rows (bounded by policy).",
                        "default": 10,
                    },
                },
                "required": ["resource"],
            },
        }

    def handle_call(
        self,
        principal: Actor,
        tool_input: dict[str, Any],
    ) -> str:
        """
        Handle a tool_use block from Claude.

        Args:
            principal  : Authenticated principal (application responsibility).
            tool_input : The ``input`` dict from the tool_use content block.

        Returns:
            JSON string for the tool_result content.
        """
        intent = Intent(
            resource=str(tool_input.get("resource", "")),
            operation=Operation.READ,
            fields=tool_input.get("fields") or None,
            filters=tool_input.get("filters") or {},
            limit=int(tool_input.get("limit") or 10),
        )

        result = self.boundary.execute(principal, intent)

        if isinstance(result, AllowedRequest):
            return json.dumps({
                "status": "allowed",
                "row_count": result.execution_result.row_count,
                "data": result.execution_result.data,
                "fields": result.execution_plan.selected_fields,
                "evidence_id": result.evidence.execution_id,
            })
        return json.dumps({
            "status": "denied",
            "reasons": list(result.decision.reasons),
        })
