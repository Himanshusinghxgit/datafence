"""
DataFence Anthropic/Claude tool-use adapter.

Exposes a DataFenceBoundary as a Claude tool so Claude models can request
data access through a properly authorized boundary.

Architecture::

    Claude model
        │  tool_use block: {"name": "datafence_query", "input": {...}}
        ▼
    DataFenceAnthropicTool.handle_call(principal, tool_input)
        │  constructs Intent (untrusted)
        ▼
    DataFenceBoundary.authorize(principal, intent)
        │  Registry → Policy → AuthorizedExecution (signed)
        ▼
    JSON tool_result describing the capability
        │
        ▼  (caller passes capability to their own connector)
    Customer-owned connector → database

Security invariants:
    - Claude controls ``tool_input`` (untrusted Intent).
    - The host application controls ``principal`` (trusted identity).
    - DataFence issues a signed capability; it does NOT execute the query.
    - The customer's connector receives the capability and executes it.

Usage::

    from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
    from datafence.core.types import Actor
    import anthropic

    # boundary = DataFenceBoundary.create(policy_engine=..., registry=..., signing_key=...)
    tool = DataFenceAnthropicTool(boundary)

    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        tools=[tool.anthropic_tool_spec()],
        messages=[{"role": "user", "content": "Show me my recent orders"}],
    )

    # Handle tool_use blocks in the response
    for block in response.content:
        if block.type == "tool_use":
            result_json = tool.handle_call(
                principal=Actor(id="user:alice", tenant_id="acme"),
                tool_input=block.input,
            )
            # Pass the capability to your connector.
            # my_connector.execute(deserialize_capability(result_json))
"""

from __future__ import annotations

import json
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.principal import Principal as Actor
from datafence.core.types import Intent, Operation
from datafence.errors import DataFenceError


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
                "Request data access through the DataFence authorization boundary. "
                "Only authorized fields and rows are returned. "
                "Sensitive fields are never accessible."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "resource": {
                        "type": "string",
                        "description": "Data resource to access (e.g. 'orders').",
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

        Calls DataFenceBoundary.authorize() and returns a JSON string
        describing the signed capability.

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

        try:
            capability = self.boundary.authorize(principal, intent)
        except DataFenceError as exc:
            return json.dumps({"status": "denied", "reasons": [str(exc)]})

        return json.dumps(
            {
                "status": "authorized",
                "execution_id": capability.execution_id,
                "resource": capability.resource,
                "operation": capability.operation.value,
                "fields": capability.selected_fields,
                "predicates": capability.filter_constraints(),
                "limit": capability.limit,
                "audience": capability.audience,
            }
        )
