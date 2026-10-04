"""
DataFence Anthropic/Claude tool-use adapter.

Returns a portable CapabilityToken so the caller's connector can verify the
authorization independently.  The adapter never executes queries.

Security invariants:
    - Claude controls ``tool_input`` (untrusted Intent).
    - The host application controls ``principal`` (trusted identity).
    - DataFence issues a signed capability; it does NOT execute the query.
    - The CapabilityToken embeds the full HMAC signature for transport.

Usage::

    from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
    from datafence.core.principal import Principal
    import anthropic

    tool = DataFenceAnthropicTool(boundary)
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        tools=[tool.anthropic_tool_spec()],
        messages=[{"role": "user", "content": "Show me my recent orders"}],
    )
    for block in response.content:
        if block.type == "tool_use":
            principal = Principal(id="user:alice", tenant_id="acme")
            result_json = tool.handle_call(principal=principal, tool_input=block.input)
            # result_json["token"] — pass to connector.
"""

from __future__ import annotations

import json
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.capability import CapabilityToken
from datafence.core.principal import Principal
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
                "Request read access to a data resource through the DataFence "
                "authorization boundary. Returns a signed authorization token. "
                "Only authorized fields and rows are permitted."
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
        principal: Principal,
        tool_input: dict[str, Any],
    ) -> str:
        """
        Handle a tool_use block from Claude.

        Args:
            principal  : Authenticated Principal (application responsibility).
            tool_input : The ``input`` dict from the tool_use content block.

        Returns:
            JSON string with ``status`` and either ``token`` (authorized)
            or ``reasons`` (denied).
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

        token = CapabilityToken.encode(capability)
        return json.dumps(
            {
                "status": "authorized",
                "token": token,
                "execution_id": capability.execution_id,
                "resource": capability.resource,
                "operation": capability.operation.value,
                "fields": list(capability.selected_fields),
                "predicates": capability.filter_constraints(),
                "limit": capability.limit,
                "audience": capability.audience,
                "obligations": dict(capability.obligations or {}),
            }
        )
