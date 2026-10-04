"""
DataFence OpenAI function-calling adapter.

Returns a portable CapabilityToken so the caller's connector can verify the
authorization independently.  The adapter never executes queries.

Security invariants:
    - The Principal is provided by the caller (your app auth layer).
    - The model controls arguments_json (untrusted Intent only).
    - DataFence issues a signed capability; it does NOT execute the query.
    - The CapabilityToken embeds the full HMAC signature for transport.

Usage::

    from datafence.integrations.openai_tool import DataFenceOpenAITool
    from datafence.core.principal import Principal

    tool = DataFenceOpenAITool(boundary)
    principal = Principal(id="user:alice", tenant_id="acme")  # from YOUR auth

    result_json = tool.handle_call(
        principal=principal,
        arguments_json=tool_call.function.arguments,
    )
    # result_json contains "token" — pass it to your connector.
"""

from __future__ import annotations

import json
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.capability import CapabilityToken
from datafence.core.principal import Principal
from datafence.core.types import Intent, Operation
from datafence.errors import DataFenceError


class DataFenceOpenAITool:
    """OpenAI function-calling adapter for DataFence."""

    def __init__(
        self,
        boundary: DataFenceBoundary,
        tool_name: str = "datafence_query",
    ) -> None:
        self.boundary = boundary
        self.tool_name = tool_name

    def openai_tool_spec(self) -> dict[str, Any]:
        """Return the tool specification for the OpenAI ``tools=`` parameter."""
        return {
            "type": "function",
            "function": {
                "name": self.tool_name,
                "description": (
                    "Request read access to a data resource through the DataFence "
                    "authorization boundary. Returns a signed authorization token. "
                    "Only authorized fields and rows are permitted."
                ),
                "parameters": {
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
                            "description": "Key=value row filters.",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max rows (bounded by policy).",
                            "default": 10,
                        },
                    },
                    "required": ["resource"],
                },
            },
        }

    def handle_call(
        self,
        principal: Principal,
        arguments_json: str | dict[str, Any],
    ) -> str:
        """
        Handle a tool call from the model.

        Args:
            principal       : Authenticated Principal from the application.
            arguments_json  : The ``function.arguments`` string or parsed dict.

        Returns:
            JSON string containing either:
            - ``{"status": "authorized", "token": "...", ...}`` with the
              portable signed CapabilityToken for transport to the connector.
            - ``{"status": "denied", "reasons": [...]}`` on denial.
        """
        if isinstance(arguments_json, str):
            args = json.loads(arguments_json)
        else:
            args = dict(arguments_json)

        intent = Intent(
            resource=str(args.get("resource", "")),
            operation=Operation.READ,
            fields=args.get("fields") or None,
            filters=args.get("filters") or {},
            limit=int(args.get("limit") or 10),
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
                "expires_at": (
                    capability.expires_at.isoformat() if capability.expires_at else None
                ),
                "audience": capability.audience,
                "obligations": dict(capability.obligations or {}),
            }
        )
