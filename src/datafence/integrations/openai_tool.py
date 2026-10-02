"""
DataFence OpenAI function-calling adapter.

Exposes a DataFenceBoundary as an OpenAI function/tool so that GPT-4 or
any OpenAI-compatible model can request data access through a properly
authorized boundary.

Architecture::

    OpenAI model
        │  function call: {"name": "datafence_query", "arguments": {...}}
        ▼
    DataFenceOpenAITool.handle_call(principal, arguments_json)
        │  parses JSON → Intent (untrusted)
        ▼
    DataFenceBoundary.authorize(principal, intent)
        │  Registry → Policy → AuthorizedExecution (signed)
        ▼
    JSON response containing the signed capability
        │
        ▼  (caller passes capability to their own connector)
    Customer-owned connector → database

Security invariants:
    - The model controls ``arguments_json`` (untrusted Intent).
    - The host application controls ``principal`` (trusted identity).
    - DataFence issues a signed capability; it does NOT execute the query.
    - The customer's connector receives the capability and executes it.

Usage::

    from datafence.integrations.openai_tool import DataFenceOpenAITool
    from datafence.core.boundary import DataFenceBoundary
    from datafence.core.types import Actor

    # boundary = DataFenceBoundary.create(policy_engine=..., registry=..., signing_key=...)
    tool = DataFenceOpenAITool(boundary)

    # 1. Register the tool spec with the model.
    tools = [tool.openai_tool_spec()]

    # 2. In your message loop, when the model returns a function call:
    result_json = tool.handle_call(
        principal=Actor(id="user:alice", tenant_id="acme"),
        arguments_json=tool_call.function.arguments,
    )

    # 3. The JSON contains the signed capability.
    #    Pass it to your connector:
    #    capability = deserialize_capability(result_json)
    #    my_connector.execute(capability)
"""

from __future__ import annotations

import json
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import Actor, Intent, Operation
from datafence.errors import DataFenceError


class DataFenceOpenAITool:
    """
    OpenAI function-calling adapter for DataFence.

    One instance wraps one DataFenceBoundary.  Attach the tool spec to
    your model calls and route tool call responses through handle_call().
    """

    def __init__(
        self,
        boundary: DataFenceBoundary,
        tool_name: str = "datafence_query",
    ) -> None:
        self.boundary = boundary
        self.tool_name = tool_name

    def openai_tool_spec(self) -> dict[str, Any]:
        """
        Return the tool specification for the OpenAI ``tools=`` parameter.

        Compatible with openai >= 1.0 (and any OpenAI-compatible API).
        """
        return {
            "type": "function",
            "function": {
                "name": self.tool_name,
                "description": (
                    "Request data access through the DataFence authorization boundary. "
                    "Returns a signed authorization capability for the fields and rows "
                    "you are permitted to access. Sensitive fields are never authorized."
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
                            "description": 'Key=value row filters (e.g. {"status": "shipped"}).',
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
        principal: Actor,
        arguments_json: str | dict,
    ) -> str:
        """
        Handle a tool call from the model.

        Calls DataFenceBoundary.authorize() and returns a JSON string
        describing the signed capability.  The caller must pass the
        capability to their own connector for execution.

        Args:
            principal       : Authenticated principal from the application.
            arguments_json  : The ``function.arguments`` string or pre-parsed dict.

        Returns:
            JSON string with the authorization result.
        """
        if isinstance(arguments_json, str):
            args = json.loads(arguments_json)
        else:
            args = arguments_json

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

        return json.dumps(
            {
                "status": "authorized",
                "execution_id": capability.execution_id,
                "resource": capability.resource,
                "operation": capability.operation.value,
                "fields": capability.selected_fields,
                "predicates": capability.filter_constraints(),
                "limit": capability.limit,
                "expires_at": capability.expires_at.isoformat() if capability.expires_at else None,
                "audience": capability.audience,
            }
        )
