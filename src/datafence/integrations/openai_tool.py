"""
DataFence OpenAI Function-Calling adapter (Phase 7).

Exposes a DataFenceBoundary as an OpenAI function/tool so that GPT-4 or
any OpenAI-compatible model can query data through a properly authorized
execution boundary.

Architecture::

    OpenAI model
        │  function call: {"name": "datafence_query", "arguments": {...}}
        ▼
    DataFenceOpenAITool.handle_call(principal, arguments_json)
        │  parses JSON → Intent
        ▼
    DataFenceBoundary.execute(principal, intent)
        │  policy → capability → connector → validation
        ▼
    OpenAI tool result (str JSON)

Security invariant:
    The model controls the arguments (untrusted Intent).
    The host application controls the principal (trusted identity).

Usage::

    from datafence.integrations.openai_tool import DataFenceOpenAITool
    from datafence.core.boundary import DataFenceBoundary
    from datafence.core.policy import create_banking_policy
    from datafence.connectors.sqlite_connector import create_demo_database

    policy_engine = create_banking_policy()
    boundary = DataFenceBoundary.create(
        policy_engine=policy_engine,
        connector_factory=create_demo_database,
        registry=policy_engine.registry,
        database_path="/data/banking.db",
    )
    tool = DataFenceOpenAITool(boundary)

    # 1. Register with the model
    tools = [tool.openai_tool_spec()]

    # 2. In your message loop, handle tool calls:
    result = tool.handle_call(
        principal=Actor(id="user:alice", tenant_id="acme"),
        arguments_json=tool_call.function.arguments,
    )
    # Return result to model as a tool message
"""

from __future__ import annotations

import json
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import Actor, AllowedRequest, Intent, Operation


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
                    "Query data through the DataFence authorization boundary. "
                    "Returns only the fields and rows you are authorized to access. "
                    "Never returns sensitive fields like card_number or SSN."
                ),
                "parameters": {
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
                            "description": 'Key=value row filters (e.g. {"merchant": "Amazon"}).',
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

        Args:
            principal       : Authenticated principal from the application.
            arguments_json  : The ``function.arguments`` string from the
                              OpenAI tool call (or a pre-parsed dict).

        Returns:
            JSON string to return as the tool message content.
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

        result = self.boundary.execute(principal, intent)

        if isinstance(result, AllowedRequest):
            return json.dumps(
                {
                    "status": "allowed",
                    "row_count": result.execution_result.row_count,
                    "data": result.execution_result.data,
                    "fields": result.execution_plan.selected_fields,
                    "evidence_id": result.evidence.execution_id,
                }
            )
        else:
            return json.dumps(
                {
                    "status": "denied",
                    "reasons": list(result.decision.reasons),
                    "request_id": result.request_id,
                }
            )
