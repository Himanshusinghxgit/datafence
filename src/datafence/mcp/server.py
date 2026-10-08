"""
DataFence MCP Server.

Framework-agnostic MCP request handler.  Resolves the Principal from the
transport-layer session context (never from agent JSON) and returns a
portable CapabilityToken in the tool response.

Architecture::

    [AI Agent]
        │  MCP JSON-RPC call (untrusted arguments)
        ▼
    DataFenceMCPServer.handle_call_tool(tool_name, arguments, session_context)
        │  session_context comes from the transport layer — never from arguments
        │  principal_resolver(session_context) → Principal (required)
        ▼
    DataFenceQueryTool.call(principal, params)
        ▼
    DataFenceBoundary.authorize(principal, intent)
        ▼
    CapabilityToken  (signed, portable) → returned in MCP response
        │
        ▼  caller passes token to their connector
    Customer-owned connector → enterprise data

Security notes
--------------
``principal_resolver`` is REQUIRED.  Omitting it raises ``TypeError`` at
construction time.

The agent's JSON arguments are NEVER used as identity.  The ``_session``
field sometimes embedded in MCP requests is intentionally ignored by
``handle_request()``.  Transport adapters must inject authenticated context
via ``session_context`` in their own ``handle_call_tool()`` calls.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.principal import Principal
from datafence.mcp.tool import DataFenceQueryTool, ToolResult

logger = logging.getLogger(__name__)


class DataFenceMCPServer:
    """
    MCP server exposing DataFence query tools.

    Parameters
    ----------
    boundary : DataFenceBoundary
        The configured security boundary.
    server_name : str
        MCP server name advertised to clients.
    version : str
        Server version string.
    principal_resolver : Callable[[dict], Principal]
        **Required** callable mapping authenticated session context → Principal.
        Raises ``TypeError`` at construction if omitted.
    """

    def __init__(
        self,
        boundary: DataFenceBoundary,
        server_name: str = "datafence",
        version: str = "0.1.0",
        principal_resolver: Callable[[dict], Principal] | None = None,
    ) -> None:
        if principal_resolver is None:
            raise TypeError(
                "DataFenceMCPServer requires a principal_resolver. "
                "Provide a callable(session_context: dict) -> Principal "
                "that resolves identity from your authenticated transport context. "
                "The agent's JSON arguments must never be the source of identity."
            )
        self.server_name = server_name
        self.version = version
        self._principal_resolver: Callable[[dict], Principal] = principal_resolver

        self._query_tool = DataFenceQueryTool(boundary=boundary)
        self._tools: dict[str, DataFenceQueryTool] = {self._query_tool.tool_name: self._query_tool}

    def register_tool(self, tool: DataFenceQueryTool) -> None:
        """Register an additional DataFenceQueryTool under its tool_name."""
        self._tools[tool.tool_name] = tool

    # ------------------------------------------------------------------
    # MCP protocol handlers
    # ------------------------------------------------------------------

    def handle_initialize(self) -> dict[str, Any]:
        """Handle MCP initialize request."""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": self.server_name, "version": self.version},
        }

    def handle_list_tools(self) -> dict[str, Any]:
        """Handle MCP tools/list request."""
        return {"tools": [tool.schema() for tool in self._tools.values()]}

    def handle_call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Handle MCP tools/call request.

        Args:
            tool_name       : Name of the tool to invoke.
            arguments       : Tool arguments from the agent (untrusted Intent).
            session_context : Authenticated session metadata from the transport layer.
                              This must NEVER come from agent-controlled JSON.

        Returns:
            MCP-compatible response dict.  On success, ``content[0]["text"]``
            contains a JSON object with ``status``, ``token`` (the portable
            CapabilityToken), ``capability`` metadata, and ``request_id``.
            DataFence does NOT return database rows.
        """
        if tool_name not in self._tools:
            return self._error_response(f"Unknown tool: {tool_name!r}")

        # Principal MUST come from authenticated transport context, not arguments.
        try:
            principal = self._resolve_principal(session_context or {})
        except Exception as exc:
            logger.warning("Principal resolution failed: %s", exc)
            return self._error_response(f"Authentication required: {exc}")

        tool = self._tools[tool_name]
        result: ToolResult = tool.call(principal, arguments)

        if result.allowed:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "authorized",
                                "token": result.token,
                                "capability": result.capability,
                                "request_id": result.request_id,
                            }
                        ),
                    }
                ]
            }
        else:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "denied",
                                "reasons": result.denial_reasons,
                                "request_id": result.request_id,
                            }
                        ),
                    }
                ],
                "isError": True,
            }

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Dispatch a raw MCP JSON-RPC request dict.

        Security: the agent-provided ``_session`` field in ``params`` is
        intentionally NOT forwarded to ``handle_call_tool``.  Transport
        adapters must supply authenticated context via a separate channel.
        """
        method = request.get("method", "")
        params = request.get("params", {})

        if method == "initialize":
            result = self.handle_initialize()
        elif method == "tools/list":
            result = self.handle_list_tools()
        elif method == "tools/call":
            result = self.handle_call_tool(
                tool_name=params.get("name", ""),
                arguments=params.get("arguments", {}),
                # _session field from agent JSON is intentionally not forwarded.
                session_context=None,
            )
        else:
            result = self._error_response(f"Unknown method: {method!r}")

        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": result,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_principal(self, session_context: dict) -> Principal:
        """Resolve the authenticated Principal from transport session context."""
        principal = self._principal_resolver(session_context)
        if not isinstance(principal, Principal):
            raise TypeError(
                f"principal_resolver must return Principal, got {type(principal).__name__!r}"
            )
        return principal

    @staticmethod
    def _error_response(message: str) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": json.dumps({"error": message})}],
            "isError": True,
        }
