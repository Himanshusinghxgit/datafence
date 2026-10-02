"""
DataFence MCP Server (Phase 6).

Wraps DataFenceBoundary as a Model Context Protocol server that can be
registered with any MCP-compatible agent framework.

Architecture::

    [AI Agent / Claude / GPT-4]
            │  MCP JSON-RPC call
            ▼
    DataFenceMCPServer
            │  resolves principal from session context
            │  calls DataFenceQueryTool.call(principal, params)
            ▼
    DataFenceBoundary
            │  policy → capability → connector → validation
            ▼
    ToolResult → JSON response to agent

The MCP server is responsible for:
    1. Authenticating the session (who is calling)
    2. Mapping session identity → Principal
    3. Routing tool calls to the correct DataFenceQueryTool

DataFence is responsible for:
    1. Authorizing what the principal may do
    2. Generating signed capabilities
    3. Enforcing row/field policy
    4. Returning verified results + evidence

Usage (standalone HTTP-based MCP server)::

    from datafence.mcp.server import DataFenceMCPServer
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

    server = DataFenceMCPServer(
        boundary=boundary,
        server_name="banking-datafence",
        version="0.6.0",
    )

    # With a MCP HTTP transport:
    # server.run(host="0.0.0.0", port=8080)

    # Or get the callable for embedding in another framework:
    # handler = server.as_handler()
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import Actor
from datafence.mcp.tool import DataFenceQueryTool, ToolResult

logger = logging.getLogger(__name__)


class DataFenceMCPServer:
    """
    MCP server exposing one or more DataFence query tools.

    This class is framework-agnostic.  It implements the core dispatch
    logic (list_tools / call_tool) and can be adapted to any transport
    (HTTP, stdio, WebSocket) by wrapping the ``handle_request`` method.

    Parameters
    ----------
    boundary : DataFenceBoundary
        The configured security boundary.
    server_name : str
        MCP server name advertised to clients.
    version : str
        Server version string.
    principal_resolver : Callable
        Required callable ``(authenticated_context: dict) -> Actor``. The
        agent's JSON arguments and request metadata are never a principal.
    """

    def __init__(
        self,
        boundary: DataFenceBoundary,
        server_name: str = "datafence",
        version: str = "0.5.0",
        principal_resolver: Callable[[dict], Actor] | None = None,
    ) -> None:
        self.server_name = server_name
        self.version = version
        # Direct callers must provide authenticated context. The legacy
        # resolver below exists only for the pre-v1 Python API; raw MCP JSON
        # never forwards its agent-controlled _session field.
        self._principal_resolver = principal_resolver or self._legacy_direct_resolver

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
            arguments       : Tool arguments from the agent.
            session_context : Session metadata used to resolve the principal.

        Returns:
            MCP-compatible response dict.
        """
        if tool_name not in self._tools:
            return self._error_response(f"Unknown tool: {tool_name!r}")

        # Resolve principal
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
                                "status": "allowed",
                                "row_count": result.row_count,
                                "data": result.data,
                                "request_id": result.request_id,
                                "evidence_id": result.evidence_id,
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

        This is the main entry point for transport adapters.
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
                # _session is agent-controlled JSON and is intentionally not
                # trusted. Transport adapters must call handle_call_tool with
                # an authenticated context obtained outside the MCP request.
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

    def _resolve_principal(self, session_context: dict) -> Actor:
        """
        Resolve the authenticated principal from session context.

        The context must be supplied by a trusted transport adapter.
        """
        principal = self._principal_resolver(session_context)
        if not isinstance(principal, Actor):
            raise TypeError("principal_resolver must return Actor")
        return principal

    @staticmethod
    def _legacy_direct_resolver(session_context: dict) -> Actor:
        """Compatibility for direct Python callers; not used by raw MCP."""
        principal_data = session_context.get("principal")
        if not principal_data:
            raise ValueError("authenticated principal context required")
        return Actor(id=principal_data["id"], tenant_id=principal_data["tenant_id"],
                     metadata=principal_data.get("metadata", {}))

    @staticmethod
    def _error_response(message: str) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": json.dumps({"error": message})}],
            "isError": True,
        }
