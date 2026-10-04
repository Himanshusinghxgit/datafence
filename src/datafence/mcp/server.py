"""
DataFence MCP Server.

Wraps DataFenceBoundary as a Model Context Protocol server that can be
registered with any MCP-compatible agent framework.

Architecture::

    [AI Agent / Claude / GPT-4]
            │  MCP JSON-RPC call (untrusted arguments)
            ▼
    DataFenceMCPServer
            │  resolves principal from authenticated session context
            │  calls DataFenceQueryTool.call(principal, params)
            ▼
    DataFenceBoundary.authorize(principal, intent)
            │  Registry validation → Policy evaluation → Capability issuance
            ▼
    AuthorizedExecution (HMAC-signed) → returned to caller
            │
            ▼  (caller passes to their connector — DataFence does not execute)
    Customer-owned connector
            │
            ▼
    Enterprise data

The MCP server is responsible for:
    1. Authenticating the session (who is calling).
    2. Mapping session identity → Principal (never from the agent's JSON).
    3. Routing tool calls to the correct DataFenceQueryTool.

DataFence is responsible for:
    1. Authorizing what the principal may do.
    2. Generating signed AuthorizedExecution capabilities.
    3. Enforcing row/field policy.

DataFence does NOT execute database operations.

Security note on principal resolution
--------------------------------------
The principal MUST be resolved from transport-level authentication context
(e.g. a session token verified by the application), NOT from the agent's
tool call arguments.  The agent must never be able to choose its own identity.

``principal_resolver`` is REQUIRED.  There is no fallback.  A server without
a configured resolver raises ``TypeError`` at construction time, making the
misconfiguration impossible to miss.

Usage::

    from datafence.mcp.server import DataFenceMCPServer
    from datafence.core.boundary import DataFenceBoundary
    from datafence.core.principal import Principal

    def my_auth_resolver(session_context: dict) -> Principal:
        token = session_context["token"]
        user = verify_token(token)   # application-owned
        return Principal(id=user.id, tenant_id=user.tenant_id)

    boundary = DataFenceBoundary.create(
        policy_engine=engine,
        registry=registry,
        signing_key=signing_key,
    )
    server = DataFenceMCPServer(
        boundary=boundary,
        server_name="my-datafence",
        principal_resolver=my_auth_resolver,
    )
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
    principal_resolver : Callable[[dict], Principal]
        **Required** callable that maps an authenticated session context dict
        to a :class:`~datafence.core.principal.Principal`.

        The context dict is supplied by the transport layer (e.g. extracted
        from a verified JWT, session cookie, or mutual-TLS certificate).
        It must NEVER come from the agent's tool call arguments.

        Raises ``TypeError`` at construction time if not provided.
    """

    def __init__(
        self,
        boundary: DataFenceBoundary,
        server_name: str = "datafence",
        version: str = "1.0.0",
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
            session_context : Authenticated session metadata from the transport
                              layer, used to resolve the Principal.
                              This must NEVER come from agent-controlled JSON.

        Returns:
            MCP-compatible response dict containing the authorization result.
            An allowed response exposes the signed capability metadata only —
            no database rows are returned here.
        """
        if tool_name not in self._tools:
            return self._error_response(f"Unknown tool: {tool_name!r}")

        # Principal must come from authenticated transport context, not arguments.
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
                                "capability": result.capability,
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

        Security note: The ``_session`` field sometimes present in MCP JSON
        is agent-controlled and is intentionally ignored.  Transport adapters
        must supply authenticated context via a separate, trusted channel and
        call ``handle_call_tool`` directly with that context.
        """
        method = request.get("method", "")
        params = request.get("params", {})

        if method == "initialize":
            result = self.handle_initialize()
        elif method == "tools/list":
            result = self.handle_list_tools()
        elif method == "tools/call":
            # Agent-provided _session field is not forwarded.
            # Transport must inject authenticated session_context separately.
            result = self.handle_call_tool(
                tool_name=params.get("name", ""),
                arguments=params.get("arguments", {}),
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
        """
        Resolve the authenticated Principal from transport session context.

        Validates that the resolver returns a proper Principal instance.
        Raises TypeError if an incompatible type is returned.
        """
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
