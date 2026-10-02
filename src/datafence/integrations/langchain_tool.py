"""
DataFence LangChain tool adapter.

Wraps a DataFenceBoundary as a LangChain BaseTool so it can be used inside
LangChain agents, chains, and tool executors.

Architecture::

    LangChain Agent
        │  tool.run('{"resource": "orders", "fields": [...]}')
        ▼
    DataFenceLangChainTool._run(query_str)
        │  parses JSON → Intent (untrusted)
        ▼
    DataFenceBoundary.authorize(principal, intent)
        │  Registry → Policy → AuthorizedExecution (signed)
        ▼
    JSON string describing the signed capability
        │
        ▼  (caller passes capability to their own connector)
    Customer-owned connector → database

Security invariants:
    - The LangChain agent controls the query string (untrusted Intent).
    - The host application provides the principal at construction time.
    - DataFence issues a signed capability; it does NOT execute the query.
    - The customer's connector receives the capability and executes it.

Usage::

    from datafence.integrations.langchain_tool import DataFenceLangChainTool
    from datafence.core.types import Actor

    # boundary = DataFenceBoundary.create(policy_engine=..., registry=..., signing_key=...)
    principal = Actor(id="user:alice", tenant_id="acme")
    tool = DataFenceLangChainTool(boundary=boundary, principal=principal)

    # Use directly:
    result_json = tool.run('{"resource": "orders", "fields": ["id", "total"], "limit": 5}')

    # Or add to a LangChain agent:
    from langchain.agents import initialize_agent, AgentType
    agent = initialize_agent(tools=[tool.as_langchain_tool()], llm=llm,
                             agent=AgentType.OPENAI_FUNCTIONS)
    agent.run("Show me my recent orders")

Note: LangChain is an optional dependency.
    pip install 'datafence[integrations]'
"""

from __future__ import annotations

import json
from typing import Any

from datafence.core.boundary import DataFenceBoundary
from datafence.core.principal import Principal as Actor
from datafence.core.types import Intent, Operation
from datafence.errors import DataFenceError


class DataFenceLangChainTool:
    """
    LangChain-compatible tool wrapping DataFenceBoundary.

    Inherits from LangChain BaseTool when available; otherwise provides a
    compatible interface that works with agent frameworks that duck-type tools.

    The principal is bound at construction time — the agent cannot change it.
    """

    name: str = "datafence_query"
    description: str = (
        "Request data access through the DataFence authorization boundary. "
        "Input must be a JSON string with 'resource' (required), and optionally "
        "'fields' (list), 'filters' (dict), and 'limit' (int). "
        'Example: {"resource": "orders", "fields": ["id", "total"], "limit": 5}'
    )

    def __init__(
        self,
        boundary: DataFenceBoundary,
        principal: Actor,
        tool_name: str = "datafence_query",
    ) -> None:
        self.boundary = boundary
        self.principal = principal
        self.name = tool_name

        self._langchain_available = False
        try:
            import importlib.util
            self._langchain_available = importlib.util.find_spec("langchain.tools") is not None
        except (ImportError, ValueError):
            self._langchain_available = False

    def run(self, query: str) -> str:
        """LangChain tool interface: accepts a string, returns a string."""
        return self._run(query)

    def _run(self, query: str, **_: Any) -> str:
        """
        Authorize a data access request and return a JSON capability.

        Args:
            query : JSON string with resource, fields, filters, limit.

        Returns:
            JSON string with the authorization result.
        """
        try:
            args = json.loads(query) if isinstance(query, str) else query
        except json.JSONDecodeError:
            args = {"resource": query}

        intent = Intent(
            resource=str(args.get("resource", "")),
            operation=Operation.READ,
            fields=args.get("fields") or None,
            filters=args.get("filters") or {},
            limit=int(args.get("limit") or 10),
        )

        try:
            capability = self.boundary.authorize(self.principal, intent)
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
            }
        )

    async def _arun(self, query: str, **kwargs: Any) -> str:
        """Async interface (delegates to sync)."""
        return self._run(query, **kwargs)

    def as_langchain_tool(self) -> Any:
        """
        Return a proper LangChain BaseTool instance if LangChain is installed.

        Raises ImportError if langchain is not available.
        """
        try:
            from langchain.tools import BaseTool  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "LangChain is required. Install with: pip install 'datafence[integrations]'"
            ) from exc

        boundary = self.boundary
        principal = self.principal
        tool_name = self.name

        class _Tool(BaseTool):
            name = tool_name
            description = DataFenceLangChainTool.description

            def _run(self, query: str, **kw: Any) -> str:  # type: ignore[override]
                return DataFenceLangChainTool(boundary, principal, tool_name)._run(query)

            async def _arun(self, query: str, **kw: Any) -> str:  # type: ignore[override]
                return self._run(query)

        return _Tool()
