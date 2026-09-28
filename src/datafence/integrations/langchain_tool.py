"""
DataFence LangChain tool adapter (Phase 7).

Wraps a DataFenceBoundary as a LangChain BaseTool so it can be used inside
LangChain agents, chains, and tool executors.

Architecture::

    LangChain Agent
        │  tool.run("{'resource': 'transactions', 'fields': [...]}")
        ▼
    DataFenceLangChainTool._run(query_str)
        │  parses JSON → Intent
        ▼
    DataFenceBoundary.execute(principal, intent)
        │  policy → capability → connector → validation
        ▼
    str (JSON result or denial)

Security invariant:
    The LangChain agent controls the query string (untrusted).
    The host application provides the principal at construction time.

Usage::

    from datafence.integrations.langchain_tool import DataFenceLangChainTool
    from datafence.core.types import Actor

    principal = Actor(id="user:alice", tenant_id="acme")
    tool = DataFenceLangChainTool(boundary=boundary, principal=principal)

    # Add to LangChain agent
    agent = initialize_agent(
        tools=[tool],
        llm=llm,
        agent=AgentType.OPENAI_FUNCTIONS,
    )
    agent.run("Show me recent transactions for my account")

Note: LangChain is an optional dependency.
    pip install 'datafence[integrations]'
"""

from __future__ import annotations

import json
from typing import Any, Optional, Type

from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import Actor, AllowedRequest, Intent, Operation


class DataFenceLangChainTool:
    """
    LangChain-compatible tool wrapping DataFenceBoundary.

    Inherits from LangChain BaseTool when available; otherwise provides a
    compatible interface that works with agent frameworks that duck-type tools.

    The principal is bound at construction time — the agent cannot change it.
    """

    name: str = "datafence_query"
    description: str = (
        "Query data through the DataFence authorization boundary. "
        "Input must be a JSON string with 'resource' (required), and optionally "
        "'fields' (list), 'filters' (dict), and 'limit' (int). "
        "Example: {\"resource\": \"transactions\", \"fields\": [\"merchant\", \"amount\"], \"limit\": 5}"
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

        # Try to inherit from LangChain BaseTool if available
        self._langchain_available = False
        try:
            from langchain.tools import BaseTool as LCBaseTool  # type: ignore[import]
            self._langchain_available = True
        except ImportError:
            pass

    def run(self, query: str) -> str:
        """LangChain tool interface: accepts a string, returns a string."""
        return self._run(query)

    def _run(self, query: str, **_: Any) -> str:
        """
        Execute the tool.

        Args:
            query : JSON string with resource, fields, filters, limit.

        Returns:
            JSON string with results or denial reason.
        """
        try:
            args = json.loads(query) if isinstance(query, str) else query
        except json.JSONDecodeError:
            # Treat bare string as a resource name
            args = {"resource": query}

        intent = Intent(
            resource=str(args.get("resource", "")),
            operation=Operation.READ,
            fields=args.get("fields") or None,
            filters=args.get("filters") or {},
            limit=int(args.get("limit") or 10),
        )

        result = self.boundary.execute(self.principal, intent)

        if isinstance(result, AllowedRequest):
            return json.dumps({
                "status": "allowed",
                "row_count": result.execution_result.row_count,
                "data": result.execution_result.data,
                "fields": result.execution_plan.selected_fields,
            })
        return json.dumps({
            "status": "denied",
            "reasons": list(result.decision.reasons),
        })

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
