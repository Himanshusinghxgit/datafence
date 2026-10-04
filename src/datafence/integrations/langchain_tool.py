"""
DataFence LangChain tool adapter.

Returns a portable CapabilityToken so the caller's connector can verify the
authorization independently.  The adapter never executes queries.

Security invariants:
    - The Principal is bound at construction time — the agent cannot change it.
    - The LangChain agent controls the query string (untrusted Intent only).
    - DataFence issues a signed capability; it does NOT execute the query.
    - The CapabilityToken embeds the full HMAC signature for transport.

Usage::

    from datafence.integrations.langchain_tool import DataFenceLangChainTool
    from datafence.core.principal import Principal

    principal = Principal(id="user:alice", tenant_id="acme")
    tool = DataFenceLangChainTool(boundary=boundary, principal=principal)

    result_json = tool.run('{"resource": "orders", "fields": ["id", "total"], "limit": 5}')
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


class DataFenceLangChainTool:
    """
    LangChain-compatible tool wrapping DataFenceBoundary.

    The Principal is bound at construction time — the agent cannot change it.
    """

    name: str = "datafence_query"
    description: str = (
        "Request read access to a data resource through the DataFence authorization boundary. "
        "Input must be a JSON string with 'resource' (required), and optionally "
        "'fields' (list), 'filters' (dict), and 'limit' (int). "
        'Example: {"resource": "orders", "fields": ["id", "total"], "limit": 5}. '
        "Returns a signed authorization token; does NOT return data rows."
    )

    def __init__(
        self,
        boundary: DataFenceBoundary,
        principal: Principal,
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
        Authorize a data access request and return a JSON capability token.

        Args:
            query : JSON string with resource, fields, filters, limit.

        Returns:
            JSON string with the authorization result including the capability token.
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
                "obligations": dict(capability.obligations or {}),
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
