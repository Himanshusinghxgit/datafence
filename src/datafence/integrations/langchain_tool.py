"""
LangChain integration for DataFence.

Provides LangChain tools with DataFence security enforcement.
"""

from typing import Any, Optional, Type

try:
    from langchain.tools import BaseTool
    from langchain.callbacks.manager import CallbackManagerForToolRun
    from pydantic import BaseModel, Field
except ImportError:
    BaseTool = None
    CallbackManagerForToolRun = None
    BaseModel = object
    Field = None

from datafence.core.engine import DataFence
from datafence.errors import DataFenceError


class DataFenceQueryInput(BaseModel):
    """Input schema for DataFence query tool."""

    resource: str = Field(description="Name of the data resource to query")
    fields: list[str] = Field(
        default=None, description="List of fields to retrieve (optional)"
    )
    filters: dict[str, Any] = Field(
        default_factory=dict, description="Filter conditions as key-value pairs"
    )
    limit: int = Field(default=100, description="Maximum number of rows to return")


class DataFenceTool(BaseTool):
    """
    LangChain tool for querying data with DataFence security.

    This tool allows LangChain agents to query data sources with automatic
    policy enforcement, field restrictions, and tenant isolation.

    Example:
        from langchain.agents import AgentExecutor, create_openai_functions_agent
        from langchain.prompts import ChatPromptTemplate
        from langchain_openai import ChatOpenAI

        fence = DataFence.from_yaml("policy.yaml", connector)
        tool = DataFenceTool(fence=fence, actor={"id": "user:123", "tenant_id": "acme"})

        tools = [tool]
        llm = ChatOpenAI(model="gpt-4")

        agent = create_openai_functions_agent(llm, tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=tools)

        response = agent_executor.invoke({"input": "Show me recent transactions"})
    """

    name: str = "query_data"
    description: str = (
        "Query data from secure data sources with automatic policy enforcement. "
        "Use this tool to retrieve data with field-level and row-level security. "
        "Specify the resource name, optional fields, filters, and limit."
    )
    args_schema: Type[BaseModel] = DataFenceQueryInput

    fence: Any = Field(exclude=True)  # DataFence instance
    actor: dict[str, Any] = Field(exclude=True)  # Actor information
    context: Optional[dict[str, Any]] = Field(default=None, exclude=True)

    class Config:
        """Pydantic config."""

        arbitrary_types_allowed = True

    def _run(
        self,
        resource: str,
        fields: list[str] | None = None,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """
        Execute the tool.

        Args:
            resource: Resource name
            fields: Fields to retrieve
            filters: Filter conditions
            limit: Result limit
            run_manager: Callback manager (optional)

        Returns:
            JSON string with results
        """
        try:
            # Build request
            request_dict = {
                "actor": self.actor,
                "operation": "read",
                "resource": resource,
                "fields": fields,
                "filters": filters or {},
                "limit": limit,
            }

            if self.context:
                request_dict["context"] = self.context

            # Execute through DataFence
            result = self.fence.execute(request_dict)

            if result.verified:
                import json

                return json.dumps(
                    {
                        "success": True,
                        "data": result.data,
                        "row_count": len(result.data),
                    },
                    indent=2,
                )
            else:
                return json.dumps(
                    {
                        "success": False,
                        "error": "Access denied",
                        "reasons": result.decision.reasons,
                    },
                    indent=2,
                )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)}, indent=2)

    async def _arun(
        self,
        resource: str,
        fields: list[str] | None = None,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """
        Async execution (delegates to sync for now).

        Args:
            resource: Resource name
            fields: Fields to retrieve
            filters: Filter conditions
            limit: Result limit
            run_manager: Callback manager (optional)

        Returns:
            JSON string with results
        """
        # For now, delegate to sync version
        # In future, could support async connectors
        return self._run(resource, fields, filters, limit, run_manager)


def create_datafence_tools(
    fence: DataFence, actor: dict[str, Any], context: dict[str, Any] | None = None
) -> list[Any]:
    """
    Create LangChain tools from DataFence policy.

    Creates one tool per resource in the policy for more specific tool descriptions.

    Args:
        fence: DataFence instance
        actor: Actor information
        context: Additional context

    Returns:
        List of LangChain tools

    Example:
        tools = create_datafence_tools(
            fence,
            actor={"id": "user:123", "tenant_id": "acme"}
        )
    """
    if BaseTool is None:
        raise ImportError(
            "langchain required. Install with: pip install langchain"
        )

    tools = []

    # Get all resources from policy
    if not fence.policy or not fence.policy.resources:
        # Create generic tool
        tools.append(DataFenceTool(fence=fence, actor=actor, context=context))
        return tools

    # Create specific tool for each resource
    for resource_name, resource_config in fence.policy.resources.items():
        allowed_ops = resource_config.operations.get("allow", [])

        if "read" in allowed_ops:
            # Get allowed fields
            allowed_fields = resource_config.fields.get("allow", [])

            # Create custom input schema for this resource
            class ResourceQueryInput(BaseModel):
                """Input schema for resource query."""

                fields: list[str] = Field(
                    default=None,
                    description=f"Fields to retrieve. Allowed: {', '.join(allowed_fields)}",
                )
                filters: dict[str, Any] = Field(
                    default_factory=dict,
                    description="Filter conditions as key-value pairs",
                )
                limit: int = Field(
                    default=100, description="Maximum number of rows to return"
                )

            # Create resource-specific tool
            class ResourceTool(BaseTool):
                """Tool for specific resource."""

                name: str = f"query_{resource_name}"
                description: str = (
                    f"Query {resource_name} data with security enforcement. "
                    f"Allowed fields: {', '.join(allowed_fields)}. "
                    f"Use filters to narrow results."
                )
                args_schema: Type[BaseModel] = ResourceQueryInput

                fence: Any = Field(exclude=True)
                actor: dict[str, Any] = Field(exclude=True)
                context: Optional[dict[str, Any]] = Field(default=None, exclude=True)
                resource_name: str = Field(exclude=True)

                class Config:
                    """Pydantic config."""

                    arbitrary_types_allowed = True

                def _run(
                    self,
                    fields: list[str] | None = None,
                    filters: dict[str, Any] | None = None,
                    limit: int = 100,
                    run_manager: Optional[CallbackManagerForToolRun] = None,
                ) -> str:
                    """Execute query."""
                    import json

                    try:
                        request_dict = {
                            "actor": self.actor,
                            "operation": "read",
                            "resource": self.resource_name,
                            "fields": fields,
                            "filters": filters or {},
                            "limit": limit,
                        }

                        if self.context:
                            request_dict["context"] = self.context

                        result = self.fence.execute(request_dict)

                        if result.verified:
                            return json.dumps(
                                {
                                    "success": True,
                                    "data": result.data,
                                    "row_count": len(result.data),
                                },
                                indent=2,
                            )
                        else:
                            return json.dumps(
                                {
                                    "success": False,
                                    "error": "Access denied",
                                    "reasons": result.decision.reasons,
                                },
                                indent=2,
                            )

                    except Exception as e:
                        return json.dumps({"success": False, "error": str(e)}, indent=2)

                async def _arun(
                    self,
                    fields: list[str] | None = None,
                    filters: dict[str, Any] | None = None,
                    limit: int = 100,
                    run_manager: Optional[CallbackManagerForToolRun] = None,
                ) -> str:
                    """Async execution."""
                    return self._run(fields, filters, limit, run_manager)

            tool = ResourceTool(
                fence=fence,
                actor=actor,
                context=context,
                resource_name=resource_name,
            )

            tools.append(tool)

    return tools
