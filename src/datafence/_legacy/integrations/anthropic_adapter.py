"""
Anthropic Claude adapter for DataFence.

Converts DataFence policies into Claude tool schemas and handles execution.
"""

import json
from typing import Any, Callable

try:
    import anthropic
except ImportError:
    anthropic = None

from datafence.core.engine import DataFence
from datafence.core.request import Operation
from datafence.errors import DataFenceError


class ClaudeAdapter:
    """
    Adapter for Anthropic Claude tool use with DataFence security.

    Converts DataFence policies to Claude tool schemas and enforces
    security policies when tools are called.

    Example:
        fence = DataFence.from_yaml("policy.yaml", connector)
        adapter = ClaudeAdapter(fence)

        # Get tool schemas for Claude
        tools = adapter.get_tools()

        # Call Claude with tools
        client = anthropic.Anthropic()
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            tools=tools,
            messages=[{"role": "user", "content": "Show me transactions"}]
        )

        # Execute tool use through DataFence
        if response.stop_reason == "tool_use":
            for block in response.content:
                if block.type == "tool_use":
                    result = adapter.execute_tool(
                        block.name,
                        block.input,
                        actor={"id": "user:123", "tenant_id": "acme"}
                    )
    """

    def __init__(self, fence: DataFence):
        """
        Initialize Claude adapter.

        Args:
            fence: Configured DataFence instance
        """
        self.fence = fence

    def get_tools(self) -> list[dict[str, Any]]:
        """
        Generate Claude tool schemas from DataFence policies.

        Returns:
            List of Claude tool schemas
        """
        tools = []

        # Get all resources from policy
        if not self.fence.policy or not self.fence.policy.resources:
            return tools

        for resource_name, resource_config in self.fence.policy.resources.items():
            # Create a tool for each allowed operation
            allowed_ops = resource_config.operations.get("allow", [])

            if "read" in allowed_ops or Operation.READ.value in allowed_ops:
                tools.append(self._create_read_tool(resource_name, resource_config))

        return tools

    def _create_read_tool(self, resource_name: str, resource_config: Any) -> dict[str, Any]:
        """
        Create Claude tool schema for reading a resource.

        Args:
            resource_name: Name of the resource
            resource_config: Resource configuration from policy

        Returns:
            Claude tool schema
        """
        # Get allowed fields
        allowed_fields = resource_config.fields.get("allow", [])

        # Build tool schema
        tool_schema = {
            "name": f"read_{resource_name}",
            "description": f"Read data from {resource_name} with security enforcement. Returns filtered data based on permissions.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "fields": {
                        "type": "array",
                        "items": {"type": "string", "enum": allowed_fields},
                        "description": f"Fields to retrieve. Allowed fields: {', '.join(allowed_fields)}",
                    },
                    "filters": {
                        "type": "object",
                        "description": "Filter conditions as key-value pairs (e.g., {\"customer_id\": \"123\"})",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of rows to return",
                        "minimum": 1,
                        "maximum": resource_config.limits.get("max_rows", 1000)
                        if hasattr(resource_config, "limits")
                        else 1000,
                    },
                },
                "required": [],
            },
        }

        return tool_schema

    def execute_tool(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        actor: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute Claude tool call through DataFence.

        Args:
            tool_name: Name of the tool being called
            tool_input: Tool input parameters
            actor: Actor information (id, tenant_id, etc.)
            context: Additional context for policy evaluation

        Returns:
            Execution result with data and metadata

        Raises:
            DataFenceError: If execution fails or is denied
        """
        # Extract operation and resource from tool name
        # Expected format: read_<resource_name>
        if not tool_name.startswith("read_"):
            raise DataFenceError(f"Unsupported tool: {tool_name}")

        resource_name = tool_name[5:]  # Remove "read_" prefix

        # Build DataFence request
        request_dict = {
            "actor": actor,
            "operation": "read",
            "resource": resource_name,
            "fields": tool_input.get("fields"),
            "filters": tool_input.get("filters", {}),
            "limit": tool_input.get("limit"),
        }

        if context:
            request_dict["context"] = context

        # Execute through DataFence
        result = self.fence.execute(request_dict)

        # Format response for Claude
        if result.verified:
            return {
                "success": True,
                "data": result.data,
                "row_count": len(result.data),
                "evidence": {
                    "decision": result.decision.decision.value,
                    "applied_policies": result.decision.applied_policies,
                },
            }
        else:
            return {
                "success": False,
                "error": "Access denied",
                "reasons": result.decision.reasons,
                "decision": result.decision.decision.value,
            }

    def create_tool_result_block(
        self, tool_use_id: str, result: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create Claude tool result block from execution result.

        Args:
            tool_use_id: Tool use ID from Claude response
            result: Result from execute_tool

        Returns:
            Tool result block for Claude API
        """
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": json.dumps(result),
        }


def create_claude_agent(
    fence: DataFence,
    model: str = "claude-3-5-sonnet-20241022",
    system_prompt: str | None = None,
    api_key: str | None = None,
    max_tokens: int = 1024,
) -> Callable[[str, dict[str, Any]], str]:
    """
    Create a simple Claude agent with DataFence security.

    Args:
        fence: DataFence instance
        model: Claude model name
        system_prompt: System prompt for the agent
        api_key: Anthropic API key (uses env var if not provided)
        max_tokens: Maximum tokens in response

    Returns:
        Agent function that takes (message, actor) and returns response

    Example:
        agent = create_claude_agent(fence, system_prompt="You are a helpful assistant.")
        response = agent("Show me transactions", actor={"id": "user:123", "tenant_id": "acme"})
    """
    if anthropic is None:
        raise ImportError("anthropic package required. Install with: pip install anthropic")

    adapter = ClaudeAdapter(fence)
    tools = adapter.get_tools()

    if api_key:
        client = anthropic.Anthropic(api_key=api_key)
    else:
        client = anthropic.Anthropic()  # Uses ANTHROPIC_API_KEY env var

    def agent(message: str, actor: dict[str, Any], context: dict[str, Any] | None = None) -> str:
        """
        Send message and get response with tool use.

        Args:
            message: User message
            actor: Actor information
            context: Additional context

        Returns:
            Agent response
        """
        messages = [{"role": "user", "content": message}]

        # Call Claude
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt if system_prompt else "",
            tools=tools if tools else [],
            messages=messages,
        )

        # Handle tool use
        while response.stop_reason == "tool_use":
            # Process tool uses
            tool_results = []

            for block in response.content:
                if block.type == "tool_use":
                    # Execute tool through DataFence
                    result = adapter.execute_tool(
                        block.name, block.input, actor=actor, context=context
                    )

                    # Create tool result block
                    tool_results.append(
                        adapter.create_tool_result_block(block.id, result)
                    )

            # Add assistant message with tool use
            messages.append({"role": "assistant", "content": response.content})

            # Add tool results
            messages.append({"role": "user", "content": tool_results})

            # Continue conversation
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system_prompt if system_prompt else "",
                tools=tools if tools else [],
                messages=messages,
            )

        # Extract final text response
        text_content = ""
        for block in response.content:
            if block.type == "text":
                text_content += block.text

        return text_content

    return agent
